//! node: 对等节点。
//! - peer 隧道监听 (exit 数据面, ACL 控制)
//! - coordinator 注册/目录同步
//! - SOCKS5 入口 + 策略路由: direct / auto / 指定节点出口
//!
//! serve 子命令复用 handle_peer (无 mesh 的独立出口, ACL=All)。

use yz_core::ingress::{self, IngressRule};
use yz_core::util::{is_local_source, local_addrs};
pub(crate) use yz_core::peer::{
    handle_peer, resolve_node, spawn_incoming_handler, tunnel_for, tunnel_for_retry, PeerCtx,
};
pub(crate) use yz_core::util::{now_ms, pick_addr};
use yz_core::policy::{match_route, ExitAcl, RouteRule};
use crate::socks5;
use yz_core::tunnel::{self};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use tokio::io::AsyncReadExt;
use yz_proto::{caps, Addr, ControlMsg, Frame};

pub struct NodeOpts {
    pub bind: String,
    /// 协调器列表 (多实例容错: 按序轮换)
    pub coord: Vec<String>,
    pub name: String,
    /// 对外公布的隧道监听地址
    pub advertise: String,
    /// 手动指定对外公布的 UDP 映射地址 (VPS/云 NAT 场景, 探测会被回环误导)
    pub udp_advertise: Option<String>,
    pub socks5: Option<String>,
    /// Web UI 监听地址
    pub web: Option<String>,
    /// Web UI 访问令牌 (挂公网必须设)
    pub web_token: Option<String>,
    /// 静态入口发布
    pub ingress: Vec<IngressRule>,
    /// 动态入口发布 ACL
    pub ingress_acl: ExitAcl,
    /// 动态发布允许的端口范围
    pub ingress_ports: (u16, u16),
    /// direct | auto | 节点名/node_id 前缀
    pub default_exit: String,
    pub routes: Vec<RouteRule>,
    pub exit_acl: ExitAcl,
    /// 握手失败连接的伪装转发目标 (抗主动探测)
    pub fallback: Option<String>,
    /// TUN 网卡名, 启用虚拟组网
    pub tun: Option<String>,
    /// 可持久化配置路径 (Web UI 改动落盘)
    pub config: Option<PathBuf>,
}

pub use yz_core::state::CoreState as NodeState;
pub use yz_core::state::PersistedConfig;


pub async fn run(opts: NodeOpts, ns: &NetworkSecret, id_pub: [u8; 32]) -> Result<()> {
    let self_id = yz_crypto::node_id(&id_pub);
    let mut state0 = NodeState::default();
    state0.config_path.clone_from(&opts.config);
    let state = Arc::new(state0);

    // 配置加载: 文件优先 (Web UI 改的是事实源), 无文件时用 CLI 初值
    let persisted: Option<PersistedConfig> = opts
        .config
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok());
    let (routes_init, exit_init) = match &persisted {
        Some(c) => (
            c.routes
                .as_ref()
                .map(|rs| rs.iter().filter_map(|r| RouteRule::parse(r).ok()).collect())
                .unwrap_or_else(|| opts.routes.clone()),
            c.default_exit
                .clone()
                .unwrap_or_else(|| opts.default_exit.clone()),
        ),
        None => (opts.routes.clone(), opts.default_exit.clone()),
    };
    *state.routes.write().await = routes_init;
    *state.default_exit.write().await = exit_init;
    if opts.config.is_some() && persisted.is_none() {
        state.save_config().await; // 首次生成配置文件
    }

    // 0) UDP 端点 + NAT 探测 (YZ_NO_P2P=1 强制关闭, 调试用)
    let udp_ep = if std::env::var("YZ_NO_P2P").is_ok() {
        log::info!("p2p disabled by YZ_NO_P2P");
        None
    } else {
        // 重启时旧进程可能未完全退出, 重试几次绑定
        let mut bound = None;
        for attempt in 0..5 {
            match tokio::net::UdpSocket::bind(&opts.bind).await {
                Ok(s) => {
                    bound = Some(s);
                    break;
                }
                Err(e) => {
                    if attempt == 4 {
                        log::warn!("udp bind {} 失败: {e} (P2P 不可用)", opts.bind);
                    } else {
                        tokio::time::sleep(Duration::from_millis(500 * (attempt + 1))).await;
                    }
                }
            }
        }
        match bound {
            Some(s) => match yz_rudp::Endpoint::bind(s, ns, id_pub).await {
                Ok(ep) => Some(Arc::new(ep)),
                Err(e) => {
                    log::warn!("udp endpoint: {e:#}");
                    None
                }
            },
            None => None,
        }
    };
    *state.udp_ep.write().await = udp_ep.clone();

    // 经 coordinator UDP (P 与 P+1) 探测公网映射与 NAT 类型
    let mut udp_addr = String::new();
    let probe_failed = std::sync::atomic::AtomicBool::new(false);
    let probe_failed = &probe_failed;
    if let Some(ep) = &udp_ep {
        if let Some(coord_addr) = tokio::net::lookup_host(&opts.coord[0])
            .await
            .ok()
            .and_then(|mut i| i.next())
        {
            let mut coord2 = coord_addr;
            coord2.set_port(coord_addr.port() + 1);
            match (ep.probe_via(coord_addr).await, ep.probe_via(coord2).await) {
                (Ok(a1), Ok(a2)) => {
                    udp_addr = a1.to_string();
                    if a1.port() == a2.port() {
                        log::info!("nat: cone, public udp {a1}");
                    } else {
                        log::info!("nat: symmetric ({a1} vs {a2})");
                    }
                }
                _ => {
                    log::warn!("nat probe failed, p2p disabled");
                    probe_failed.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }
    if let Some(manual) = &opts.udp_advertise {
        udp_addr = manual.clone();
        log::info!("udp advertise overridden: {manual}");
    }
    *state.udp_addr.write().await = udp_addr.clone();

    // 探测失败: 指数退避重试 (10s→60s), 成功后更新 udp_addr 并重发 HELLO 让全网目录更新
    if let Some(ep) = &udp_ep {
        let state2 = state.clone();
        let ep2 = ep.clone();
        let coord_first = opts.coord.first().cloned().unwrap_or_default();
        let hello_name = opts.name.clone();
        let hello_addr = opts.advertise.clone();
        let hello_caps = if opts.exit_acl.advertise() {
            caps::EXIT
        } else {
            0
        };
        tokio::spawn(async move {
            let mut wait = Duration::from_secs(10);
            loop {
                tokio::time::sleep(wait).await;
                if !state2.udp_addr.read().await.is_empty() {
                    break; // 已通过其它途径拿到映射
                }
                if let Some(ca) = tokio::net::lookup_host(coord_first.as_str())
                    .await
                    .ok()
                    .and_then(|mut i| i.next())
                {
                    let mut ca2 = ca;
                    ca2.set_port(ca.port() + 1);
                    if let (Ok(a1), Ok(_)) = (ep2.probe_via(ca).await, ep2.probe_via(ca2).await) {
                        *state2.udp_addr.write().await = a1.to_string();
                        state2
                            .push_event("info", format!("NAT 探测成功: {a1}"))
                            .await;
                        log::info!("nat probe ok: {a1}");
                        // 重发 HELLO, 让协调器目录立刻带上 udp_addr
                        if let Some(ct) = state2.coord_tunnel.read().await.clone() {
                            let port = hello_addr
                                .rsplit_once(':')
                                .and_then(|(_, p)| p.parse::<u16>().ok())
                                .unwrap_or(9100);
                            let addrs = local_addrs(port, Some(hello_addr.as_str()));
                            let hello = yz_proto::encode_control(&ControlMsg::Hello {
                                version: 1,
                                name: hello_name.clone(),
                                addrs,
                                udp_addr: a1.to_string(),
                                caps: hello_caps,
                            });
                            let _ = ct
                                .write_frame(&Frame::Control { payload: hello })
                                .await;
                        }
                        break;
                    }
                }
                wait = (wait * 2).min(Duration::from_secs(60));
            }
        });
    }

    // 1b) UDP 隧道接入 (P2P 被打入方)
    if let Some(ep) = udp_ep.clone() {
        let ctx = PeerCtx {
            exit_acl: opts.exit_acl.clone(),
            ingress_acl: opts.ingress_acl.clone(),
            ingress_ports: opts.ingress_ports,
            state: Some(state.clone()),
            fallback: opts.fallback.clone(),
            ns: ns.clone(),
            id_pub,
        };
        tokio::spawn(async move {
            while let Some((rudp, peer)) = ep.accept().await {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_peer(tunnel::from_rudp(rudp, peer), &ctx).await {
                        log::debug!("udp peer closed: {e:#}");
                    }
                });
            }
        });
    }

    // 1) peer 隧道监听 (exit 数据面)
    {
        let listener = bind_tcp_retry(&opts.bind).await?;
        log::info!("node [{}] serving peers on {}", opts.name, opts.bind);
        let ns = ns.clone();
        let state = state.clone();
        let ctx = PeerCtx {
            exit_acl: opts.exit_acl.clone(),
            ingress_acl: opts.ingress_acl.clone(),
            ingress_ports: opts.ingress_ports,
            state: Some(state.clone()),
            fallback: opts.fallback.clone(),
            ns: ns.clone(),
            id_pub,
        };
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, from)) => {
                        let ns = ns.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            match tunnel::accept(stream, &ns, &id_pub, ctx.fallback.as_deref()).await
                            {
                                Ok(Some(h)) => {
                                    if let Err(e) = handle_peer(h, &ctx).await {
                                        log::debug!("peer conn from {from} closed: {e:#}");
                                    }
                                }
                                Ok(None) => {} // 探针已转发 fallback
                                Err(e) => log::debug!("handshake from {from}: {e:#}"),
                            }
                        });
                    }
                    Err(e) => {
                        // FD 耗尽时退避, 避免刷屏
                        if e.raw_os_error() == Some(24) {
                            state.push_event("warn", "FD 耗尽 (EMFILE), 1s 后重试 accept".into()).await;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        } else {
                            log::warn!("accept: {e}");
                        }
                    }
                }
            }
        });
    }

    // 2) SOCKS5 入口 + 策略路由
    if let Some(listen) = opts.socks5.clone() {
        // 绑通配地址 (0.0.0.0/::) = 对局域网开放, 此时自动只放行私网/回环来源,
        // 避免无认证的 SOCKS5 被公网当作开放代理
        let wildcard = {
            let host = listen.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
            host.is_empty() || host == "0.0.0.0" || host == "[::]" || host == "::"
        };
        let listener = TcpListener::bind(&listen).await?;
        if wildcard {
            log::info!("socks5 entry on {listen} (通配地址: 仅放行私网/回环来源)");
        } else {
            log::info!("socks5 entry on {listen}");
        }
        let state = state.clone();
        let ns = ns.clone();
        let self_id = self_id.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, from)) => {
                        // 绑通配地址时只接受私网/回环来源
                        if wildcard && !is_local_source(from.ip()) {
                            log::warn!("socks5 拒绝非私网来源 {from}");
                            continue;
                        }
                        let state = state.clone();
                        let ns = ns.clone();
                        let self_id = self_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_socks5(stream, &state, &ns, &id_pub, &self_id).await
                            {
                                log::debug!("socks5 {from}: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        if e.raw_os_error() == Some(24) {
                            state.push_event("warn", "FD 耗尽 (EMFILE), SOCKS5 accept 1s 后重试".into()).await;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        } else {
                            log::warn!("socks5 accept: {e}");
                        }
                    }
                }
            }
        });
    }

    // 2b) Web UI
    if let Some(web_bind) = opts.web.clone() {
        let app = Arc::new(crate::web::AppState {
            node: state.clone(),
            info: crate::web::SelfInfo {
                node_id: self_id.clone(),
                name: opts.name.clone(),
                socks5: opts.socks5.clone(),
            },
            ns: ns.clone(),
            id_pub,
            token: opts.web_token.clone(),
        });
        tokio::spawn(async move {
            if let Err(e) = crate::web::run(&web_bind, app).await {
                log::warn!("web ui: {e:#}");
            }
        });
    }

    // 2c) 静态 ingress 端口发布
    for rule in opts.ingress.iter().cloned() {
        let state = state.clone();
        let ns = ns.clone();
        let self_id = self_id.clone();
        tokio::spawn(async move {
            if let Err(e) = ingress::run_static(rule, state, ns, id_pub, self_id).await {
                log::warn!("ingress: {e:#}");
            }
        });
    }

    // 2d) TUN 虚拟组网
    if let Some(ifname) = opts.tun.clone() {
        let state = state.clone();
        let ns = ns.clone();
        let self_id = self_id.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::mesh::run(&ifname, state, ns, id_pub, self_id).await {
                log::warn!("tun: {e:#}");
            }
        });
    }

    // 3) coordinator 注册 + 目录同步, 多实例按序轮换 + 指数退避
    let mut backoff = Duration::from_secs(1);
    let mut cur = 0usize;
    loop {
        let coord = &opts.coord[cur % opts.coord.len()];
        cur = cur.wrapping_add(1);
        match tunnel::connect(coord, ns, &id_pub).await {
            Ok(mut h) => {
                backoff = Duration::from_secs(1);
                log::info!(
                    "registered to coordinator {} ({})",
                    coord,
                    &h.peer.node_id()[..8]
                );
                *state.coord_tunnel.write().await = Some(h.tunnel.clone());
                let port = opts
                    .advertise
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok())
                    .unwrap_or(9100);
                let addrs = local_addrs(port, Some(opts.advertise.as_str()));
                log::info!("advertise addrs: {addrs:?}");
                let hello = yz_proto::encode_control(&ControlMsg::Hello {
                    version: 1,
                    name: opts.name.clone(),
                    addrs: addrs.clone(),
                    udp_addr: udp_addr.clone(),
                    caps: if opts.exit_acl.advertise() {
                        caps::EXIT
                    } else {
                        0
                    },
                });
                if let Err(e) = h.tunnel.write_frame(&Frame::Control { payload: hello }).await {
                    log::warn!("send HELLO: {e:#}");
                }
                // coordinator 开流 = 中继端点请求
                spawn_incoming_handler(
                    h.tunnel.clone(),
                    h.accept_rx,
                    h.peer.node_id(),
                    ns.clone(),
                    id_pub,
                    Some(state.clone()),
                    opts.exit_acl.clone(),
                    true,
                );
                // coordinator 隧道存活探测 (它挂了要尽早重连)
                {
                    let t = h.tunnel.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            if t.is_closed()
                                || t.write_frame(&Frame::Ping { ts: now_ms() }).await.is_err()
                            {
                                break;
                            }
                        }
                    });
                }
                loop {
                    tokio::select! {
                        f = h.ctrl_rx.recv() => match f {
                            Some(Frame::Control { payload }) => {
                                match yz_proto::decode_control(&payload) {
                                    Ok(ControlMsg::DirSync { nodes }) => {
                                        let list: Vec<String> = nodes
                                            .iter()
                                            .map(|n| {
                                                let exit = if n.caps & caps::EXIT != 0 { "+" } else { "" };
                                                let p2p = if n.udp_addr.is_empty() { "" } else { "@" };
                                                format!("{}{}{}({})", n.name, exit, p2p, &n.node_id[..8])
                                            })
                                            .collect();
                                        log::info!("directory: {} nodes: {}", nodes.len(), list.join(", "));
                                        let mut dir = state.dir.write().await;
                                        dir.clear();
                                        for n in nodes {
                                            dir.insert(n.node_id.clone(), n);
                                        }
                                    }
                                    Ok(ControlMsg::PunchStart {
                                        peer_id,
                                        initiator,
                                        addrs,
                                    }) => {
                                        if initiator {
                                            if let Some(tx) =
                                                state.punch_pending.lock().await.remove(&peer_id)
                                            {
                                                let _ = tx.send(addrs);
                                            }
                                        } else if let Some(ep) = state.udp_ep.read().await.clone() {
                                            // 被叫: 散射打开 NAT 映射, 等对方 connect
                                            tokio::spawn(async move {
                                                let cands: Vec<SocketAddr> = addrs
                                                    .iter()
                                                    .filter_map(|a| a.parse().ok())
                                                    .collect();
                                                if !cands.is_empty() {
                                                    let _ = ep
                                                        .punch(&cands, Duration::from_millis(2500))
                                                        .await;
                                                }
                                            });
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(e) => log::debug!("bad control msg: {e}"),
                                }
                            }
                            Some(Frame::Ping { ts }) => {
                                let _ = h.tunnel.write_frame(&Frame::Pong { ts }).await;
                            }
                            Some(_) => {}
                            None => break,
                        },
                        _ = h.closed.changed() => break,
                    }
                }
                // 目录失效: 离线期间不知道谁下线, 保守清空
                state.coord_tunnel.write().await.take();
                state.dir.write().await.clear();
                state.tunnels.lock().await.retain(|_, t| !t.is_closed());
                log::warn!("lost coordinator, reconnecting...");
            }
            Err(e) => log::warn!("connect coordinator {coord}: {e:#}"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

// ---------- SOCKS5 入口与路由 ----------

enum Exit {
    Direct,
    Via(String), // node_id
}

async fn handle_socks5(
    mut local: TcpStream,
    state: &Arc<NodeState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    self_id: &str,
) -> Result<()> {
    local.set_nodelay(true).ok();
    let addr = match socks5::handshake(&mut local).await? {
        socks5::Request::Connect(a) => a,
        socks5::Request::UdpAssociate => {
            return udp_associate(local, state, ns, id_pub, self_id).await;
        }
    };

    let key = {
        let routes = state.routes.read().await;
        match match_route(&routes, &addr) {
            Some(e) => e.to_string(),
            None => state.default_exit.read().await.clone(),
        }
    };
    // 显式出口节点但目录尚未同步 (刚启动/部署窗口): 等目录到位, 不静默走 direct
    if !matches!(key.as_str(), "direct" | "auto") {
        for _ in 0..8 {
            if resolve_node(state, &key).await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let decision = resolve_exit(state, &key, self_id).await;

    match decision {
        Exit::Direct => {
            let outbound = match TcpStream::connect(addr.to_string()).await {
                Ok(s) => s,
                Err(e) => {
                    socks5::reply_fail(&mut local).await;
                    return Err(e.into());
                }
            };
            socks5::reply_ok(&mut local).await?;
            log::debug!("{addr} -> direct");
            let (mut lr, mut lw) = local.into_split();
            let (mut or, mut ow) = outbound.into_split();
            let a = tokio::io::copy(&mut lr, &mut ow);
            let b = tokio::io::copy(&mut or, &mut lw);
            let _ = tokio::join!(a, b);
            Ok(())
        }
        Exit::Via(node_id) => {
            let t = tunnel_for_retry(state, ns, id_pub, &node_id, 2, Duration::from_millis(1200))
                .await?;
            let (sid, mut rx) = match t.open_stream(addr.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    // 开流失败通常意味着隧道已死: 淘汰缓存, 让下次请求重建
                    log::debug!("open_stream 失败, 淘汰隧道 {}: {e:#}", &node_id[..8]);
                    t.mark_closed();
                    state.tunnels.lock().await.remove(&node_id);
                    state.path.write().await.remove(&node_id);
                    socks5::reply_fail(&mut local).await;
                    return Err(e);
                }
            };
            // SYN_ACK 短超时: 隧道若是僵尸(链路已死), 必须尽快失败并重建,
            // 否则请求会卡满 10s (浏览器早已放弃)
            let acked = match timeout(Duration::from_secs(3), rx.recv()).await {
                Ok(Some(Frame::SynAck { ok, .. })) => Some(ok),
                Ok(Some(_)) => Some(false),
                Ok(None) => None,
                Err(_) => None, // 超时 = 链路可能已死
            };
            match acked {
                Some(true) => {}
                other => {
                    // 淘汰疑似僵尸隧道, 下次请求会重建
                    t.mark_closed();
                    state.tunnels.lock().await.remove(&node_id);
                    state.path.write().await.remove(&node_id);
                    state
                        .push_event(
                            "warn",
                            format!(
                                "隧道无响应, 已淘汰: {} ({})",
                                &node_id[..8.min(node_id.len())],
                                if other.is_some() { "拒绝" } else { "超时" }
                            ),
                        )
                        .await;
                    socks5::reply_fail(&mut local).await;
                    bail!("exit {node_id} 流建立失败 ({other:?}), 隧道已淘汰");
                }
            }
            socks5::reply_ok(&mut local).await?;
            log::debug!("{addr} -> via {}", &node_id[..8]);
            tunnel::pump_stream(local, sid, rx, t).await
        }
    }
}

/// 枚举本机可用于隧道连接的地址 (不含回环/通配):
/// 把 --advertise 的端口应用到所有本地网卡 IP 上, 让不同网段的节点都能连到我们
async fn resolve_exit(state: &Arc<NodeState>, exit: &str, self_id: &str) -> Exit {    match exit {
        "direct" => Exit::Direct,
                // auto: 选延迟最低的可出口节点 (未测得延迟的排最后)
                "auto" => {
                    let dir = state.dir.read().await;
                    let rtt = state.rtt.read().await;
                    let mut cands: Vec<(u32, String)> = dir
                        .values()
                        .filter(|n| n.caps & caps::EXIT != 0 && n.node_id != self_id)
                        .map(|n| {
                            (
                                rtt.get(&n.node_id).copied().unwrap_or(u32::MAX),
                                n.node_id.clone(),
                            )
                        })
                        .collect();
                    cands.sort();
                    match cands.first() {
                        Some((_, id)) => Exit::Via(id.clone()),
                        None => Exit::Direct,
                    }
                }
        key => {
            match resolve_node(state, key).await {
                Some(n) => Exit::Via(n.node_id),
                None => {
                    log::warn!("exit node '{key}' not in directory, fallback direct");
                    Exit::Direct
                }
            }
        }
    }
}

// ---------- SOCKS5 UDP ASSOCIATE ----------

/// 本地 UDP 中继: 解 SOCKS5 UDP 头 → 按策略走 direct 或 exit 节点的数据报通道
async fn udp_associate(
    mut tcp: TcpStream,
    state: &Arc<NodeState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    self_id: &str,
) -> Result<()> {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let relay = sock.local_addr()?;
    socks5::reply_udp(&mut tcp, relay).await?;
    log::debug!("udp associate relay {relay}");

    // TCP 连接关闭 = 关联结束: 用 watch 主动唤醒 UDP 循环 (否则中继/目标 socket 永不释放)
    let (dead_tx, mut dead_rx) = tokio::sync::watch::channel(false);
    {
        let dead_tx = dead_tx.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            loop {
                match tcp.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = dead_tx.send(true);
        });
    }

    let client: Arc<Mutex<Option<SocketAddr>>> = Default::default();
    let routes: Arc<Mutex<HashMap<Addr, mpsc::Sender<Vec<u8>>>>> = Default::default();
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, from) = tokio::select! {
            r = sock.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(_) => break,
            },
            _ = dead_rx.changed() => break, // 关联结束
        };
        {
            let mut c = client.lock().await;
            if c.is_none() {
                *c = Some(from);
                log::debug!("udp client {from}");
            }
            if *c != Some(from) {
                continue;
            }
        }
        let Some((target, off)) = socks5::parse_udp_header(&buf[..n]) else {
            continue;
        };
        let data = buf[off..n].to_vec();
        let existing = { routes.lock().await.get(&target).cloned() };
        let tx = match existing {
            Some(tx) => tx,
            None => {
                let tx = match open_udp_route(
                    state,
                    ns,
                    id_pub,
                    self_id,
                    &target,
                    sock.clone(),
                    client.clone(),
                    dead_rx.clone(),
                )
                .await
                {
                    Ok(tx) => tx,
                    Err(e) => {
                        log::debug!("udp route {target}: {e:#}");
                        continue;
                    }
                };
                routes.lock().await.insert(target.clone(), tx.clone());
                tx
            }
        };
        if tx.send(data).await.is_err() {
            routes.lock().await.remove(&target);
        }
    }
    // 广播结束: 所有目标通道关闭 → 任务/套接字全部释放
    let _ = dead_tx.send(true);
    drop(routes);
    Ok(())
}

/// 建一条到目标的 UDP 通道: direct 本地转发, 或经 exit 节点的隧道流
async fn open_udp_route(
    state: &Arc<NodeState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    self_id: &str,
    target: &Addr,
    client_sock: Arc<tokio::net::UdpSocket>,
    client: Arc<Mutex<Option<SocketAddr>>>,
    dead_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<mpsc::Sender<Vec<u8>>> {
    let key = {
        let routes = state.routes.read().await;
        match match_route(&routes, target) {
            Some(e) => e.to_string(),
            None => state.default_exit.read().await.clone(),
        }
    };
    log::debug!("udp route {target} key={key}");
    match resolve_exit(state, &key, self_id).await {
        Exit::Direct => {
            log::debug!("udp route {target} -> direct");
            let bind = match target {
                Addr::V6(..) => "[::]:0",
                _ => "0.0.0.0:0",
            };
            let out = Arc::new(tokio::net::UdpSocket::bind(bind).await?);
            out.connect(target.to_string()).await?;
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
            let out2 = out.clone();
            let target = target.clone();
            let mut dead = dead_rx.clone();
            tokio::spawn(async move {
                let o = out2.clone();
                let down = tokio::spawn(async move {
                    while let Some(d) = rx.recv().await {
                        if o.send(&d).await.is_err() {
                            break;
                        }
                    }
                });
                let mut b = vec![0u8; 65536];
                loop {
                    // 关联结束(对端 TCP 关闭)时主动退出, 否则 socket 永不释放
                    tokio::select! {
                        r = out2.recv(&mut b) => match r {
                            Ok(n) => {
                                if let Some(c) = *client.lock().await {
                                    let pkt = socks5::build_udp_header(&target, &b[..n]);
                                    if client_sock.send_to(&pkt, c).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(_) => break,
                        },
                        _ = dead.changed() => break,
                    }
                }
                down.abort();
            });
            Ok(tx)
        }
        Exit::Via(node_id) => {
            log::debug!("udp route {target} -> exit {}", &node_id[..8]);
            let t = tunnel_for_retry(state, ns, id_pub, &node_id, 2, Duration::from_millis(1200))
                .await?;
            let (sid, mut rx) = t
                .open_stream_kind(target.clone(), yz_proto::StreamKind::Udp)
                .await?;
            log::debug!("udp stream {sid} opened to exit");
            match timeout(Duration::from_secs(10), rx.recv()).await? {
                Some(Frame::SynAck { ok: true, .. }) => {
                    log::debug!("udp stream {sid} ready");
                }
                Some(other) => bail!("exit {node_id} udp open rejected: {other:?}"),
                None => bail!("exit {node_id} udp stream closed before ack"),
            }
            let (tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
            let t2 = t.clone();
            let target = target.clone();
            let mut dead = dead_rx.clone();
            tokio::spawn(async move {
                let t3 = t2.clone();
                let down = tokio::spawn(async move {
                    while let Some(d) = out_rx.recv().await {
                        if t3
                            .write_frame(&Frame::Data {
                                stream_id: sid,
                                payload: d,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
                loop {
                    // 关联结束: 停止回包并通知出口侧关掉数据报流
                    let f = tokio::select! {
                        f = rx.recv() => match f { Some(f) => f, None => break },
                        _ = dead.changed() => Frame::Fin { stream_id: sid },
                    };
                    match f {
                        Frame::Data { payload, .. } => {
                            if let Some(c) = *client.lock().await {
                                let pkt = socks5::build_udp_header(&target, &payload);
                                if client_sock.send_to(&pkt, c).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Frame::Fin { .. } | Frame::Rst { .. } => break,
                        _ => {}
                    }
                }
                down.abort();
                // 通知出口侧关流
                let _ = t2.write_frame(&Frame::Fin { stream_id: sid }).await;
                t2.close_stream(sid).await;
            });
            Ok(tx)
        }
    }
}



/// 按 node_id / 名字 / id 前缀解析目录条目
async fn bind_tcp_retry(bind: &str) -> Result<TcpListener> {
    let mut last_err = None;
    for attempt in 0..6u64 {
        match TcpListener::bind(bind).await {
            Ok(l) => return Ok(l),
            Err(e) => {
                log::warn!("tcp bind {bind} 失败: {e}, 重试 ({}/6)", attempt + 1);
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(500 * (attempt + 1))).await;
            }
        }
    }
    Err(last_err.expect("bind attempts").into())
}

/// 独立出口 (serve 子命令), 允许组网内任何节点, 不开 ingress
pub async fn serve(
    bind: &str,
    ns: &NetworkSecret,
    id_pub: [u8; 32],
    udp: bool,
    fallback: Option<String>,
    wss: Option<(String, String)>,
) -> Result<()> {
    let ctx = PeerCtx {
        exit_acl: ExitAcl::All,
        ingress_acl: ExitAcl::None,
        ingress_ports: (0, 0),
        state: None,
        fallback,
        ns: ns.clone(),
        id_pub,
    };
    if let Some((cert, key)) = wss {
        let acceptor = yz_core::wss::server_acceptor(Path::new(&cert), Path::new(&key))?;
        let listener = bind_tcp_retry(bind).await?;
        log::info!("serving tunnel on wss/{bind}");
        loop {
            let (stream, from) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let ns = ns.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                match tunnel::accept_wss(stream, &acceptor, &ns, &id_pub, ctx.fallback.as_deref()).await {
                    Ok(Some(h)) => {
                        if let Err(e) = handle_peer(h, &ctx).await {
                            log::debug!("wss conn from {from} closed: {e:#}");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => log::debug!("wss from {from}: {e:#}"),
                }
            });
        }
    }
    if udp {
        let sock = tokio::net::UdpSocket::bind(bind).await?;
        let ep = yz_rudp::Endpoint::bind(sock, ns, id_pub).await?;
        log::info!("serving tunnel on udp/{bind}");
        while let Some((rudp, peer)) = ep.accept().await {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_peer(tunnel::from_rudp(rudp, peer), &ctx).await {
                    log::debug!("udp peer closed: {e:#}");
                }
            });
        }
        return Ok(());
    }
    let listener = bind_tcp_retry(bind).await?;
    log::info!("serving tunnel on {bind}");
    loop {
        let (stream, from) = listener.accept().await?;
        let ns = ns.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match tunnel::accept(stream, &ns, &id_pub, ctx.fallback.as_deref()).await {
                Ok(Some(h)) => {
                    if let Err(e) = handle_peer(h, &ctx).await {
                        log::debug!("conn from {from} closed: {e:#}");
                    }
                }
                Ok(None) => {}
                Err(e) => log::debug!("handshake from {from}: {e:#}"),
            }
        });
    }
}

