//! node: 对等节点。
//! - peer 隧道监听 (exit 数据面, ACL 控制)
//! - coordinator 注册/目录同步
//! - SOCKS5 入口 + 策略路由: direct / auto / 指定节点出口
//!
//! serve 子命令复用 handle_peer (无 mesh 的独立出口, ACL=All)。

use crate::ingress::{self, IngressEntry, IngressRule};
use crate::policy::{match_route, ExitAcl, RouteRule};
use crate::socks5;
use crate::tunnel::{self, Incoming, Tunnel, TunnelHandle};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use yz_proto::{caps, ControlMsg, Frame, NodeEntry};

pub struct NodeOpts {
    pub bind: String,
    pub coord: String,
    pub name: String,
    /// 对外公布的隧道监听地址
    pub advertise: String,
    pub socks5: Option<String>,
    /// Web UI 监听地址
    pub web: Option<String>,
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
}

#[derive(Default)]
pub struct NodeState {
    /// node_id -> 目录条目
    pub dir: RwLock<HashMap<String, NodeEntry>>,
    /// node_id -> 到该节点的隧道
    pub tunnels: Mutex<HashMap<String, Arc<Tunnel>>>,
    /// 分流规则 (Web UI 可热改)
    pub routes: RwLock<Vec<RouteRule>>,
    /// 默认出口 (Web UI 可热改)
    pub default_exit: RwLock<String>,
    /// 本节点发布的入口映射
    pub ingress_pub: RwLock<Vec<IngressEntry>>,
    /// 本节点向其他节点申请的入口映射
    pub ingress_req: RwLock<Vec<IngressEntry>>,
    /// UDP 端点 (P2P 打洞/直连)
    pub udp_ep: RwLock<Option<Arc<yz_rudp::Endpoint>>>,
    /// coordinator 隧道
    pub coord_tunnel: RwLock<Option<Arc<Tunnel>>>,
    /// 打洞等待者: target node_id → PunchStart addrs
    pub punch_pending: Mutex<HashMap<String, oneshot::Sender<Vec<String>>>>,
    /// mesh 收编: 隧道来的 IP 包 → TUN (未启用 TUN 时 None)
    pub mesh_sink: RwLock<Option<mpsc::Sender<Vec<u8>>>>,
}

pub async fn run(opts: NodeOpts, ns: &NetworkSecret, id_pub: [u8; 32]) -> Result<()> {
    let self_id = yz_crypto::node_id(&id_pub);
    let state = Arc::new(NodeState::default());
    *state.routes.write().await = opts.routes.clone();
    *state.default_exit.write().await = opts.default_exit.clone();

    // 0) UDP 端点 + NAT 探测 (YZ_NO_P2P=1 强制关闭, 调试用)
    let udp_ep = if std::env::var("YZ_NO_P2P").is_ok() {
        log::info!("p2p disabled by YZ_NO_P2P");
        None
    } else {
        match tokio::net::UdpSocket::bind(&opts.bind).await {
            Ok(s) => match yz_rudp::Endpoint::bind(s, ns, id_pub).await {
                Ok(ep) => Some(Arc::new(ep)),
                Err(e) => {
                    log::warn!("udp endpoint: {e:#}");
                    None
                }
            },
            Err(e) => {
                log::warn!("udp bind {}: {e}", opts.bind);
                None
            }
        }
    };
    *state.udp_ep.write().await = udp_ep.clone();

    // 经 coordinator UDP (P 与 P+1) 探测公网映射与 NAT 类型
    let mut udp_addr = String::new();
    if let Some(ep) = &udp_ep {
        if let Some(coord_addr) = tokio::net::lookup_host(&opts.coord)
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
                _ => log::warn!("nat probe failed, p2p disabled"),
            }
        }
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
        let listener = TcpListener::bind(&opts.bind).await?;
        log::info!("node [{}] serving peers on {}", opts.name, opts.bind);
        let ns = ns.clone();
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
                    Err(e) => log::warn!("accept: {e}"),
                }
            }
        });
    }

    // 2) SOCKS5 入口 + 策略路由
    if let Some(listen) = opts.socks5.clone() {
        let listener = TcpListener::bind(&listen).await?;
        log::info!("socks5 entry on {listen}");
        let state = state.clone();
        let ns = ns.clone();
        let self_id = self_id.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, from)) => {
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
                    Err(e) => log::warn!("socks5 accept: {e}"),
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

    // 3) coordinator 注册 + 目录同步, 指数退避重连
    let mut backoff = Duration::from_secs(1);
    loop {
        match tunnel::connect(&opts.coord, ns, &id_pub).await {
            Ok(mut h) => {
                backoff = Duration::from_secs(1);
                log::info!(
                    "registered to coordinator {} ({})",
                    opts.coord,
                    &h.peer.node_id()[..8]
                );
                *state.coord_tunnel.write().await = Some(h.tunnel.clone());
                let hello = yz_proto::encode_control(&ControlMsg::Hello {
                    version: 1,
                    name: opts.name.clone(),
                    addr: opts.advertise.clone(),
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
                                                        .punch(&cands, Duration::from_secs(4))
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
            Err(e) => log::warn!("connect coordinator: {e:#}"),
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
    let addr = socks5::handshake(&mut local).await?;

    let key = {
        let routes = state.routes.read().await;
        match match_route(&routes, &addr) {
            Some(e) => e.to_string(),
            None => state.default_exit.read().await.clone(),
        }
    };
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
            let t = tunnel_for(state, ns, id_pub, &node_id).await?;
            let (sid, mut rx) = t.open_stream(addr.clone()).await?;
            match timeout(Duration::from_secs(10), rx.recv()).await? {
                Some(Frame::SynAck { ok: true, .. }) => {}
                Some(Frame::SynAck { ok: false, .. }) => {
                    socks5::reply_fail(&mut local).await;
                    bail!("exit {node_id} connect {addr} failed");
                }
                _ => {
                    socks5::reply_fail(&mut local).await;
                    bail!("expect SYN_ACK");
                }
            }
            socks5::reply_ok(&mut local).await?;
            log::debug!("{addr} -> via {}", &node_id[..8]);
            tunnel::pump_stream(local, sid, rx, t).await
        }
    }
}

/// 解析 exit 配置为具体决策
async fn resolve_exit(state: &Arc<NodeState>, exit: &str, self_id: &str) -> Exit {
    match exit {
        "direct" => Exit::Direct,
        "auto" => {
            // P3: 取目录里第一个可出口节点(非自己); P4 起按延迟
            let dir = state.dir.read().await;
            let mut candidates: Vec<&NodeEntry> = dir
                .values()
                .filter(|n| n.caps & caps::EXIT != 0 && n.node_id != self_id)
                .collect();
            candidates.sort_by(|a, b| a.node_id.cmp(&b.node_id));
            match candidates.first() {
                Some(n) => Exit::Via(n.node_id.clone()),
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

/// 按 node_id / 名字 / id 前缀解析目录条目
pub(crate) async fn resolve_node(state: &Arc<NodeState>, key: &str) -> Option<NodeEntry> {
    let dir = state.dir.read().await;
    dir.values()
        .find(|n| n.node_id == key || n.name == key || n.node_id.starts_with(key))
        .cloned()
}

/// 取到指定节点的隧道: 复用活跃隧道 → P2P 打洞 → TCP 兜底
pub(crate) async fn tunnel_for(
    state: &Arc<NodeState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    node_id: &str,
) -> Result<Arc<Tunnel>> {
    {
        let tunnels = state.tunnels.lock().await;
        if let Some(t) = tunnels.get(node_id) {
            if !t.is_closed() {
                return Ok(t.clone());
            }
        }
    }
    let entry = {
        let dir = state.dir.read().await;
        dir.get(node_id)
            .cloned()
            .with_context(|| format!("node {} not in directory", &node_id[..8.min(node_id.len())]))?
    };
    // P2P 打洞优先
    if !entry.udp_addr.is_empty() {
        if let Some(h) = try_punch(state, ns, id_pub, &entry).await {
            return Ok(adopt_tunnel(state, h, node_id, ns, *id_pub).await);
        }
    }
    // TCP 兜底 → 中继兜底
    match tunnel::connect(&entry.addr, ns, id_pub).await {
        Ok(h) => Ok(adopt_tunnel(state, h, node_id, ns, *id_pub).await),
        Err(e) => {
            log::debug!("tcp direct {}: {e:#}", &node_id[..8.min(node_id.len())]);
            let coord_t = state
                .coord_tunnel
                .read()
                .await
                .clone()
                .context("no path: direct failed and no coordinator for relay")?;
            let h = tunnel::connect_relayed(&coord_t, node_id, ns, id_pub).await?;
            log::info!("relayed via coordinator to {}", &node_id[..8.min(node_id.len())]);
            Ok(adopt_tunnel(state, h, node_id, ns, *id_pub).await)
        }
    }
}

/// 隧道收编: 排空控制消息 + 接管对端开流 + mesh 转发 + 注册到隧道表
async fn adopt_tunnel(
    state: &Arc<NodeState>,
    h: TunnelHandle,
    node_id: &str,
    ns: &NetworkSecret,
    id_pub: [u8; 32],
) -> Arc<Tunnel> {
    let t = h.tunnel.clone();
    let mut ctrl = h.ctrl_rx;
    tokio::spawn(async move { while ctrl.recv().await.is_some() {} });
    spawn_incoming_handler(
        t.clone(),
        h.accept_rx,
        node_id.to_string(),
        ns.clone(),
        id_pub,
        Some(state.clone()),
        ExitAcl::None, // 主动侧不接受嵌套中继
        false,
    );
    crate::mesh::spawn_forward(h.mesh_rx, state.clone());
    state
        .tunnels
        .lock()
        .await
        .insert(node_id.to_string(), t.clone());
    t
}

/// 经 coordinator 撮合打洞, 成功返回 P2P UDP 隧道
async fn try_punch(
    state: &Arc<NodeState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    entry: &NodeEntry,
) -> Option<TunnelHandle> {
    let ep = state.udp_ep.read().await.clone()?;
    let coord_t = state.coord_tunnel.read().await.clone()?;
    let node_id = entry.node_id.clone();
    let (tx, rx) = oneshot::channel();
    state.punch_pending.lock().await.insert(node_id.clone(), tx);
    let req = yz_proto::encode_control(&ControlMsg::PunchReq {
        target: node_id.clone(),
    });
    if coord_t
        .write_frame(&Frame::Control { payload: req })
        .await
        .is_err()
    {
        state.punch_pending.lock().await.remove(&node_id);
        return None;
    }
    let addrs = match timeout(Duration::from_secs(3), rx).await {
        Ok(Ok(a)) => a,
        _ => {
            state.punch_pending.lock().await.remove(&node_id);
            return None;
        }
    };
    let mut cands: Vec<SocketAddr> = addrs.iter().filter_map(|a| a.parse().ok()).collect();
    // 对称 NAT 兜底: 绕观察端口 ±64 采样散射
    if let Some(obs) = cands.first().copied() {
        for i in 1..=16u16 {
            cands.push(SocketAddr::new(obs.ip(), obs.port().wrapping_add(i * 4)));
            cands.push(SocketAddr::new(obs.ip(), obs.port().wrapping_sub(i * 4)));
        }
    }
    if cands.is_empty() {
        return None;
    }
    let punched = match ep.punch(&cands, Duration::from_secs(4)).await {
        Ok(a) => a,
        Err(e) => {
            log::debug!("punch {}: {e:#}", &node_id[..8]);
            return None;
        }
    };
    match ep.connect(punched, ns, id_pub).await {
        Ok((rudp, info)) => {
            log::info!("p2p punched {} via {punched}", &node_id[..8]);
            Some(tunnel::from_rudp_with_base(rudp, info, 1))
        }
        Err(e) => {
            log::debug!("punch connect {}: {e:#}", &node_id[..8]);
            None
        }
    }
}

// ---------- exit 数据面 ----------

/// 对端隧道上下文
#[derive(Clone)]
pub struct PeerCtx {
    pub exit_acl: ExitAcl,
    pub ingress_acl: ExitAcl,
    pub ingress_ports: (u16, u16),
    pub state: Option<Arc<NodeState>>,
    pub fallback: Option<String>,
    pub ns: NetworkSecret,
    pub id_pub: [u8; 32],
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
        let acceptor = crate::wss::server_acceptor(Path::new(&cert), Path::new(&key))?;
        let listener = TcpListener::bind(bind).await?;
        log::info!("serving tunnel on wss/{bind}");
        loop {
            let (stream, from) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let ns = ns.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                match tunnel::accept_wss(stream, &acceptor, &ns, &id_pub).await {
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
    let listener = TcpListener::bind(bind).await?;
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

/// 对端隧道: ACL 检查后接收流并访问目标; 处理 INGRESS_PUB 控制消息
pub async fn handle_peer(h: TunnelHandle, ctx: &PeerCtx) -> Result<()> {
    let peer_id = h.peer.node_id();
    if !ctx.exit_acl.allows(&peer_id) {
        log::warn!("exit denied for peer {}", &peer_id[..8]);
        bail!("exit denied by acl");
    }
    log::debug!("peer {} tunnel up", &peer_id[..8]);
    let t = h.tunnel.clone();
    // P2P 被接受的隧道也注册, 双向复用
    if let Some(st) = &ctx.state {
        st.tunnels.lock().await.insert(peer_id.clone(), t.clone());
    }

    // peer 控制消息: 动态 ingress 发布
    let mut ctrl = h.ctrl_rx;
    {
        let t = t.clone();
        let peer_id = peer_id.clone();
        let ingress_acl = ctx.ingress_acl.clone();
        let range = ctx.ingress_ports;
        let state = ctx.state.clone();
        tokio::spawn(async move {
            while let Some(f) = ctrl.recv().await {
                let Frame::Control { payload } = f else { continue };
                if let Ok(ControlMsg::IngressPub { port, addr }) = yz_proto::decode_control(&payload)
                {
                    let (ok, msg) = ingress::handle_pub_request(
                        &state,
                        &ingress_acl,
                        range,
                        &peer_id,
                        port,
                        &addr,
                        t.clone(),
                    )
                    .await;
                    let ack = yz_proto::encode_control(&ControlMsg::IngressPubAck { port, ok, msg });
                    let _ = t.write_frame(&Frame::Control { payload: ack }).await;
                }
            }
        });
    }

    spawn_incoming_handler(
        t.clone(),
        h.accept_rx,
        peer_id.clone(),
        ctx.ns.clone(),
        ctx.id_pub,
        ctx.state.clone(),
        ctx.exit_acl.clone(),
        true,
    );
    if let Some(st) = &ctx.state {
        crate::mesh::spawn_forward(h.mesh_rx, st.clone());
    }
    let mut closed = h.closed;
    let _ = closed.changed().await;
    if let Some(st) = &ctx.state {
        st.tunnels.lock().await.remove(&peer_id);
    }
    Ok(())
}

/// 消费对端开流: 连接目标地址并转发; SYN=Domain(yz.relay,0) 为中继端点, 其上跑嵌套握手
pub(crate) fn spawn_incoming_handler(
    t: Arc<Tunnel>,
    mut accept_rx: tokio::sync::mpsc::Receiver<Incoming>,
    peer_id: String,
    ns: NetworkSecret,
    id_pub: [u8; 32],
    state: Option<Arc<NodeState>>,
    relay_acl: ExitAcl,
    relay_ok: bool,
) {
    tokio::spawn(async move {
        while let Some(Incoming { sid, addr, rx }) = accept_rx.recv().await {
            // 中继端点
            if relay_ok && matches!(&addr, yz_proto::Addr::Domain(d, 0) if d == tunnel::RELAY_MARK)
            {
                let t = t.clone();
                let ns = ns.clone();
                let state = state.clone();
                let acl = relay_acl.clone();
                tokio::spawn(async move {
                    // 先应答 SYN_ACK 打通中继链路, 再跑嵌套握手 (否则三方互等死锁)
                    if t.write_frame(&Frame::SynAck {
                        stream_id: sid,
                        ok: true,
                    })
                    .await
                    .is_err()
                    {
                        return;
                    }
                    let mut io = tunnel::StreamIo::new(t.clone(), sid, rx);
                    match tunnel::hs_accept_io(&mut io, &ns, &id_pub).await {
                        Ok(Some((keys, peer))) => {
                            let pid = peer.node_id();
                            if !acl.allows(&pid) {
                                log::warn!("relay exit denied for {}", &pid[..8]);
                                return;
                            }
                            log::info!("relay tunnel from {} up", &pid[..8]);
                            let h = tunnel::assemble_stream(
                                io,
                                &keys,
                                yz_crypto::Role::Responder,
                                2,
                                peer,
                            );
                            let t2 = h.tunnel.clone();
                            let mut ctrl = h.ctrl_rx;
                            tokio::spawn(async move { while ctrl.recv().await.is_some() {} });
                            if let Some(st) = &state {
                                crate::mesh::spawn_forward(h.mesh_rx, st.clone());
                            }
                            // 嵌套隧道上的开流 = 对端代理请求; 不再嵌套中继
                            spawn_incoming_handler(
                                t2,
                                h.accept_rx,
                                pid.clone(),
                                ns,
                                id_pub,
                                state.clone(),
                                acl,
                                false,
                            );
                            if let Some(st) = &state {
                                st.tunnels.lock().await.insert(pid.clone(), h.tunnel.clone());
                            }
                            let mut closed = h.closed;
                            let _ = closed.changed().await;
                            if let Some(st) = &state {
                                st.tunnels.lock().await.remove(&pid);
                            }
                        }
                        _ => {}
                    }
                });
                continue;
            }
            let t = t.clone();
            let peer_id = peer_id.clone();
            tokio::spawn(async move {
                match TcpStream::connect(addr.to_string()).await {
                    Ok(local) => {
                        log::debug!("stream {sid} {} -> {addr}", &peer_id[..8]);
                        if t.write_frame(&Frame::SynAck {
                            stream_id: sid,
                            ok: true,
                        })
                        .await
                        .is_ok()
                        {
                            let _ = tunnel::pump_stream(local, sid, rx, t).await;
                        }
                    }
                    Err(e) => {
                        log::debug!("connect {addr}: {e}");
                        let _ = t
                            .write_frame(&Frame::SynAck {
                                stream_id: sid,
                                ok: false,
                            })
                            .await;
                    }
                }
            });
        }
    });
}
