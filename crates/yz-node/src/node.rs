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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use tokio::io::AsyncReadExt;
use yz_proto::{caps, Addr, ControlMsg, Frame, NodeEntry};

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
    /// node_id → 最近测得 RTT (ms)
    pub rtt: RwLock<HashMap<String, u32>>,
    /// 持久化配置路径
    pub config_path: Option<PathBuf>,
}

/// 落盘的最小配置面 (Web UI 可改的那部分)
#[derive(Serialize, Deserialize, Default)]
pub struct PersistedConfig {
    pub default_exit: Option<String>,
    pub routes: Option<Vec<String>>,
}

impl NodeState {
    /// 汇总全网隧道流量统计: (tx字节, rx字节, 累计开流数)
    pub async fn traffic(&self) -> (u64, u64, u64) {
        let mut tx = 0u64;
        let mut rx = 0u64;
        let mut streams = 0u64;
        let mut add = |s: (u64, u64, u64)| {
            tx += s.0;
            rx += s.1;
            streams += s.2;
        };
        for t in self.tunnels.lock().await.values() {
            add(t.stats());
        }
        if let Some(ct) = &*self.coord_tunnel.read().await {
            add(ct.stats());
        }
        (tx, rx, streams)
    }

    /// 将当前路由/默认出口写入配置文件
    pub async fn save_config(&self) {
        let Some(path) = &self.config_path else { return };
        let cfg = PersistedConfig {
            default_exit: Some(self.default_exit.read().await.clone()),
            routes: Some(self.routes.read().await.iter().map(|r| r.to_string()).collect()),
        };
        match serde_json::to_string_pretty(&cfg) {
            Ok(s) => {
                if let Err(e) = std::fs::write(path, s) {
                    log::warn!("save config {}: {e}", path.display());
                }
            }
            Err(e) => log::warn!("serialize config: {e}"),
        }
    }
}

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
                _ => log::warn!("nat probe failed, p2p disabled"),
            }
        }
    }
    if let Some(manual) = &opts.udp_advertise {
        udp_addr = manual.clone();
        log::info!("udp advertise overridden: {manual}");
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

    // TCP 连接关闭 = 关联结束
    let alive = Arc::new(AtomicBool::new(true));
    {
        let alive = alive.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            while let Ok(n) = tcp.read(&mut b).await {
                if n == 0 {
                    break;
                }
            }
            alive.store(false, Ordering::Relaxed);
        });
    }

    let client: Arc<Mutex<Option<SocketAddr>>> = Default::default();
    let routes: Arc<Mutex<HashMap<Addr, mpsc::Sender<Vec<u8>>>>> = Default::default();
    let mut buf = vec![0u8; 65536];
    loop {
        if !alive.load(Ordering::Relaxed) {
            break;
        }
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => break,
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
                    match out2.recv(&mut b).await {
                        Ok(n) => {
                            if let Some(c) = *client.lock().await {
                                let pkt = socks5::build_udp_header(&target, &b[..n]);
                                if client_sock.send_to(&pkt, c).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                down.abort();
            });
            Ok(tx)
        }
        Exit::Via(node_id) => {
            log::debug!("udp route {target} -> exit {}", &node_id[..8]);
            let t = tunnel_for(state, ns, id_pub, &node_id).await?;
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
                while let Some(f) = rx.recv().await {
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
                t2.close_stream(sid).await;
            });
            Ok(tx)
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
    // TCP 兜底 → 中继兜底 (直连加快速超时, 避免被防火墙黑洞拖死降级链)
    let direct = timeout(Duration::from_secs(6), tunnel::connect(&entry.addr, ns, id_pub)).await;
    match direct {
        Ok(Ok(h)) => Ok(adopt_tunnel(state, h, node_id, ns, *id_pub).await),
        Ok(Err(e)) => {
            log::debug!("tcp direct {}: {e:#}", &node_id[..8.min(node_id.len())]);
            relay_fallback(state, node_id, ns, id_pub).await
        }
        Err(_) => {
            log::debug!("tcp direct {}: timeout", &node_id[..8.min(node_id.len())]);
            relay_fallback(state, node_id, ns, id_pub).await
        }
    }
}

/// 中继兜底: 经 coordinator 建立嵌套隧道
async fn relay_fallback(
    state: &Arc<NodeState>,
    node_id: &str,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<Arc<Tunnel>> {
    let coord_t = state
        .coord_tunnel
        .read()
        .await
        .clone()
        .context("no path: direct failed and no coordinator for relay")?;
    let h = timeout(
        Duration::from_secs(10),
        tunnel::connect_relayed(&coord_t, node_id, ns, id_pub),
    )
    .await
    .context("relay timeout")??;
    log::info!("relayed via coordinator to {}", &node_id[..8.min(node_id.len())]);
    Ok(adopt_tunnel(state, h, node_id, ns, *id_pub).await)
}

/// 隧道控制消息统一处理: 延迟测量(PING/PONG) + 存活探测 + 可选 ingress 发布
///
/// `ingress = None` 时只处理延迟/回射 ingress 应答 (主动侧/中继侧隧道)
fn spawn_ctrl_handler(
    t: Arc<Tunnel>,
    mut ctrl: mpsc::Receiver<Frame>,
    peer_id: String,
    self_id: Option<String>,
    state: Option<Arc<NodeState>>,
    ingress: Option<(ExitAcl, (u16, u16))>,
) {
    // 每 10s 发一次 PING, 兼作存活探测 (对端不回则 RTT 不更新)
    if let Some(st) = &state {
        let t2 = t.clone();
        let pid = peer_id.clone();
        let st2 = st.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if t2.is_closed() {
                    st2.rtt.write().await.remove(&pid);
                    break;
                }
                if t2.write_frame(&Frame::Ping { ts: now_ms() }).await.is_err() {
                    break;
                }
            }
        });
    }
    // 定时密钥轮换 (默认关闭, 实验性): 需显式设置 YZ_REKEY_SECS>0
    // 已知问题: 切换瞬间旧钥帧积压在 rudp 未确认队列, 新钥帧被窗口阻塞会明显停摆
    if let (Some(me), Some(_)) = (&self_id, &state) {
        let rekey_secs = std::env::var("YZ_REKEY_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        if rekey_secs > 0 && me.as_str() < peer_id.as_str() {
            let t2 = t.clone();
            let secs = rekey_secs;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    if t2.is_closed() {
                        break;
                    }
                    match t2.rekey_begin().await {
                        Ok(wire) => {
                            let payload =
                                yz_proto::encode_control(&ControlMsg::RekeyInit { wire });
                            if t2
                                .write_frame(&Frame::Control { payload })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => log::debug!("rekey begin: {e}"),
                    }
                }
            });
        }
    }
    tokio::spawn(async move {
        while let Some(f) = ctrl.recv().await {
            match f {
                Frame::Ping { ts } => {
                    let _ = t.write_frame(&Frame::Pong { ts }).await;
                }
                Frame::Pong { ts } => {
                    if let Some(st) = &state {
                        let rtt = now_ms().saturating_sub(ts).min(u32::MAX as u64) as u32;
                        st.rtt.write().await.insert(peer_id.clone(), rtt);
                    }
                }
                Frame::Control { payload } => {
                    match yz_proto::decode_control(&payload) {
                        // 对端申请发布端口 (我是入口节点)
                        Ok(ControlMsg::IngressPub { port, addr }) => {
                            if let Some((acl, range)) = &ingress {
                                let (ok, msg) = ingress::handle_pub_request(
                                    &state,
                                    acl,
                                    *range,
                                    &peer_id,
                                    port,
                                    &addr,
                                    t.clone(),
                                )
                                .await;
                                let ack = yz_proto::encode_control(&ControlMsg::IngressPubAck {
                                    port,
                                    ok,
                                    msg,
                                });
                                let _ = t.write_frame(&Frame::Control { payload: ack }).await;
                            }
                        }
                        // 密钥轮换
                        Ok(ControlMsg::RekeyInit { wire }) => match t.rekey_accept(&wire).await {
                            Ok((reply, keys)) => {
                                // 先用旧密钥回 ack, 再切换
                                let payload =
                                    yz_proto::encode_control(&ControlMsg::RekeyAck { wire: reply });
                                let _ = t.write_frame(&Frame::Control { payload }).await;
                                t.apply_keys_responder(&keys).await;
                                log::info!("rekey done (responder, peer {})", &peer_id[..8]);
                            }
                            Err(e) => log::warn!("rekey accept: {e}"),
                        },
                        Ok(ControlMsg::RekeyAck { wire }) => {
                            match t.rekey_finish_with(&wire).await {
                                Ok(()) => log::info!("rekey done (initiator, peer {})", &peer_id[..8]),
                                Err(e) => log::warn!("rekey finish: {e}"),
                            }
                        }
                        Ok(ControlMsg::IngressPubAck { port, ok, msg }) => {
                            log::info!(
                                "ingress :{port} {} ({msg})",
                                if ok { "ok" } else { "failed" }
                            );
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    });
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
    spawn_ctrl_handler(
        t.clone(),
        h.ctrl_rx,
        node_id.to_string(),
        Some(yz_crypto::node_id(&id_pub)),
        Some(state.clone()),
        None,
    );
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
    let punched = match ep.punch(&cands, Duration::from_millis(2500)).await {
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

/// TCP 监听绑定重试 (重启时旧进程可能未退干净; 避免崩溃重启循环)
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
        let acceptor = crate::wss::server_acceptor(Path::new(&cert), Path::new(&key))?;
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

    // 控制消息: PING/PONG(延迟) + 动态 ingress 发布
    spawn_ctrl_handler(
        t.clone(),
        h.ctrl_rx,
        peer_id.clone(),
        Some(yz_crypto::node_id(&ctx.id_pub)),
        ctx.state.clone(),
        Some((ctx.ingress_acl.clone(), ctx.ingress_ports)),
    );

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
        while let Some(Incoming { sid, kind, addr, rx }) = accept_rx.recv().await {
            // UDP 流: 目标侧做数据报中继
            if kind == yz_proto::StreamKind::Udp {
                let t = t.clone();
                tokio::spawn(async move {
                    if let Err(e) = tunnel::pump_udp_stream(addr, sid, rx, t).await {
                        log::debug!("udp stream {sid}: {e:#}");
                    }
                });
                continue;
            }
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
                            let self_id = yz_crypto::node_id(&id_pub);
                            spawn_ctrl_handler(
                                t2.clone(),
                                h.ctrl_rx,
                                pid.clone(),
                                Some(self_id),
                                state.clone(),
                                None,
                            );
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
