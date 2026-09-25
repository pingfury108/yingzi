//! node: 对等节点。
//! - peer 隧道监听 (exit 数据面, ACL 控制)
//! - coordinator 注册/目录同步
//! - SOCKS5 入口 + 策略路由: direct / auto / 指定节点出口
//!
//! serve 子命令复用 handle_peer (无 mesh 的独立出口, ACL=All)。

use crate::ingress::{self, IngressEntry, IngressRule};
use crate::policy::{match_route, ExitAcl, RouteRule};
use crate::socks5;
use crate::tunnel::{self, Incoming, Tunnel};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
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
}

pub async fn run(opts: NodeOpts, ns: &NetworkSecret, id_pub: [u8; 32]) -> Result<()> {
    let self_id = yz_crypto::node_id(&id_pub);
    let state = Arc::new(NodeState::default());
    *state.routes.write().await = opts.routes.clone();
    *state.default_exit.write().await = opts.default_exit.clone();

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
        };
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, from)) => {
                        let ns = ns.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_peer(stream, &ns, &id_pub, &ctx).await {
                                log::debug!("peer conn from {from} closed: {e:#}");
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
                let hello = yz_proto::encode_control(&ControlMsg::Hello {
                    version: 1,
                    name: opts.name.clone(),
                    addr: opts.advertise.clone(),
                    caps: if opts.exit_acl.advertise() {
                        caps::EXIT
                    } else {
                        0
                    },
                });
                if let Err(e) = h.tunnel.write_frame(&Frame::Control { payload: hello }).await {
                    log::warn!("send HELLO: {e:#}");
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
                                                format!("{}{}({})", n.name, exit, &n.node_id[..8])
                                            })
                                            .collect();
                                        log::info!("directory: {} nodes: {}", nodes.len(), list.join(", "));
                                        let mut dir = state.dir.write().await;
                                        dir.clear();
                                        for n in nodes {
                                            dir.insert(n.node_id.clone(), n);
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

/// 取到指定节点的隧道: 复用活跃隧道, 否则按目录地址新建
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
    let addr = {
        let dir = state.dir.read().await;
        dir.get(node_id)
            .map(|n| n.addr.clone())
            .with_context(|| format!("node {} not in directory", &node_id[..8.min(node_id.len())]))?
    };
    let h = tunnel::connect(&addr, ns, id_pub).await?;
    let t = h.tunnel.clone();
    // 控制消息暂无用武之地, 排空; 对端开流(如动态ingress)必须接管
    let mut ctrl = h.ctrl_rx;
    tokio::spawn(async move { while ctrl.recv().await.is_some() {} });
    spawn_incoming_handler(t.clone(), h.accept_rx, node_id.to_string());

    state
        .tunnels
        .lock()
        .await
        .insert(node_id.to_string(), t.clone());
    Ok(t)
}

// ---------- exit 数据面 ----------

/// 对端隧道上下文
#[derive(Clone)]
pub struct PeerCtx {
    pub exit_acl: ExitAcl,
    pub ingress_acl: ExitAcl,
    pub ingress_ports: (u16, u16),
    pub state: Option<Arc<NodeState>>,
}

/// 独立出口 (serve 子命令), 允许组网内任何节点, 不开 ingress
pub async fn serve(bind: &str, ns: &NetworkSecret, id_pub: [u8; 32]) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    log::info!("serving tunnel on {bind}");
    let ctx = PeerCtx {
        exit_acl: ExitAcl::All,
        ingress_acl: ExitAcl::None,
        ingress_ports: (0, 0),
        state: None,
    };
    loop {
        let (stream, from) = listener.accept().await?;
        let ns = ns.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_peer(stream, &ns, &id_pub, &ctx).await {
                log::debug!("conn from {from} closed: {e:#}");
            }
        });
    }
}

/// 对端隧道: ACL 检查后接收流并访问目标; 处理 INGRESS_PUB 控制消息
pub async fn handle_peer(
    stream: TcpStream,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    ctx: &PeerCtx,
) -> Result<()> {
    let h = tunnel::accept(stream, ns, id_pub).await?;
    let peer_id = h.peer.node_id();
    if !ctx.exit_acl.allows(&peer_id) {
        log::warn!("exit denied for peer {}", &peer_id[..8]);
        bail!("exit denied by acl");
    }
    log::debug!("peer {} tunnel up", &peer_id[..8]);
    let t = h.tunnel.clone();

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

    spawn_incoming_handler(t.clone(), h.accept_rx, peer_id.clone());
    let mut closed = h.closed;
    let _ = closed.changed().await;
    Ok(())
}

/// 消费对端开流: 连接目标地址并转发 (被动侧与主动侧复用)
pub(crate) fn spawn_incoming_handler(
    t: Arc<Tunnel>,
    mut accept_rx: tokio::sync::mpsc::Receiver<Incoming>,
    peer_id: String,
) {
    tokio::spawn(async move {
        while let Some(Incoming { sid, addr, rx }) = accept_rx.recv().await {
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
