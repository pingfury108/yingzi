//! peer: 隧道管理与对端数据面（桌面端与 Android 共用）
//!
//! 包含: 隧道建立（复用/局域网直连/打洞/中继）、健康检测、控制消息、
//! 对端开流处理、ingress 发布处理。

use crate::ingress;
use crate::policy::ExitAcl;
use crate::state::CoreState;
use crate::tunnel::{self, Incoming, Tunnel, TunnelHandle};
use crate::util::{is_lan_addr, now_ms, pick_addr};
use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use yz_proto::{ControlMsg, Frame, NodeEntry};

pub async fn resolve_node(state: &Arc<CoreState>, key: &str) -> Option<NodeEntry> {
    let dir = state.dir.read().await;
    dir.values()
        .find(|n| n.node_id == key || n.name == key || n.node_id.starts_with(key))
        .cloned()
}

/// 取到指定节点的隧道: 复用活跃隧道 → P2P 打洞 → TCP 兜底
pub async fn tunnel_for(
    state: &Arc<CoreState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    node_id: &str,
) -> Result<Arc<Tunnel>> {
    {
        let tunnels = state.tunnels.lock().await;
        if let Some(t) = tunnels.get(node_id) {
            // 僵尸隧道判定: P2P UDP 会因 NAT 映射过期静默死亡, 必须按"无入向流量超时"淘汰
            if !t.is_closed() && !t.is_dead(Duration::from_secs(45)).await {
                return Ok(t.clone());
            }
            if t.is_closed() {
                log::debug!("复用隧道已关闭, 重建: {}", &node_id[..8.min(node_id.len())]);
            } else {
                log::info!(
                    "隧道无响应 {}s, 判定失效并重建: {}",
                    t.idle_for().await.as_secs(),
                    &node_id[..8.min(node_id.len())]
                );
                state
                    .push_event(
                        "warn",
                        format!("隧道失效重建: {}", &node_id[..8.min(node_id.len())]),
                    )
                    .await;
                t.mark_closed();
            }
        }
    }
    let entry = {
        let dir = state.dir.read().await;
        dir.get(node_id)
            .cloned()
            .with_context(|| format!("node {} not in directory", &node_id[..8.min(node_id.len())]))?
    };
    // 局域网对端: 直连优先 (省掉打洞等待, 同网段通常 <1ms 可连)
    if let Some(a) = pick_addr(&entry.addrs, true) {
        if is_lan_addr(&a) {
            if let Ok(Ok(h)) = timeout(
                Duration::from_millis(1500),
                tunnel::connect(&a, ns, id_pub),
            )
            .await
            {
                log::debug!("lan direct to {} ({a})", &node_id[..8]);
                return Ok(adopt_tunnel(state, h, node_id, ns, *id_pub, "direct").await);
            }
        }
    }
    // P2P 连续失效后短暂降级: 跳过打洞直接走 TCP (打洞在对称 NAT 下易反复失效)
    let p2p_ok = {
        let fails = state.p2p_fail.read().await;
        match fails.get(node_id) {
            Some((n, until)) if *n >= 1 && std::time::Instant::now() < *until => {
                log::debug!("P2P 降级中 (连续失效 {} 次), 跳过打洞: {}", n, &node_id[..8.min(node_id.len())]);
                false
            }
            _ => true,
        }
    };
    // P2P 打洞优先
    if p2p_ok && !entry.udp_addr.is_empty() {
        if let Some(h) = try_punch(state, ns, id_pub, &entry).await {
            state.p2p_fail.write().await.remove(node_id);
            state.push_event("info", format!("P2P 打洞成功: {}", &node_id[..8.min(node_id.len())])).await;
            return Ok(adopt_tunnel(state, h, node_id, ns, *id_pub, "p2p").await);
        }
    }
    // TCP 兜底 → 中继兜底 (依次尝试各地址, 直连加快速超时避免黑洞拖死降级链)
    let mut last_err: Option<anyhow::Error> = None;
    for a in entry.addrs.iter() {
        match timeout(Duration::from_secs(4), tunnel::connect(a, ns, id_pub)).await {
            Ok(Ok(h)) => {
                return Ok(adopt_tunnel(state, h, node_id, ns, *id_pub, "direct").await)
            }
            Ok(Err(e)) => {
                log::debug!("tcp direct {a}: {e:#}");
                last_err = Some(e);
            }
            Err(_) => log::debug!("tcp direct {a}: timeout"),
        }
    }
    if let Some(e) = last_err {
        log::debug!("tcp direct {} 全部失败: {e:#}", &node_id[..8.min(node_id.len())]);
    }
    relay_fallback(state, node_id, ns, id_pub).await
}

/// 中继兜底: 经 coordinator 建立嵌套隧道

pub async fn relay_fallback(
    state: &Arc<CoreState>,
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
    state.push_event("warn", format!("走中继: {}", &node_id[..8.min(node_id.len())])).await;
    Ok(adopt_tunnel(state, h, node_id, ns, *id_pub, "relay").await)
}

/// 隧道控制消息统一处理: 延迟测量(PING/PONG) + 存活探测 + 可选 ingress 发布
///
/// `ingress = None` 时只处理延迟/回射 ingress 应答 (主动侧/中继侧隧道)

pub fn spawn_ctrl_handler(
    t: Arc<Tunnel>,
    mut ctrl: mpsc::Receiver<Frame>,
    peer_id: String,
    self_id: Option<String>,
    state: Option<Arc<CoreState>>,
    ingress: Option<(ExitAcl, (u16, u16))>,
) {
    // 心跳: 兼作存活探测 + 维持 NAT 映射。
    // 自适应间隔: 活跃 10s / 空闲 30s —— 手机端省电（避免 10s 一次唤醒射频）
    const PING_ACTIVE: Duration = Duration::from_secs(10);
    const PING_IDLE: Duration = Duration::from_secs(30);
    if let Some(st) = &state {
        let t2 = t.clone();
        let pid = peer_id.clone();
        let st2 = st.clone();
        tokio::spawn(async move {
            let mut interval = PING_ACTIVE;
            loop {
                tokio::time::sleep(interval).await;
                if t2.is_closed() {
                    st2.rtt.write().await.remove(&pid);
                    break;
                }
                // 空闲超过 20s 降频到 30s；有流量立刻回到 10s
                interval = if t2.idle_for().await < Duration::from_secs(20) {
                    PING_ACTIVE
                } else {
                    PING_IDLE
                };
                // 判定僵尸: 两个心跳周期无任何入向数据 (PING 发出但无 PONG/数据回来)
                let dead_after = interval * 2 + Duration::from_secs(5);
                if t2.is_dead(dead_after).await {
                    log::warn!(
                        "隧道无入向流量 {}s, 判定失效: {}",
                        dead_after.as_secs(),
                        &pid[..8.min(pid.len())]
                    );
                    st2.push_event("warn", format!("隧道失效: {}", &pid[..8.min(pid.len())]))
                        .await;
                    st2.rtt.write().await.remove(&pid);
                    // 若是 P2P 路径, 累加失效计数并降级 5 分钟
                    let was_p2p = st2
                        .path
                        .read()
                        .await
                        .get(&pid)
                        .map(|p| p == "p2p")
                        .unwrap_or(false);
                    {
                        let mut fails = st2.p2p_fail.write().await;
                        let e = fails.entry(pid.clone()).or_insert((0, std::time::Instant::now()));
                        e.0 += 1;
                        // 首次失效即降级 2 分钟, 避免反复在打洞上耗时间
                        e.1 = std::time::Instant::now() + Duration::from_secs(120);
                        log::info!(
                            "隧道失效({}) 计数 {} → 降级 2 分钟: {}",
                            if was_p2p { "p2p" } else { "其它" },
                            e.0,
                            &pid[..8.min(pid.len())]
                        );
                    }
                    st2.path.write().await.remove(&pid);
                    t2.mark_closed();
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


/// 隧道收编: 排空控制消息 + 接管对端开流 + mesh 转发 + 注册到隧道表
pub async fn adopt_tunnel(
    state: &Arc<CoreState>,
    h: TunnelHandle,
    node_id: &str,
    ns: &NetworkSecret,
    id_pub: [u8; 32],
    path: &str,
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
        .path
        .write()
        .await
        .insert(node_id.to_string(), path.to_string());
    state.push_event("info", format!("隧道建立: {} ({path})", &node_id[..8.min(node_id.len())])).await;
    state
        .tunnels
        .lock()
        .await
        .insert(node_id.to_string(), t.clone());
    t
}

/// 经 coordinator 撮合打洞, 成功返回 P2P UDP 隧道

pub async fn try_punch(
    state: &Arc<CoreState>,
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
    pub state: Option<Arc<CoreState>>,
    pub fallback: Option<String>,
    pub ns: NetworkSecret,
    pub id_pub: [u8; 32],
}

/// TCP 监听绑定重试 (重启时旧进程可能未退干净; 避免崩溃重启循环)

pub async fn handle_peer(h: TunnelHandle, ctx: &PeerCtx) -> Result<()> {
    let peer_id = h.peer.node_id();
    if !ctx.exit_acl.allows(&peer_id) {
        log::warn!("exit denied for peer {}", &peer_id[..8]);
        bail!("exit denied by acl");
    }
    log::debug!("peer {} tunnel up", &peer_id[..8]);
    let t = h.tunnel.clone();
    // P2P 被接受的隧道也注册, 双向复用
    let path = if h.tunnel.transport() == "udp" { "p2p" } else { "direct" };
    if let Some(st) = &ctx.state {
        st.tunnels.lock().await.insert(peer_id.clone(), t.clone());
        st.path.write().await.insert(peer_id.clone(), path.to_string());
        st.push_event("info", format!("隧道建立: {peer_id} ({path})")).await;
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
        st.path.write().await.remove(&peer_id);
        st.push_event("warn", format!("隧道断开: {peer_id}")).await;
    }
    Ok(())
}

pub fn spawn_incoming_handler(
    t: Arc<Tunnel>,
    mut accept_rx: tokio::sync::mpsc::Receiver<Incoming>,
    peer_id: String,
    ns: NetworkSecret,
    id_pub: [u8; 32],
    state: Option<Arc<CoreState>>,
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

/// 建隧道带重试: 部署/重启窗口期目录或链路暂不可用时, 等待而不是立即失败
pub async fn tunnel_for_retry(
    state: &Arc<CoreState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    node_id: &str,
    attempts: usize,
    gap: Duration,
) -> Result<Arc<Tunnel>> {
    let mut last: Option<anyhow::Error> = None;
    for i in 0..attempts {
        if i > 0 {
            tokio::time::sleep(gap).await;
        }
        match tunnel_for(state, ns, id_pub, node_id).await {
            Ok(t) => return Ok(t),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("attempts > 0"))
}
