//! peer: 隧道管理与对端数据面（桌面端与 Android 共用）
//!
//! 包含: 隧道建立（复用/局域网直连/打洞/中继）、健康检测、控制消息、
//! 对端开流处理、ingress 发布处理。

use crate::ingress;
use crate::policy::ExitAcl;
use crate::state::CoreState;
use crate::tunnel::{self, Incoming, Tunnel, TunnelHandle};
use crate::util::{is_same_subnet, now_ms, pick_addr};
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

/// 取到指定节点的隧道: 复用活跃隧道 → P2P 打洞 → TCP 兜底 → 中继兜底
pub async fn tunnel_for(
    state: &Arc<CoreState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    node_id: &str,
) -> Result<Arc<Tunnel>> {
    tunnel_for_with(state, ns, id_pub, node_id, true).await
}

/// 同上；`allow_relay=false` 时不做中继兜底（中转请求处理时用，防中继套中继成环）
pub async fn tunnel_for_with(
    state: &Arc<CoreState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    node_id: &str,
    allow_relay: bool,
) -> Result<Arc<Tunnel>> {
    match tunnel_direct_only(state, ns, id_pub, node_id).await {
        Ok(t) => Ok(t),
        Err(e) => {
            if allow_relay {
                relay_fallback(state, node_id, ns, id_pub).await
            } else {
                Err(e)
            }
        }
    }
}

/// 只走直连/打洞（不含中继），中转请求处理与中继跳板选择都用它（防递归成环）
async fn tunnel_direct_only(
    state: &Arc<CoreState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    node_id: &str,
) -> Result<Arc<Tunnel>> {
    // 注意：绝不能在持有 tunnels 锁时 await（is_dead / push_event 都会拿别的锁）
    // 先把候选 Arc 取出来，放掉锁再判断。
    let existing = { state.tunnels.lock().await.get(node_id).cloned() };
    {
        if let Some(t) = existing {
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
                state.tunnels.lock().await.remove(node_id);
            }
        }
    }
    let entry = {
        let dir = state.dir.read().await;
        dir.get(node_id)
            .cloned()
            .with_context(|| format!("node {} not in directory", &node_id[..8.min(node_id.len())]))?
    };
    // 同 /24 的对端直连优先（省掉打洞），不要用 is_private 判，
    // 对端上报的 172.17-31.x 往往是它那边的 docker 网段，会白等 1.5s
    if let Some(a) = pick_addr(&entry.addrs, true) {
        if is_same_subnet(&a) {
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
    // P2P 连续失效后降级: 打洞在对称 NAT 下几乎不可用，指数退避避免每次都白等
    let p2p_ok = {
        let fails = state.p2p_fail.read().await;
        match fails.get(node_id) {
            Some((n, until)) if *n >= 1 && std::time::Instant::now() < *until => {
                log::debug!(
                    "P2P 降级中 (连续失效 {} 次), 跳过打洞: {}",
                    n,
                    &node_id[..8.min(node_id.len())]
                );
                false
            }
            _ => true,
        }
    };

    // 打洞与 TCP 直连**并行竞速**：先成功者胜。
    // 旧实现串行（先打洞 5.5s 再回落），对称 NAT 下每次冷建链都白等 5s。
    let mut punch_task = {
        let st = state.clone();
        let ns2 = ns.clone();
        let ip = *id_pub;
        let e = entry.clone();
        tokio::spawn(async move {
            if !p2p_ok || e.udp_addr.is_empty() {
                return None;
            }
            try_punch(&st, &ns2, &ip, &e).await
        })
    };
    let mut tcp_task = {
        let ns2 = ns.clone();
        let ip = *id_pub;
        let e = entry.clone();
        tokio::spawn(async move {
            for a in e.addrs.iter() {
                match timeout(Duration::from_secs(4), tunnel::connect(a, &ns2, &ip)).await {
                    Ok(Ok(h)) => return Some(h),
                    Ok(Err(err)) => log::debug!("tcp direct {a}: {err:#}"),
                    Err(_) => log::debug!("tcp direct {a}: timeout"),
                }
            }
            None
        })
    };

    let mut punch_done = false;
    let mut tcp_done = false;
    let mut winner: Option<(&'static str, TunnelHandle)> = None;
    loop {
        tokio::select! {
            r = &mut punch_task, if !punch_done => {
                punch_done = true;
                if let Some(h) = r.ok().flatten() {
                    winner = Some(("p2p", h));
                    break;
                }
            }
            r = &mut tcp_task, if !tcp_done => {
                tcp_done = true;
                if let Some(h) = r.ok().flatten() {
                    winner = Some(("direct", h));
                    break;
                }
            }
        }
        if punch_done && tcp_done {
            break;
        }
    }

    match winner {
        Some((path, h)) => {
            log::debug!("竞速胜者: {path}");
            // 清理落败分支：只 abort 未完成的那个。
            // 已完成的 JoinHandle 不能再 poll（tokio 会 panic: polled after completion）；
            // 而且已完成说明它没成功（成功就会被选为 winner），无需处理。
            if path == "p2p" {
                if !tcp_done {
                    tcp_task.abort();
                    if let Ok(Some(l)) = tcp_task.await {
                        l.tunnel.mark_closed();
                    }
                }
            } else if !punch_done {
                punch_task.abort();
                if let Ok(Some(l)) = punch_task.await {
                    l.tunnel.mark_closed();
                }
            }
            if path == "p2p" {
                state.p2p_fail.write().await.remove(node_id);
                state
                    .push_event(
                        "info",
                        format!("P2P 打洞成功: {}", &node_id[..8.min(node_id.len())]),
                    )
                    .await;
            }
            Ok(adopt_tunnel(state, h, node_id, ns, *id_pub, path).await)
        }
        None => anyhow::bail!("直连/打洞均失败: {}", &node_id[..8.min(node_id.len())]),
    }
}

/// 中继兜底: 经 coordinator 建立嵌套隧道

pub async fn relay_fallback(
    state: &Arc<CoreState>,
    node_id: &str,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<Arc<Tunnel>> {
    // 1) 本地化中继：优先经一个「最近且能直连」的节点转发，
    //    避免所有中继流量都压到 geography 很远的 coordinator。
    //    用 allow_relay=false 取该节点的隧道，确保不会再递归中继（防环）。
    {
        let hop = {
            let dir = state.dir.read().await;
            let rtt = state.rtt.read().await;
            let mut v: Vec<(u32, String)> = dir
                .values()
                .filter(|n| n.node_id != node_id)
                .map(|n| {
                    (
                        rtt.get(&n.node_id).copied().unwrap_or(u32::MAX),
                        n.node_id.clone(),
                    )
                })
                .collect();
            v.sort();
            v.first().map(|(_, id)| id.clone())
        };
        if let Some(hop) = hop {
            // 本机必须能直连/打洞到这个跳板（否则无意义）
            if let Ok(Ok(hop_t)) = timeout(
                Duration::from_secs(4),
                tunnel_direct_only(state, ns, id_pub, &hop),
            )
            .await
            {
                if let Ok(Ok(h)) = timeout(
                    Duration::from_secs(6),
                    tunnel::connect_relayed(&hop_t, node_id, ns, id_pub),
                )
                .await
                {
                    state
                        .push_event(
                            "warn",
                            format!(
                                "中继: {} 经 {}",
                                &node_id[..8.min(node_id.len())],
                                &hop[..8.min(hop.len())]
                            ),
                        )
                        .await;
                    log::info!(
                        "localized relay to {} via {}",
                        &node_id[..8.min(node_id.len())],
                        &hop[..8.min(hop.len())]
                    );
                    return Ok(adopt_tunnel(state, h, node_id, ns, *id_pub, "relay").await);
                }
            }
        }
    }

    // 2) 兵底：经 coordinator 中继
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
    state
        .push_event("warn", format!("走中继: {}", &node_id[..8.min(node_id.len())]))
        .await;
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
    // 间隔按路径与实测 NAT 映射存活时间自适应：
    //  · P2P(UDP) 路径必须勤发，否则映射被运营商回收 → 静默丢包（最大不稳定源）
    //  · TCP/中继不存在映射过期，空闲可以降频省电
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
                let is_p2p = st2
                    .path
                    .read()
                    .await
                    .get(&pid)
                    .map(|p| p == "p2p")
                    .unwrap_or(false);
                interval = if is_p2p {
                    // 映射存活时间未知时保守用 10s；测得后取一半，夹在 [8s, 25s]
                    let life = st2
                        .nat_lifetime_secs
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if life == 0 {
                        PING_ACTIVE
                    } else {
                        Duration::from_secs((life / 2).clamp(8, 25))
                    }
                } else if t2.idle_for().await < Duration::from_secs(20) {
                    PING_ACTIVE
                } else {
                    PING_IDLE
                };
                // 判定僵尸 (三层):
                //  a) 隧道已关闭
                //  b) 上一次 PING 至今无 PONG 且超过 1.5×周期 (容忍单次丢包, 连续两轮无应答才判死)
                //  c) 完全静默 (连对端的 PING 都收不到) 超过宽松阈值 (空闲静默 ≠ 链路死)
                let dead_after = interval * 2 + Duration::from_secs(5);
                let unanswered = t2.ping_unanswered_for().await;
                let silent_too_long = t2.idle_for().await > Duration::from_secs(180);
                let dead = t2.is_closed()
                    || match unanswered {
                        Some(d) => d > interval + interval / 2,
                        None => silent_too_long,
                    };
                if dead {
                    log::warn!(
                        "隧道无入向流量 {}s, 判定失效: {}",
                        dead_after.as_secs(),
                        &pid[..8.min(pid.len())]
                    );
                    st2.push_event("warn", format!("隧道失效: {}", &pid[..8.min(pid.len())]))
                        .await;
                    st2.diag(&pid, |d| d.dead += 1);
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
                        // 指数退避：2m → 5m → 15m → 30m（上限）
                        // 对称 NAT 下打洞基本不可用，反复尝试只会白花时间
                        let backoff = match e.0 {
                            1 => 120,
                            2 => 300,
                            3 => 900,
                            _ => 1800,
                        };
                        e.1 = std::time::Instant::now() + Duration::from_secs(backoff);
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
                t2.mark_ping_sent().await;
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
                    t.mark_ping_acked();
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
    log::debug!("adopt {node_id}: {path}");
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
    // 替换旧隧道: 必须显式关闭, 否则旧心跳任务永不退出, 持续误报"隧道失效"
    log::debug!("adopt {node_id}: 旧隧道检查");
    log::debug!("adopt {node_id}: 旧隧道检查");
    {
        let old = state.tunnels.lock().await.get(node_id).cloned();
        if let Some(o) = old {
            if !Arc::ptr_eq(&o, &t) {
                o.mark_closed();
            }
        }
    }
    log::debug!("adopt {node_id}: 写 path 表");
    state
        .path
        .write()
        .await
        .insert(node_id.to_string(), path.to_string());
    // 诊断埋点：路径计数 + 切换记录
    match path {
        "direct" => state.diag(node_id, |d| d.direct_ok += 1),
        "relay" => state.diag(node_id, |d| d.relay_ok += 1),
        _ => {}
    }
    state.note_path(node_id, path);
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
    state.diag(&node_id, |d| d.punch_try += 1);
    let t0 = std::time::Instant::now();
    let punched = match ep.punch(&cands, Duration::from_millis(2500)).await {
        Ok(a) => a,
        Err(e) => {
            log::debug!("punch {}: {e:#}", &node_id[..8.min(node_id.len())]);
            state.diag(&node_id, |d| d.punch_fail += 1);
            return None;
        }
    };
    match ep.connect(punched, ns, id_pub).await {
        Ok((rudp, info)) => {
            let ms = t0.elapsed().as_millis() as u64;
            state.diag(&node_id, |d| {
                d.punch_ok += 1;
                d.punch_ms = ms;
            });
            log::info!("p2p punched {} via {punched}", &node_id[..8.min(node_id.len())]);
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
    /// 谁可以请我当中转（把我当作到达第三方的跳板）
    pub relay_acl: ExitAcl,
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
        ctx.relay_acl.clone(),
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
            // 中转类流（端口 0，非 RELAY_MARK）：不处理时必须显式拒绝，
            // 绝不能落到下面的通用 connect——那会把 <node_id>:0 当域名去解析，
            // 白白等一次 DNS 失败（之前 Android 上就是这么把整条链路弄断的）。
            if matches!(&addr, yz_proto::Addr::Domain(d, 0) if d != tunnel::RELAY_MARK) {
                if !relay_ok {
                    let _ = t
                        .write_frame(&Frame::SynAck {
                            stream_id: sid,
                            ok: false,
                        })
                        .await;
                    log::debug!(
                        "relay request refused (relay disabled on this link): {}",
                        &peer_id[..8.min(peer_id.len())]
                    );
                    continue;
                }
            }
            // 通用中转请求: 对端希望「先到我, 再到另一个节点」
            // 地址形如 Domain(目标节点, 0)，不是 RELAY_MARK 就说明是请我当跳板
            if relay_ok
                && matches!(&addr, yz_proto::Addr::Domain(d, 0) if d != tunnel::RELAY_MARK)
            {
                let yz_proto::Addr::Domain(key, _) = addr.clone() else {
                    continue;
                };
                let t = t.clone();
                let ns = ns.clone();
                let st = state.clone();
                let acl = relay_acl.clone();
                let peer_id = peer_id.clone();
                tokio::spawn(async move {
                    // 拒绝条件: ACL 不允许 / 目标就是请求者自己(防 A→B→A)
                    if !acl.allows(&peer_id) || key == peer_id {
                        let _ = t
                            .write_frame(&Frame::SynAck {
                                stream_id: sid,
                                ok: false,
                            })
                            .await;
                        log::warn!(
                            "relay request denied ({}) from {}",
                            if key == peer_id { "self" } else { "acl" },
                            &peer_id[..8.min(peer_id.len())]
                        );
                        return;
                    }
                    let Some(st) = st else {
                        let _ = t
                            .write_frame(&Frame::SynAck {
                                stream_id: sid,
                                ok: false,
                            })
                            .await;
                        return;
                    };
                    let Some(entry) = resolve_node(&st, &key).await else {
                        let _ = t
                            .write_frame(&Frame::SynAck {
                                stream_id: sid,
                                ok: false,
                            })
                            .await;
                        log::debug!("relay target {key} 不在目录");
                        return;
                    };
                    // allow_relay=false: 中转请求处理时不再递归中继，否则会成环
                    // 中转请求处理：只走直连/打洞，不再递归中继（防成环）
                    let target_t = match tunnel_direct_only(&st, &ns, &id_pub, &entry.node_id).await {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = t
                                .write_frame(&Frame::SynAck {
                                    stream_id: sid,
                                    ok: false,
                                })
                                .await;
                            log::debug!("relay: 到 {} 的隧道失败: {e:#}", &entry.node_id[..8.min(entry.node_id.len())]);
                            return;
                        }
                    };
                    // 向目标开中继端点流并等它应答
                    let (sid_b, mut rx_b) = match target_t
                        .open_stream(yz_proto::Addr::Domain(tunnel::RELAY_MARK.into(), 0))
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = t
                                .write_frame(&Frame::SynAck {
                                    stream_id: sid,
                                    ok: false,
                                })
                                .await;
                            log::debug!("relay: open RELAY_MARK 失败: {e:#}");
                            return;
                        }
                    };
                    match timeout(Duration::from_secs(10), rx_b.recv()).await {
                        Ok(Some(Frame::SynAck { ok: true, .. })) => {}
                        _ => {
                            let _ = t
                                .write_frame(&Frame::SynAck {
                                    stream_id: sid,
                                    ok: false,
                                })
                                .await;
                            log::debug!("relay: 目标未应答");
                            return;
                        }
                    }
                    if t.write_frame(&Frame::SynAck { stream_id: sid, ok: true })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    log::debug!(
                        "relay stream {sid}: {} -> {}",
                        &peer_id[..8.min(peer_id.len())],
                        &entry.node_id[..8.min(entry.node_id.len())]
                    );
                    crate::tunnel::pipe_streams(t, sid, rx, target_t, sid_b, rx_b).await;
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
