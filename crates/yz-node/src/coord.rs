//! coordinator: 节点注册表 + 目录广播。
//! 只做控制信令, 不接触业务明文。

use crate::tunnel::{self, Tunnel};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use yz_proto::{ControlMsg, Frame, NodeEntry};

struct NodeRec {
    name: String,
    addr: String,
    udp_addr: String,
    caps: u8,
    tunnel: Arc<Tunnel>,
}

type Registry = Arc<Mutex<HashMap<String, NodeRec>>>;

pub async fn run(bind: &str, ns: &NetworkSecret, id_pub: [u8; 32], fallback: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    log::info!("coordinator on {bind}, node_id = {}", yz_crypto::node_id(&id_pub));

    // NAT 探测应答器: UDP bind端口 与 +1 (双端口判定对称NAT)
    if let Ok(sa) = bind.parse::<std::net::SocketAddr>() {
        for off in 0u16..=1 {
            let addr = std::net::SocketAddr::new(sa.ip(), sa.port() + off);
            match tokio::net::UdpSocket::bind(addr).await {
                Ok(s) => match yz_rudp::probe_key(ns) {
                    Ok(k) => yz_rudp::spawn_probe_responder(s, k),
                    Err(e) => log::warn!("probe key: {e:#}"),
                },
                Err(e) => log::warn!("probe udp bind {addr}: {e}"),
            }
        }
    }

    let registry: Registry = Default::default();
    loop {
        let (stream, from) = listener.accept().await?;
        let registry = registry.clone();
        let ns = ns.clone();
        let fallback = fallback.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, from.to_string(), &ns, &id_pub, registry, fallback).await {
                log::debug!("node conn from {from} closed: {e:#}");
            }
        });
    }
}

async fn handle(
    stream: TcpStream,
    from: String,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    registry: Registry,
    fallback: Option<String>,
) -> Result<()> {
    let Some(mut h) = tunnel::accept(stream, ns, id_pub, fallback.as_deref()).await? else {
        return Ok(()); // 探针已转发 fallback
    };
    let nid = h.peer.node_id();

    // 首条控制消息必须是 HELLO
    let first = timeout(Duration::from_secs(10), h.ctrl_rx.recv())
        .await?
        .context("expect HELLO")?;
    let (name, addr, udp_addr, caps) = match first {
        Frame::Control { payload } => match yz_proto::decode_control(&payload)? {
            ControlMsg::Hello {
                version,
                name,
                addr,
                udp_addr,
                caps,
            } => {
                // advertise 为通配地址时, 用观察到的源 IP 替代主机部分
                let addr = fixup_advertise(&addr, &from);
                log::info!(
                    "node {} ({name}) joined from {from}, addr {addr}, udp {udp_addr}, proto v{version}",
                    &nid[..8]
                );
                (name, addr, udp_addr, caps)
            }
            _ => bail!("expect HELLO"),
        },
        _ => bail!("expect CONTROL frame"),
    };

    registry.lock().await.insert(
        nid.clone(),
        NodeRec {
            name,
            addr,
            udp_addr,
            caps,
            tunnel: h.tunnel.clone(),
        },
    );
    broadcast(&registry).await;

    // 中继数据面: SYN Domain(node_id, 0) = 请求中继到目标节点
    {
        let registry = registry.clone();
        let t = h.tunnel.clone();
        let mut accept_rx = h.accept_rx;
        tokio::spawn(async move {
            while let Some(crate::tunnel::Incoming { sid, addr, rx }) = accept_rx.recv().await {
                let registry = registry.clone();
                let t = t.clone();
                tokio::spawn(async move {
                    if let Err(e) = relay_stream(registry, t, sid, addr, rx).await {
                        log::debug!("relay: {e:#}");
                    }
                });
            }
        });
    }

    loop {
        tokio::select! {
            f = h.ctrl_rx.recv() => match f {
                Some(Frame::Ping { ts }) => {
                    let _ = h.tunnel.write_frame(&Frame::Pong { ts }).await;
                }
                Some(Frame::Control { payload }) => {
                    if let Ok(ControlMsg::PunchReq { target }) = yz_proto::decode_control(&payload) {
                        route_punch(&registry, &nid, &target).await;
                    }
                }
                Some(_) => {}
                None => break,
            },
            _ = h.closed.changed() => break,
        }
    }

    registry.lock().await.remove(&nid);
    log::info!("node {} left", &nid[..8]);
    broadcast(&registry).await;
    Ok(())
}

async fn broadcast(registry: &Registry) {
    let reg = registry.lock().await;
    let nodes: Vec<NodeEntry> = reg
        .iter()
        .map(|(id, r)| NodeEntry {
            node_id: id.clone(),
            name: r.name.clone(),
            addr: r.addr.clone(),
            udp_addr: r.udp_addr.clone(),
            caps: r.caps,
        })
        .collect();
    let payload = yz_proto::encode_control(&ControlMsg::DirSync { nodes });
    for r in reg.values() {
        let _ = r
            .tunnel
            .write_frame(&Frame::Control {
                payload: payload.clone(),
            })
            .await;
    }
}

/// 打洞撮合: 给双方互发对端 UDP candidates
async fn route_punch(registry: &Registry, from_id: &str, target: &str) {
    let (t_from, t_target, udp_from, udp_target) = {
        let reg = registry.lock().await;
        let (Some(a), Some(b)) = (reg.get(from_id), reg.get(target)) else {
            log::debug!("punch req: {from_id} -> {target} 有一方不在线");
            return;
        };
        (
            a.tunnel.clone(),
            b.tunnel.clone(),
            a.udp_addr.clone(),
            b.udp_addr.clone(),
        )
    };
    let to_req = yz_proto::encode_control(&ControlMsg::PunchStart {
        peer_id: target.to_string(),
        initiator: true,
        addrs: if udp_target.is_empty() {
            vec![]
        } else {
            vec![udp_target]
        },
    });
    let to_tgt = yz_proto::encode_control(&ControlMsg::PunchStart {
        peer_id: from_id.to_string(),
        initiator: false,
        addrs: if udp_from.is_empty() { vec![] } else { vec![udp_from] },
    });
    let _ = t_from.write_frame(&Frame::Control { payload: to_req }).await;
    let _ = t_target.write_frame(&Frame::Control { payload: to_tgt }).await;
    log::debug!("punch撮合 {} <-> {}", &from_id[..8], &target[..8]);
}

/// 中继转发: 在 A 的流与目标节点的流之间对泵 (端口 0 的 SYN 视为中继请求)
async fn relay_stream(
    registry: Registry,
    coord_t: Arc<Tunnel>,
    sid: u32,
    addr: yz_proto::Addr,
    rx: tokio::sync::mpsc::Receiver<Frame>,
) -> Result<()> {
    let yz_proto::Addr::Domain(target, 0) = &addr else {
        bail!("coord stream: only relay (port 0)");
    };
    let target_t = {
        let reg = registry.lock().await;
        reg.get(target).map(|r| r.tunnel.clone()).or_else(|| {
            reg.values()
                .find(|r| r.name == *target)
                .map(|r| r.tunnel.clone())
        })
    };
    let Some(target_t) = target_t else {
        let _ = coord_t
            .write_frame(&Frame::SynAck {
                stream_id: sid,
                ok: false,
            })
            .await;
        bail!("relay target {target} offline");
    };
    // 向目标开中继端点流
    let (sid_b, mut rx_b) = target_t
        .open_stream(yz_proto::Addr::Domain(crate::tunnel::RELAY_MARK.into(), 0))
        .await?;
    match timeout(Duration::from_secs(10), rx_b.recv()).await? {
        Some(Frame::SynAck { ok: true, .. }) => {}
        _ => {
            let _ = coord_t
                .write_frame(&Frame::SynAck {
                    stream_id: sid,
                    ok: false,
                })
                .await;
            bail!("relay target refused");
        }
    }
    coord_t
        .write_frame(&Frame::SynAck {
            stream_id: sid,
            ok: true,
        })
        .await?;
    log::debug!("relay stream {sid} -> {target}");
    crate::tunnel::pipe_streams(coord_t, sid, rx, target_t, sid_b, rx_b).await;
    Ok(())
}

/// advertise 主机为 0.0.0.0/空 时, 用观察到的源 IP 替代
fn fixup_advertise(addr: &str, from: &str) -> String {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return addr.to_string();
    };
    if host.is_empty() || host == "0.0.0.0" || host == "::" || host == "[::]" {
        let src_ip = from.rsplit_once(':').map(|(h, _)| h).unwrap_or(from);
        format!("{src_ip}:{port}")
    } else {
        addr.to_string()
    }
}
