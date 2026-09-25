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
    caps: u8,
    tunnel: Arc<Tunnel>,
}

type Registry = Arc<Mutex<HashMap<String, NodeRec>>>;

pub async fn run(bind: &str, ns: &NetworkSecret, id_pub: [u8; 32]) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    log::info!("coordinator on {bind}, node_id = {}", yz_crypto::node_id(&id_pub));
    let registry: Registry = Default::default();
    loop {
        let (stream, from) = listener.accept().await?;
        let registry = registry.clone();
        let ns = ns.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, from.to_string(), &ns, &id_pub, registry).await {
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
) -> Result<()> {
    let mut h = tunnel::accept(stream, ns, id_pub).await?;
    let nid = h.peer.node_id();

    // 首条控制消息必须是 HELLO
    let first = timeout(Duration::from_secs(10), h.ctrl_rx.recv())
        .await?
        .context("expect HELLO")?;
    let (name, addr, caps) = match first {
        Frame::Control { payload } => match yz_proto::decode_control(&payload)? {
            ControlMsg::Hello {
                version,
                name,
                addr,
                caps,
            } => {
                // advertise 为通配地址时, 用观察到的源 IP 替代主机部分
                let addr = fixup_advertise(&addr, &from);
                log::info!(
                    "node {} ({name}) joined from {from}, addr {addr}, proto v{version}",
                    &nid[..8]
                );
                (name, addr, caps)
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
            caps,
            tunnel: h.tunnel.clone(),
        },
    );
    broadcast(&registry).await;

    loop {
        tokio::select! {
            f = h.ctrl_rx.recv() => match f {
                Some(Frame::Ping { ts }) => {
                    let _ = h.tunnel.write_frame(&Frame::Pong { ts }).await;
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
