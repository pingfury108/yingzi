//! node: 对等节点。监听 peer 隧道(exit 数据面) + 连 coordinator 同步节点目录。
//! serve 子命令复用 handle_peer (无 mesh 的独立出口)。

use crate::tunnel::{self, Incoming};
use anyhow::Result;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use yz_crypto::NetworkSecret;
use yz_proto::{ControlMsg, Frame};

/// 完整节点: peer 隧道监听 + coordinator 注册/目录同步
pub async fn run(
    bind: &str,
    coord: &str,
    name: &str,
    ns: &NetworkSecret,
    id_pub: [u8; 32],
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    log::info!("node [{name}] serving peers on {bind}");
    {
        let ns = ns.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, from)) => {
                        let ns = ns.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_peer(stream, &ns, &id_pub).await {
                                log::debug!("peer conn from {from} closed: {e:#}");
                            }
                        });
                    }
                    Err(e) => log::warn!("accept: {e}"),
                }
            }
        });
    }

    // coordinator 注册 + 目录同步, 指数退避重连
    let mut backoff = Duration::from_secs(1);
    loop {
        match tunnel::connect(coord, ns, &id_pub).await {
            Ok(mut h) => {
                backoff = Duration::from_secs(1);
                log::info!("registered to coordinator {coord} ({})", &h.peer.node_id()[..8]);
                let hello = yz_proto::encode_control(&ControlMsg::Hello {
                    version: 1,
                    name: name.to_string(),
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
                                            .map(|n| format!("{}({})", n.name, &n.node_id[..8]))
                                            .collect();
                                        log::info!("directory: {} nodes: {}", nodes.len(), list.join(", "));
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
                log::warn!("lost coordinator, reconnecting...");
            }
            Err(e) => log::warn!("connect coordinator: {e:#}"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// 独立出口 (serve 子命令)
pub async fn serve(bind: &str, ns: &NetworkSecret, id_pub: [u8; 32]) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    log::info!("serving tunnel on {bind}");
    loop {
        let (stream, from) = listener.accept().await?;
        let ns = ns.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_peer(stream, &ns, &id_pub).await {
                log::debug!("conn from {from} closed: {e:#}");
            }
        });
    }
}

/// 对端隧道: 接收流并访问目标 (exit 数据面; ACL 在 P3)
pub async fn handle_peer(
    stream: TcpStream,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<()> {
    let mut h = tunnel::accept(stream, ns, id_pub).await?;
    log::debug!("peer {} tunnel up", &h.peer.node_id()[..8]);
    let t = h.tunnel.clone();
    // P0/P1 阶段 peer 控制消息无用途, 排空防止通道堆积
    let mut ctrl = h.ctrl_rx;
    tokio::spawn(async move { while ctrl.recv().await.is_some() {} });

    while let Some(Incoming { sid, addr, rx }) = h.accept_rx.recv().await {
        let t = t.clone();
        tokio::spawn(async move {
            match TcpStream::connect(addr.to_string()).await {
                Ok(local) => {
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
    Ok(())
}
