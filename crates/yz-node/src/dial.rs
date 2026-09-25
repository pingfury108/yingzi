//! dial: 本地入口。维持一条到 peer 的复用隧道(断线重连), 每个本地连接开一条流。

use crate::tunnel::{self, Tunnel};
use anyhow::{bail, Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use yz_proto::{Addr, Frame};

pub async fn run(
    peer: &str,
    listen: &str,
    target: Addr,
    ns: &NetworkSecret,
    id_pub: [u8; 32],
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("entry on {listen}, via {peer} -> {target}");

    let current: Arc<Mutex<Option<Arc<Tunnel>>>> = Default::default();

    // 隧道维持任务
    {
        let current = current.clone();
        let peer = peer.to_string();
        let ns = ns.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                match tunnel::connect(&peer, &ns, &id_pub).await {
                    Ok(h) => {
                        backoff = Duration::from_secs(1);
                        log::info!("tunnel to {} up", &h.peer.node_id()[..8]);
                        *current.lock().await = Some(h.tunnel.clone());
                        let mut closed = h.closed.clone();
                        let mut ctrl = h.ctrl_rx;
                        tokio::spawn(async move { while ctrl.recv().await.is_some() {} });
                        let mut accept = h.accept_rx;
                        tokio::spawn(async move { while accept.recv().await.is_some() {} });
                        let _ = closed.changed().await;
                        current.lock().await.take();
                        log::warn!("tunnel down, reconnecting");
                    }
                    Err(e) => log::warn!("dial tunnel: {e:#}"),
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        });
    }

    loop {
        let (local, from) = listener.accept().await?;
        let current = current.clone();
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_local(local, current, target).await {
                log::debug!("local {from}: {e:#}");
            }
        });
    }
}

async fn handle_local(
    local: TcpStream,
    current: Arc<Mutex<Option<Arc<Tunnel>>>>,
    target: Addr,
) -> Result<()> {
    let t = { current.lock().await.clone().context("tunnel not ready")? };
    let (sid, mut rx) = t.open_stream(target).await?;
    match timeout(Duration::from_secs(10), rx.recv()).await? {
        Some(Frame::SynAck { ok: true, .. }) => {}
        Some(Frame::SynAck { ok: false, .. }) => bail!("remote connect target failed"),
        _ => bail!("expect SYN_ACK"),
    }
    tunnel::pump_stream(local, sid, rx, t).await
}
