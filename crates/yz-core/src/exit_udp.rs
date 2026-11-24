//! exit_udp: 经出口节点转发 UDP（复用 mesh 的 UDP 流）

use crate::stack::{ExitUdp, UdpRelay};
use crate::state::CoreState;
use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use yz_proto::{Addr, Frame, StreamKind};

pub struct TunnelExitUdp {
    pub state: Arc<CoreState>,
    pub ns: NetworkSecret,
    pub id_pub: [u8; 32],
}

impl TunnelExitUdp {
    pub fn new(state: Arc<CoreState>, ns: NetworkSecret, id_pub: [u8; 32]) -> Self {
        Self {
            state,
            ns,
            id_pub,
        }
    }
}

impl ExitUdp for TunnelExitUdp {
    fn open<'a>(
        &'a self,
        node: &'a str,
        dst: SocketAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Box<dyn UdpRelay>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let node_id = {
                let dir = self.state.dir.read().await;
                dir.values()
                    .find(|n| n.name == node || n.node_id == node || n.node_id.starts_with(node))
                    .map(|n| n.node_id.clone())
                    .with_context(|| format!("出口节点不在目录中: {node}"))?
            };
            // 走出口自动选路（直连 vs 经中转）
            let t = crate::exit_tunnel_for(&self.state, &self.ns, &self.id_pub, &node_id).await?;
            let target = match dst.ip() {
                std::net::IpAddr::V4(v4) => Addr::V4(v4.octets(), dst.port()),
                std::net::IpAddr::V6(v6) => Addr::V6(v6.octets(), dst.port()),
            };
            let (sid, mut rx) = t.open_stream_kind(target, StreamKind::Udp).await?;
            match timeout(Duration::from_secs(8), rx.recv()).await? {
                Some(Frame::SynAck { ok: true, .. }) => {}
                _ => {
                    t.close_stream(sid).await;
                    bail!("出口 {node} UDP 流未就绪");
                }
            }
            Ok(Box::new(TunnelUdpRelay {
                t,
                sid,
                rx: Mutex::new(rx),
            }) as Box<dyn UdpRelay>)
        })
    }
}

struct TunnelUdpRelay {
    t: Arc<crate::tunnel::Tunnel>,
    sid: u32,
    rx: Mutex<tokio::sync::mpsc::Receiver<Frame>>,
}

impl UdpRelay for TunnelUdpRelay {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.t
                .write_frame(&Frame::Data {
                    stream_id: self.sid,
                    payload: data.to_vec(),
                })
                .await
        })
    }

    fn recv<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let mut rx = self.rx.lock().await;
            loop {
                match rx.recv().await {
                    Some(Frame::Data { payload, .. }) => return Ok(payload),
                    Some(Frame::Fin { .. }) | Some(Frame::Rst { .. }) => bail!("出口 UDP 流关闭"),
                    Some(_) => continue,
                    None => bail!("出口 UDP 流结束"),
                }
            }
        })
    }
}

// ---------- 出口 TCP ----------

use crate::tcp_stack::{ExitTcp, UpstreamIo};

pub struct TunnelExitTcp {
    pub state: Arc<CoreState>,
    pub ns: NetworkSecret,
    pub id_pub: [u8; 32],
}

impl TunnelExitTcp {
    pub fn new(state: Arc<CoreState>, ns: NetworkSecret, id_pub: [u8; 32]) -> Self {
        Self {
            state,
            ns,
            id_pub,
        }
    }
}

impl ExitTcp for TunnelExitTcp {
    fn open<'a>(
        &'a self,
        node: &'a str,
        dst: SocketAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Box<dyn UpstreamIo>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let node_id = {
                let dir = self.state.dir.read().await;
                dir.values()
                    .find(|n| n.name == node || n.node_id == node || n.node_id.starts_with(node))
                    .map(|n| n.node_id.clone())
                    .with_context(|| format!("出口节点不在目录中: {node}"))?
            };
            // 走出口自动选路（直连 vs 经中转）
            let t = crate::exit_tunnel_for(&self.state, &self.ns, &self.id_pub, &node_id).await?;
            let target = match dst.ip() {
                std::net::IpAddr::V4(v4) => Addr::V4(v4.octets(), dst.port()),
                std::net::IpAddr::V6(v6) => Addr::V6(v6.octets(), dst.port()),
            };
            let (sid, mut rx) = t.open_stream(target).await?;
            match timeout(Duration::from_secs(8), rx.recv()).await? {
                Some(Frame::SynAck { ok: true, .. }) => {}
                _ => {
                    t.close_stream(sid).await;
                    bail!("出口 {node} TCP 流未就绪");
                }
            }
            Ok(Box::new(crate::tunnel::StreamIo::new(t, sid, rx)) as Box<dyn UpstreamIo>)
        })
    }
}
