//! exit_dns: 经出口节点转发 DNS 查询（复用 mesh 的 UDP 流）
//!
//! 场景：本机在受限网络（DoT 被墙/本地 DNS 被投毒）时，
//! 把 DNS 查询塞进到出口节点的隧道，由出口节点代为发出。
//! 出口节点只需支持已有的 UDP 流中继（pump_udp_stream），无需新增协议。

use crate::dns::ExitDnsQuery;
use crate::state::CoreState;
use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use yz_proto::{Addr, Frame, StreamKind};

pub struct TunnelExitDns {
    pub state: Arc<CoreState>,
    pub ns: NetworkSecret,
    pub id_pub: [u8; 32],
}

impl TunnelExitDns {
    pub fn new(state: Arc<CoreState>, ns: NetworkSecret, id_pub: [u8; 32]) -> Self {
        Self {
            state,
            ns,
            id_pub,
        }
    }
}

impl ExitDnsQuery for TunnelExitDns {
    fn query<'a>(
        &'a self,
        node: &'a str,
        server: SocketAddr,
        raw_query: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            // 解析节点名 → node_id
            let node_id = {
                let dir = self.state.dir.read().await;
                dir.values()
                    .find(|n| n.name == node || n.node_id == node || n.node_id.starts_with(node))
                    .map(|n| n.node_id.clone())
                    .with_context(|| format!("出口节点不在目录中: {node}"))?
            };

            // 走出口自动选路（直连 vs 经中转），与 node 的 TCP/UDP 入口一致
            let t = crate::exit_tunnel_for(&self.state, &self.ns, &self.id_pub, &node_id).await?;

            let target = match server.ip() {
                std::net::IpAddr::V4(v4) => Addr::V4(v4.octets(), server.port()),
                std::net::IpAddr::V6(v6) => Addr::V6(v6.octets(), server.port()),
            };
            let (sid, mut rx) = t.open_stream_kind(target, StreamKind::Udp).await?;

            // 等出口侧就绪
            match timeout(Duration::from_secs(8), rx.recv()).await? {
                Some(Frame::SynAck { ok: true, .. }) => {}
                Some(Frame::SynAck { ok: false, .. }) => {
                    t.close_stream(sid).await;
                    bail!("出口 {node} 拒绝 DNS 流");
                }
                _ => {
                    t.close_stream(sid).await;
                    bail!("出口 {node} DNS 流未就绪");
                }
            }

            // 发送查询（一帧 = 一个数据报）
            t.write_frame(&Frame::Data {
                stream_id: sid,
                payload: raw_query.to_vec(),
            })
            .await?;

            // 读应答
            let resp = timeout(Duration::from_secs(8), async {
                while let Some(f) = rx.recv().await {
                    match f {
                        Frame::Data { payload, .. } => return Ok(payload),
                        Frame::Fin { .. } | Frame::Rst { .. } => break,
                        _ => {}
                    }
                }
                bail!("出口 DNS 流已关闭")
            })
            .await;

            t.close_stream(sid).await;
            let _ = t.write_frame(&Frame::Fin { stream_id: sid }).await;
            resp?
        })
    }
}
