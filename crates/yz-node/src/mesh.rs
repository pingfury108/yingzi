//! mesh: TUN 虚拟组网 (P6)。
//! vIP = 100.64.0.0/10 | node_id 低 22 位 (确定性分配, 无需协调)。
//! TUN 读 IP 包 → 目的 vIP 反查 node_id → tunnel_for (自动 P2P) → Mesh 帧。

use crate::node::{tunnel_for, NodeState};
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use yz_crypto::NetworkSecret;
use yz_proto::Frame;

/// node_id(16 hex) → 100.64.0.0/10 内的确定性虚拟 IP
pub fn vip_of(node_id: &str) -> Ipv4Addr {
    let b = yz_crypto::from_hex(node_id).unwrap_or_else(|_| vec![0u8; 8]);
    let mut raw = [0u8; 8];
    let n = b.len().min(8);
    raw[8 - n..].copy_from_slice(&b[b.len() - n..]);
    let low = (u64::from_be_bytes(raw) & 0x3F_FFFF) as u32; // 低 22 位
    Ipv4Addr::from(0x6440_0000u32 | low) // 100.64.0.0/10
}

pub async fn run(
    ifname: &str,
    state: Arc<NodeState>,
    ns: NetworkSecret,
    id_pub: [u8; 32],
    self_id: String,
) -> Result<()> {
    let vip = vip_of(&self_id);
    let mut cfg = tun::Configuration::default();
    cfg.tun_name(ifname)
        .mtu(1400)
        .address(vip)
        .netmask(Ipv4Addr::new(255, 192, 0, 0))
        .up();
    let dev = tun::create_as_async(&cfg).context("create tun (需要 root 或 CAP_NET_ADMIN)")?;
    let dev = Arc::new(dev);
    log::info!("tun {ifname} up, virtual ip {vip}/10");

    // 收编队列: 各隧道的 mesh 帧 → TUN
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
    *state.mesh_sink.write().await = Some(tx);
    {
        let dev = dev.clone();
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                if let Err(e) = dev.send(&pkt).await {
                    log::debug!("tun write: {e}");
                }
            }
        });
    }

    let mut buf = vec![0u8; 2048];
    loop {
        let n = dev.recv(&mut buf).await?;
        let pkt = &buf[..n];
        let Some(dst) = dst_v4(pkt) else { continue };
        if dst == vip {
            continue;
        }
        let Some(nid) = find_node_by_vip(&state, dst).await else {
            continue; // 未知目的, 静默丢
        };
        match tunnel_for(&state, &ns, &id_pub, &nid).await {
            Ok(t) => {
                if let Err(e) = t
                    .write_frame(&Frame::Mesh {
                        payload: pkt.to_vec(),
                    })
                    .await
                {
                    log::debug!("mesh write {dst}: {e:#}");
                }
            }
            Err(e) => log::debug!("mesh route {dst}: {e:#}"),
        }
    }
}

/// 隧道 mesh 帧 → 本地 TUN (每条隧道一个转发任务)
pub fn spawn_forward(mut rx: mpsc::Receiver<Vec<u8>>, state: Arc<NodeState>) {
    tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            let sink = state.mesh_sink.read().await.clone();
            if let Some(sink) = sink {
                let _ = sink.send(pkt).await;
            }
        }
    });
}

fn dst_v4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

async fn find_node_by_vip(state: &Arc<NodeState>, dst: Ipv4Addr) -> Option<String> {
    let dir = state.dir.read().await;
    dir.keys().find(|id| vip_of(id) == dst).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vip_deterministic_and_in_range() {
        let a = vip_of("0123456789abcdef");
        let b = vip_of("0123456789abcdef");
        assert_eq!(a, b);
        assert_eq!(a.octets()[0], 100);
        assert!((64..128).contains(&a.octets()[1]));
        assert_ne!(vip_of("0123456789abcdef"), vip_of("fedcba9876543210"));
    }

    #[test]
    fn parse_dst() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[16..20].copy_from_slice(&[100, 70, 1, 2]);
        assert_eq!(dst_v4(&pkt), Some(Ipv4Addr::new(100, 70, 1, 2)));
        assert_eq!(dst_v4(&pkt[..10]), None);
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert_eq!(dst_v4(&v6), None);
    }
}
