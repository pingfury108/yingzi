//! mesh: 虚拟 IP 分配与 MESH 帧路由（桌面端与 Android 共用）
//!
//! 平台相关的 TUN 设备读写在调用方实现（桌面: tun crate；Android: VpnService fd）。

use crate::state::CoreState;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// 默认 TUN 网卡名: macOS 必须是 utun<N>
#[cfg(target_os = "macos")]
pub const DEFAULT_TUN_NAME: &str = "utun5";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_TUN_NAME: &str = "yz0";

/// 虚拟网段: 100.64.0.0/14 (避开阿里云/华为云 100.100.x 元数据段)
const VIP_NET: u32 = 0x6440_0000; // 100.64.0.0
const VIP_BITS: u32 = 18; // /14 → 18 位主机位
const VIP_MASK_BITS: u32 = (1 << VIP_BITS) - 1;

/// node_id(16 hex) → 100.64.0.0/14 内的确定性虚拟 IP
pub fn vip_of(node_id: &str) -> Ipv4Addr {
    let b = yz_crypto::from_hex(node_id).unwrap_or_else(|_| vec![0u8; 8]);
    let mut raw = [0u8; 8];
    let n = b.len().min(8);
    raw[8 - n..].copy_from_slice(&b[b.len() - n..]);
    let low = (u64::from_be_bytes(raw) & VIP_MASK_BITS as u64) as u32;
    Ipv4Addr::from(VIP_NET | low)
}

/// 隧道 mesh 帧 → 本地 TUN (每条隧道一个转发任务)
pub fn spawn_forward(mut rx: mpsc::Receiver<Vec<u8>>, state: Arc<CoreState>) {
    tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            let sink = state.mesh_sink.read().await.clone();
            if let Some(sink) = sink {
                let _ = sink.send(pkt).await;
            }
        }
    });
}

/// 目的 vIP → 节点
pub async fn route_target(state: &Arc<CoreState>, dst: Ipv4Addr) -> Option<String> {
    let dir = state.dir.read().await;
    dir.keys().find(|id| vip_of(id) == dst).cloned()
}
