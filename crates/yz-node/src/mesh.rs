//! mesh: TUN 虚拟组网 (P6)。
//! vIP = 100.64.0.0/10 | node_id 低 22 位 (确定性分配, 无需协调)。
//! TUN 读 IP 包 → 目的 vIP 反查 node_id → tunnel_for (自动 P2P) → Mesh 帧。

use crate::node::NodeState;
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;
use yz_crypto::NetworkSecret;

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

/// 桌面 TUN 设备的 PacketIo 实现
struct TunIo {
    dev: Arc<tun::AsyncDevice>,
}

impl yz_core::mesh::PacketIo for TunIo {
    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let n = self.dev.recv(buf).await?;
            Ok(n)
        })
    }

    fn send<'a>(
        &'a self,
        pkt: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.dev.send(pkt).await?;
            Ok(())
        })
    }
}

pub async fn run(
    ifname: &str,
    state: Arc<NodeState>,
    ns: NetworkSecret,
    id_pub: [u8; 32],
    self_id: String,
) -> Result<()> {
    let vip = yz_core::mesh::vip_of(&self_id);
    let mut cfg = tun::Configuration::default();
    cfg.tun_name(ifname)
        .mtu(1400)
        .address(vip)
        .netmask(Ipv4Addr::new(255, 252, 0, 0)) // /14
        .up();
    let dev = tun::create_as_async(&cfg).context(if cfg!(target_os = "macos") {
        "create tun (macOS 需 root: sudo 运行, 且网卡名需形如 utun<N>)"
    } else {
        "create tun (需要 root 或 CAP_NET_ADMIN, 可 sudo setcap cap_net_admin,cap_net_raw+ep <yz>)"
    })?;
    let dev = Arc::new(dev);
    log::info!("tun {ifname} up, virtual ip {vip}/14");

    let io = Arc::new(TunIo { dev });
    yz_core::mesh::run_router(
        io,
        state,
        ns,
        id_pub,
        yz_core::mesh::MeshRouterConfig {
            vip,
            af_header: cfg!(target_os = "macos"),
        },
    )
    .await
}
