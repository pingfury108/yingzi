//! mesh: 虚拟 IP 分配与 MESH 帧路由（桌面端与 Android 共用）
//!
//! 平台相关的 TUN 设备读写在调用方实现（桌面: tun crate；Android: VpnService fd）。

use crate::peer::tunnel_for;
use crate::state::CoreState;
use anyhow::Result;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use yz_crypto::NetworkSecret;
use yz_proto::Frame;

/// 虚拟网卡抽象: 桌面用 tun 设备路径, Android 用 VpnService 的 fd
pub trait PacketIo: Send + Sync {
    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>>;
    fn send<'a>(
        &'a self,
        pkt: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

/// mesh 路由配置
pub struct MeshRouterConfig {
    pub vip: Ipv4Addr,
    /// macOS utun 有 4 字节 AF 头; Linux/Android 没有
    pub af_header: bool,
}

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

/// 从 TUN 原始缓冲取 IP 包偏移 (macOS 需跳过 4 字节 AF 头)
fn ip_offset(buf: &[u8], af_header: bool) -> Option<usize> {
    if !af_header {
        return Some(0);
    }
    if buf.len() >= 24 && buf[..4] == [0, 0, 0, 2] {
        Some(4)
    } else {
        None
    }
}

fn dst_v4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

fn wrap_tun(pkt: &[u8], af_header: bool) -> Vec<u8> {
    if !af_header {
        return pkt.to_vec();
    }
    let mut out = Vec::with_capacity(4 + pkt.len());
    out.extend_from_slice(&[0, 0, 0, 2]);
    out.extend_from_slice(pkt);
    out
}

/// mesh 路由主循环: TUN 收包 → 查目的 vIP → 经隧道发给对应节点
///
/// 平台无关: 具体虚拟网卡由调用方以 `PacketIo` 提供。
pub async fn run_router<T: PacketIo + 'static>(
    io: Arc<T>,
    state: Arc<CoreState>,
    ns: NetworkSecret,
    id_pub: [u8; 32],
    cfg: MeshRouterConfig,
) -> Result<()> {
    let vip = cfg.vip;
    let af_header = cfg.af_header;

    // 隧道来的 mesh 帧 → 本地 TUN
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
    *state.mesh_sink.write().await = Some(tx);
    {
        let io = io.clone();
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let pkt = wrap_tun(&pkt, af_header);
                if let Err(e) = io.send(&pkt).await {
                    log::debug!("tun write: {e}");
                }
            }
        });
    }

    let mut buf = vec![0u8; 2048];
    loop {
        let n = io.recv(&mut buf).await?;
        let Some(off) = ip_offset(&buf[..n], af_header) else {
            continue;
        };
        let pkt = &buf[off..n];
        let Some(dst) = dst_v4(pkt) else { continue };
        if dst == vip {
            continue;
        }
        let Some(nid) = route_target(&state, dst).await else {
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
