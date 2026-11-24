//! yz-core: 组网引擎（可被桌面二进制与 Android 客户端复用）
//!
//! 只放**与 IO 框架无关**的共享逻辑：隧道、规则、承载、状态、地址工具。
//! 不含：CLI、Web 控制台、SOCKS5 入口、ingress 发布、TUN 设备路径。

pub mod dns;
pub mod exit_dns;
pub mod exit_udp;
pub mod fakeip;
pub mod geo;
pub mod ingress;
pub mod mesh;
pub mod path;
pub mod peer;
pub mod policy;
pub mod stack;
pub mod tcp_stack;
pub mod state;
pub mod tunnel;
pub mod util;
pub mod wss;

use std::sync::Arc;

/// 取到出口节点的隧道：优先自动选路（直连 / 经中转），
/// 未设置 self_id（如某些嵌入式调用）时退回普通的 tunnel_for。
pub async fn exit_tunnel_for(
    state: &Arc<state::CoreState>,
    ns: &yz_crypto::NetworkSecret,
    id_pub: &[u8; 32],
    node_id: &str,
) -> anyhow::Result<Arc<tunnel::Tunnel>> {
    let sid = state.self_id();
    log::debug!("exit_tunnel_for {node_id}: self={sid}");
    if sid.is_empty() {
        return peer::tunnel_for(state, ns, id_pub, node_id).await;
    }
    let r = path::exit_tunnel(state, ns, id_pub, sid, node_id, None).await;
    match &r {
        Ok(_) => log::debug!("exit_tunnel_for {node_id}: ok"),
        Err(e) => log::warn!("exit_tunnel_for {node_id}: {e:#}"),
    }
    r
}
