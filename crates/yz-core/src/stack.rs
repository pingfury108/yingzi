//! stack: 用户态网络栈（路径 B）
//!
//! 从 TUN 读 IP 包 → 按 5 元组分流 → 直连（本机 socket）/ 出口（mesh 隧道）/ 拦截
//!
//! 当前实现：
//! - IPv4 + UDP 完整中继（含 DNS 拦截）
//! - TCP 由 smoltcp 终结（见 tcp 模块，随后接入）
//!
//! 设计要点：
//! - UDP 无连接语义，直接按 (src, dst) 建流表，避免不必要的状态机
//! - 所有"直连" socket 都经过 `SocketProtect`，Android 上防止被自己的 VPN 捕获

use crate::dns::DnsService;
use crate::mesh::PacketIo;
use crate::policy::{Action, RuleSet};
use crate::state::CoreState;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

// ---------- IPv4 / UDP 编解码 ----------

pub struct UdpPacket<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// 解析 IPv4 + UDP；非 UDP 返回 None
pub fn parse_udp(pkt: &[u8]) -> Option<UdpPacket<'_>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    if pkt[9] != 17 {
        return None; // protocol = UDP
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let end = total_len.min(pkt.len());
    if end < ihl + 8 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let udp_len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;
    let payload_start = ihl + 8;
    let payload_end = (ihl + udp_len).min(end);
    if payload_end < payload_start {
        return None;
    }
    Some(UdpPacket {
        src,
        dst,
        src_port,
        dst_port,
        payload: &pkt[payload_start..payload_end],
    })
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 构造 IPv4 + UDP 包（用于把应答写回 TUN）
pub fn build_udp(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut out = vec![0u8; total];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags/frag
    out[8] = 64; // ttl
    out[9] = 17; // udp
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let ip_ck = checksum(&out[..20]);
    out[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    out[20..22].copy_from_slice(&src_port.to_be_bytes());
    out[22..24].copy_from_slice(&dst_port.to_be_bytes());
    out[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[28..].copy_from_slice(payload);

    // UDP 校验和（含伪首部）
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&out[20..]);
    let udp_ck = checksum(&pseudo);
    let udp_ck = if udp_ck == 0 { 0xffff } else { udp_ck };
    out[26..28].copy_from_slice(&udp_ck.to_be_bytes());
    out
}

/// 构造 ICMP 端口不可达（可选，用于 Block）
pub fn build_icmp_unreachable(orig: &[u8]) -> Option<Vec<u8>> {
    let p = parse_udp(orig)?;
    // ICMP: type=3 code=3 + 4 字节保留 + 原始 IP 头 + 前 8 字节
    let quote_len = (20 + 8).min(orig.len());
    let total = 20 + 8 + quote_len;
    let mut out = vec![0u8; total];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[8] = 64;
    out[9] = 1; // ICMP
    out[12..16].copy_from_slice(&p.dst.octets());
    out[16..20].copy_from_slice(&p.src.octets());
    let ip_ck = checksum(&out[..20]);
    out[10..12].copy_from_slice(&ip_ck.to_be_bytes());
    out[20] = 3; // destination unreachable
    out[21] = 3; // port unreachable
    out[28..28 + quote_len].copy_from_slice(&orig[..quote_len]);
    let ck = checksum(&out[20..]);
    out[22..24].copy_from_slice(&ck.to_be_bytes());
    Some(out)
}

// ---------- 出口流（UDP） ----------

/// 出口节点上的 UDP 中继通道
pub trait ExitUdp: Send + Sync {
    fn open<'a>(
        &'a self,
        node: &'a str,
        dst: SocketAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Box<dyn UdpRelay>>> + Send + 'a>,
    >;
}

pub trait UdpRelay: Send + Sync {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn recv<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>,
    >;
}

// ---------- 流表 ----------

struct UdpFlow {
    tx: mpsc::Sender<Vec<u8>>,
}

pub struct StackConfig {
    pub mtu: usize,
    /// DNS 服务（拦截 UDP:53）
    pub dns: Option<Arc<DnsService>>,
    /// 直连 socket 保护（Android）
    pub protect: Option<Arc<dyn crate::dns::SocketProtect>>,
    /// 出口 UDP 通道
    pub exit: Option<Arc<dyn ExitUdp>>,
    /// 空闲流回收时间
    pub idle_timeout: Duration,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            mtu: 1400,
            dns: None,
            protect: None,
            exit: None,
            idle_timeout: Duration::from_secs(60),
        }
    }
}

pub struct Stack {
    rules: Arc<RuleSet>,
    state: Arc<CoreState>,
    cfg: StackConfig,
    flows: Mutex<HashMap<(u16, Ipv4Addr, u16), UdpFlow>>,
    /// 统计
    pub stat_udp_direct: AtomicU64,
    pub stat_udp_exit: AtomicU64,
    pub stat_udp_dns: AtomicU64,
    pub stat_blocked: AtomicU64,
}

impl Stack {
    pub fn new(rules: Arc<RuleSet>, state: Arc<CoreState>, cfg: StackConfig) -> Self {
        Self {
            rules,
            state,
            cfg,
            flows: Mutex::new(HashMap::new()),
            stat_udp_direct: AtomicU64::new(0),
            stat_udp_exit: AtomicU64::new(0),
            stat_udp_dns: AtomicU64::new(0),
            stat_blocked: AtomicU64::new(0),
        }
    }

    /// 处理一个来自 TUN 的 IP 包（UDP 部分）
    pub async fn handle_packet(&self, io: &Arc<dyn PacketIo>, pkt: &[u8]) -> Result<()> {
        let Some(u) = parse_udp(pkt) else {
            return Ok(()); // TCP/ICMP 由 smoltcp 处理
        };

        // 1) DNS 拦截
        if u.dst_port == 53 {
            if let Some(dns) = &self.cfg.dns {
                self.stat_udp_dns.fetch_add(1, Ordering::Relaxed);
                match dns.handle_query(u.payload).await {
                    Ok(resp) => {
                        let out = build_udp(u.dst, u.dst_port, u.src, u.src_port, &resp);
                        io.send(&out).await?;
                    }
                    Err(e) => log::debug!("DNS 处理失败: {e:#}"),
                }
                return Ok(());
            }
        }

        // 2) 规则决策（按目的 IP）
        let dst = SocketAddr::new(IpAddr::V4(u.dst), u.dst_port);
        let decision = self.rules.decide_ip(u.dst);
        match decision.action {
            Action::Block => {
                self.stat_blocked.fetch_add(1, Ordering::Relaxed);
                if let Some(icmp) = build_icmp_unreachable(pkt) {
                    io.send(&icmp).await?;
                }
                return Ok(());
            }
            Action::Direct => {
                self.stat_udp_direct.fetch_add(1, Ordering::Relaxed);
                self.forward_direct(io, &u, dst).await
            }
            Action::Exit(node) => {
                self.stat_udp_exit.fetch_add(1, Ordering::Relaxed);
                let node = node.unwrap_or_else(|| {
                    // 未指定节点时用目录里第一个可出口节点
                    String::new()
                });
                self.forward_exit(io, &u, dst, &node).await
            }
        }
    }

    async fn forward_direct(
        &self,
        io: &Arc<dyn PacketIo>,
        u: &UdpPacket<'_>,
        dst: SocketAddr,
    ) -> Result<()> {
        let key = (u.src_port, u.dst, u.dst_port);
        let tx = {
            let mut flows = self.flows.lock().await;
            if let Some(f) = flows.get(&key) {
                f.tx.clone()
            } else {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                flows.insert(key, UdpFlow { tx: tx.clone() });
                let io2 = io.clone();
                let src = u.src;
                let src_port = u.src_port;
                let protect = self.cfg.protect.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        udp_direct_task(rx, dst, src, src_port, io2, protect).await
                    {
                        log::debug!("UDP 直连 {dst} 结束: {e:#}");
                    }
                });
                tx
            }
        };
        let _ = tx.send(u.payload.to_vec()).await;
        Ok(())
    }

    async fn forward_exit(
        &self,
        io: &Arc<dyn PacketIo>,
        u: &UdpPacket<'_>,
        dst: SocketAddr,
        node: &str,
    ) -> Result<()> {
        let Some(exit) = &self.cfg.exit else {
            log::debug!("未配置出口通道, 回退直连 {dst}");
            return self.forward_direct(io, u, dst).await;
        };
        let node = if node.is_empty() {
            // 从目录挑一个可出口节点
            let dir = self.state.dir.read().await;
            dir.values()
                .find(|n| n.caps & yz_proto::caps::EXIT != 0)
                .map(|n| n.node_id.clone())
                .context("目录中没有可出口节点")?
        } else {
            node.to_string()
        };

        let key = (u.src_port, u.dst, u.dst_port);
        let tx = {
            let mut flows = self.flows.lock().await;
            if let Some(f) = flows.get(&key) {
                f.tx.clone()
            } else {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                flows.insert(key, UdpFlow { tx: tx.clone() });
                let io2 = io.clone();
                let src = u.src;
                let src_port = u.src_port;
                let relay = exit.open(&node, dst).await?;
                tokio::spawn(async move {
                    if let Err(e) =
                        udp_exit_task(rx, relay, src, src_port, dst, io2).await
                    {
                        log::debug!("UDP 出口 {dst} 结束: {e:#}");
                    }
                });
                tx
            }
        };
        let _ = tx.send(u.payload.to_vec()).await;
        Ok(())
    }
}

async fn udp_direct_task(
    mut rx: mpsc::Receiver<Vec<u8>>,
    dst: SocketAddr,
    src: Ipv4Addr,
    src_port: u16,
    io: Arc<dyn PacketIo>,
    protect: Option<Arc<dyn crate::dns::SocketProtect>>,
) -> Result<()> {
    let bind: SocketAddr = if dst.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let std_sock = std::net::UdpSocket::bind(bind)?;
    std_sock.set_nonblocking(true)?;
    if let Some(p) = &protect {
        p.protect(&std_sock);
    }
    let sock = Arc::new(UdpSocket::from_std(std_sock)?);
    sock.connect(dst).await?;

    let s2 = sock.clone();
    let downstream = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match s2.recv(&mut buf).await {
                Ok(n) => {
                    let IpAddr::V4(dst_v4) = dst.ip() else { break };
                    let out = build_udp(dst_v4, dst.port(), src, src_port, &buf[..n]);
                    if io.send(&out).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    while let Some(data) = rx.recv().await {
        if sock.send(&data).await.is_err() {
            break;
        }
    }
    downstream.abort();
    Ok(())
}

async fn udp_exit_task(
    mut rx: mpsc::Receiver<Vec<u8>>,
    relay: Box<dyn UdpRelay>,
    src: Ipv4Addr,
    src_port: u16,
    dst: SocketAddr,
    io: Arc<dyn PacketIo>,
) -> Result<()> {
    let relay = Arc::new(relay);
    let r2 = relay.clone();
    let downstream = tokio::spawn(async move {
        loop {
            match r2.recv().await {
                Ok(data) => {
                    let IpAddr::V4(dst_v4) = dst.ip() else { break };
                    let out = build_udp(dst_v4, dst.port(), src, src_port, &data);
                    if io.send(&out).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    while let Some(data) = rx.recv().await {
        if relay.send(&data).await.is_err() {
            break;
        }
    }
    downstream.abort();
    Ok(())
}

// ---------- 测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_roundtrip() {
        let pkt = build_udp(
            "1.2.3.4".parse().unwrap(),
            53,
            "10.0.0.5".parse().unwrap(),
            40000,
            b"hello",
        );
        let p = parse_udp(&pkt).unwrap();
        assert_eq!(p.src, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(p.dst, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(p.src_port, 53);
        assert_eq!(p.dst_port, 40000);
        assert_eq!(p.payload, b"hello");
        // IP 头校验和应为 0
        assert_eq!(checksum(&pkt[..20]), 0);
        // UDP 校验和（含伪首部）应为 0
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&pkt[12..20]);
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&pkt[24..26]);
        pseudo.extend_from_slice(&pkt[20..]);
        assert_eq!(checksum(&pseudo), 0);
    }

    #[test]
    fn parse_rejects_non_udp() {
        let mut pkt = build_udp(
            "1.1.1.1".parse().unwrap(),
            1234,
            "2.2.2.2".parse().unwrap(),
            80,
            b"x",
        );
        pkt[9] = 6; // TCP
        assert!(parse_udp(&pkt).is_none());
        assert!(parse_udp(&[]).is_none());
        assert!(parse_udp(&[0x45; 10]).is_none());
    }

    #[test]
    fn icmp_unreachable_built() {
        let pkt = build_udp(
            "1.1.1.1".parse().unwrap(),
            5555,
            "9.9.9.9".parse().unwrap(),
            53,
            b"q",
        );
        let icmp = build_icmp_unreachable(&pkt).unwrap();
        assert_eq!(icmp[9], 1); // ICMP
        assert_eq!(icmp[20], 3); // unreachable
        assert_eq!(checksum(&icmp[..20]), 0);
        assert_eq!(checksum(&icmp[20..]), 0);
    }
}
