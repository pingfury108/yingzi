//! tcp_stack: TCP 用户态终结（smoltcp）+ 按规则分流
//!
//! ⚠️ 状态: 实验性（P4b 未完成）
//! 已验证: any_ip + 本地 IP/默认路由配置后，smoltcp 能接受任意目的地址的 SYN
//!         并建立连接；上游连接地址取自 local_endpoint（透明代理语义正确）
//! 未解决: SYN 重传会重复创建监听 socket → 连接风暴 + FD 耗尽
//!         （需要按 4 元组复用 socket，或 accept 后立即补建监听并依赖 smoltcp 的 4 元组匹配）
//!         因此暂不接入生产（yz-node / Android）。
//!
//! 数据流：
//!   TUN 包 → smoltcp 终结 TCP 连接 → 决策（Direct/Exit/Block）
//!        ├─ Direct → 真实 TCP（经 SocketProtect 绕过 VPN）
//!        └─ Exit   → 出口节点的 TCP 隧道流
//!
//! 实现要点：
//! - 任意目的端口：按 SYN 动态创建监听 socket（smoltcp 需要 per-port listen）
//! - 单任务持有 Interface/SocketSet/Device（smoltcp 非 Send），
//!   每条连接通过 channel 与上游任务通信
//! - 5ms 轮询驱动（重传/ACK 依赖 poll）

use crate::dns::SocketProtect;
use crate::mesh::PacketIo;
use crate::policy::{Action, RuleSet};
use anyhow::Result;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::HardwareAddress;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// 上游流（直连 TCP 或出口隧道流）
pub trait UpstreamIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> UpstreamIo for T {}

/// 出口 TCP 通道
pub trait ExitTcp: Send + Sync {
    fn open<'a>(
        &'a self,
        node: &'a str,
        dst: SocketAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Box<dyn UpstreamIo>>> + Send + 'a>,
    >;
}

// ---------- smoltcp 设备（队列） ----------

type TxQueue = Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>;

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: TxQueue,
    mtu: usize,
}

impl QueueDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            mtu,
        }
    }
}

struct RxTok(Vec<u8>);
struct TxTok(TxQueue);

impl RxToken for RxTok {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

impl TxToken for TxTok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        if let Ok(mut q) = self.0.lock() {
            q.push_back(buf);
        }
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((RxTok(pkt), TxTok(self.tx.clone())))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

// ---------- 连接 ----------

struct Conn {
    handle: SocketHandle,
    dst: SocketAddr,
    to_up: mpsc::Sender<Vec<u8>>,
    from_up: mpsc::UnboundedReceiver<Vec<u8>>,
    /// 待写入客户端的缓冲
    pending: VecDeque<Vec<u8>>,
    closed: bool,
}

pub struct TcpStackConfig {
    pub mtu: usize,
    /// 本机在 TUN 上的地址（any_ip 模式需要它作为默认路由网关）
    pub local_ip: Ipv4Addr,
    pub protect: Option<Arc<dyn SocketProtect>>,
    pub exit: Option<Arc<dyn ExitTcp>>,
    pub idle_timeout: Duration,
}

pub struct TcpStack {
    rules: Arc<RuleSet>,
    cfg: TcpStackConfig,
    pub stat_conn_direct: AtomicU64,
    pub stat_conn_exit: AtomicU64,
    pub stat_conn_blocked: AtomicU64,
}

impl TcpStack {
    pub fn new(rules: Arc<RuleSet>, cfg: TcpStackConfig) -> Self {
        Self {
            rules,
            cfg,
            stat_conn_direct: AtomicU64::new(0),
            stat_conn_exit: AtomicU64::new(0),
            stat_conn_blocked: AtomicU64::new(0),
        }
    }

    /// 主循环：从 channel 收 TCP 包 → smoltcp → 上游；写回走 io
    pub async fn run(
        self: Arc<Self>,
        io: Arc<dyn PacketIo>,
        mut pkt_rx: mpsc::Receiver<Vec<u8>>,
        default_exit: Option<String>,
    ) -> Result<()> {
        let mut dev = QueueDevice::new(self.cfg.mtu);
        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut dev,
            SmolInstant::now(),
        );
        // 透明代理关键: 接受发往任意目的 IP 的包。
        // any_ip 要求：接口有 IP + 有默认路由（网关=本机 IP），否则仍会丢弃
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(self.cfg.local_ip.octets()[0], self.cfg.local_ip.octets()[1], self.cfg.local_ip.octets()[2], self.cfg.local_ip.octets()[3])),
                24,
            ));
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(self.cfg.local_ip.octets()[0], self.cfg.local_ip.octets()[1], self.cfg.local_ip.octets()[2], self.cfg.local_ip.octets()[3]))
            .ok();
        let mut sockets = SocketSet::new(vec![]);
        let mut conns: HashMap<u32, Conn> = HashMap::new();
        let mut listeners: HashMap<u16, SocketHandle> = HashMap::new();
        // 已处理过的 SYN 4 元组（防重传风暴）
        let mut seen_syn: HashMap<FourTuple, std::time::Instant> = HashMap::new();
        let mut next_id: u32 = 1;
        let mut ticker = tokio::time::interval(Duration::from_millis(5));

        loop {
            tokio::select! {
                pkt = pkt_rx.recv() => {
                    let Some(pkt) = pkt else { return Ok(()) };
                    // TCP SYN 到新端口 → 建监听 socket（必须在 poll 之前）
                    if let Some((tuple, is_syn)) = parse_tcp_meta(&pkt) {
                        let dst_port = tuple.dst_port;
                        if is_syn {
                            seen_syn.retain(|_, t| t.elapsed() < Duration::from_secs(30));
                        }
                        if is_syn
                            && !seen_syn.contains_key(&tuple)
                            && !listeners.contains_key(&dst_port)
                        {
                            seen_syn.insert(tuple, std::time::Instant::now());
                            let rx = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
                            let tx = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
                            let mut sock = tcp::Socket::new(rx, tx);
                            sock.listen(dst_port).ok();
                            let h = sockets.add(sock);
                            listeners.insert(dst_port, h);
                            log::debug!("新监听 socket: 端口 {dst_port} (dst {})", tuple.dst_ip);
                        }
                    }
                    dev.rx.push_back(pkt);
                }
                _ = ticker.tick() => {}
            }

            let polled = iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
            {
                // 诊断: 每秒打印一次监听 socket 状态
                static mut LAST: u64 = 0;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                unsafe {
                    if now_ms - LAST > 1000 {
                        LAST = now_ms;
                        for (&port, &h) in listeners.iter() {
                            let sk = sockets.get::<tcp::Socket>(h);
                            log::debug!(
                                "socket 端口 {port}: state={:?} active={} listen={} txq={}",
                                sk.state(),
                                sk.is_active(),
                                sk.is_listening(),
                                dev.tx.lock().map(|q| q.len()).unwrap_or(0)
                            );
                        }
                    }
                }
            }
            log::trace!("poll={polled}");

            // 1) 已建立但还没接上游的 socket → 建立连接
            let mut new_conns: Vec<(u32, Conn)> = Vec::new();
            let accepted: Vec<(u16, SocketHandle)> = listeners
                .iter()
                .filter_map(|(&p, &h)| {
                    let s = sockets.get::<tcp::Socket>(h);
                    (s.is_active() && !s.is_listening()).then_some((p, h))
                })
                .collect();
            let mut drop_listeners: Vec<u16> = Vec::new();
            for (port, h) in accepted {
                let sock = sockets.get_mut::<tcp::Socket>(h);
                if sock.is_active() && !sock.is_listening() {
                    // 已被 accept。透明代理下 socket 的 local_endpoint 才是"原始目标地址"
                    let Some(local_ep) = sock.local_endpoint() else { continue };
                    let dst_ip = match local_ep.addr {
                        smoltcp::wire::IpAddress::Ipv4(v4) => Ipv4Addr::from(v4.0),
                        #[allow(unreachable_patterns)]
                        _ => continue,
                    };
                    let dst = SocketAddr::new(IpAddr::V4(dst_ip), local_ep.port);
                    let id = next_id;
                    next_id += 1;

                    let decision = self.rules.decide_ip(dst_ip);
                    let (to_up_tx, to_up_rx) = mpsc::channel::<Vec<u8>>(64);
                    let (from_up_tx, from_up_rx) = mpsc::unbounded_channel::<Vec<u8>>();

                    match decision.action {
                        Action::Block => {
                            self.stat_conn_blocked.fetch_add(1, Ordering::Relaxed);
                            sock.abort();
                            drop_listeners.push(port);
                            continue;
                        }
                        Action::Direct => {
                            self.stat_conn_direct.fetch_add(1, Ordering::Relaxed);
                            let protect = self.cfg.protect.clone();
                            tokio::spawn(async move {
                                if let Err(e) = pump_direct(to_up_rx, from_up_tx, dst, protect).await {
                                    log::debug!("TCP 直连 {dst} 结束: {e:#}");
                                }
                            });
                        }
                        Action::Exit(node) => {
                            self.stat_conn_exit.fetch_add(1, Ordering::Relaxed);
                            let node = node.or(default_exit.clone());
                            match (node, self.cfg.exit.clone()) {
                                (Some(node), Some(exit)) => {
                                    match exit.open(&node, dst).await {
                                        Ok(up) => {
                                            tokio::spawn(async move {
                                                if let Err(e) = pump_upstream(to_up_rx, from_up_tx, up).await {
                                                    log::debug!("TCP 出口 {dst} 结束: {e:#}");
                                                }
                                            });
                                        }
                                        Err(e) => {
                                            log::warn!("出口 {node} 打开失败: {e:#}");
                                            sock.abort();
                                            drop_listeners.push(port);
                                            continue;
                                        }
                                    }
                                }
                                _ => {
                                    log::warn!("未配置出口通道, 回退直连 {dst}");
                                    let protect = self.cfg.protect.clone();
                                    tokio::spawn(async move {
                                        let _ = pump_direct(to_up_rx, from_up_tx, dst, protect).await;
                                    });
                                }
                            }
                        }
                    }

                    new_conns.push((
                        id,
                        Conn {
                            handle: h,
                            dst,
                            to_up: to_up_tx,
                            from_up: from_up_rx,
                            pending: VecDeque::new(),
                            closed: false,
                        },
                    ));
                    drop_listeners.push(port);
                }
            }
            for p in drop_listeners {
                listeners.remove(&p);
            }
            for (id, c) in new_conns {
                log::debug!("TCP 连接 {id} -> {} ({:?})", c.dst, "ok");
                conns.insert(id, c);
            }

            // 2) 双向泵数据
            let mut dead = Vec::new();
            for (&id, c) in conns.iter_mut() {
                let sock = sockets.get_mut::<tcp::Socket>(c.handle);
                // 客户端 → 上游
                while sock.can_recv() {
                    let mut chunk = Vec::new();
                    match sock.recv(|b| {
                        let n = b.len().min(16 * 1024);
                        chunk.extend_from_slice(&b[..n]);
                        (n, ())
                    }) {
                        Ok(()) => {}
                        Err(_) => break,
                    }
                    if chunk.is_empty() {
                        break;
                    }
                    if c.to_up.try_send(chunk).is_err() {
                        break;
                    }
                }
                // 上游 → 客户端
                while let Ok(data) = c.from_up.try_recv() {
                    c.pending.push_back(data);
                }
                while let Some(front) = c.pending.front() {
                    if !sock.can_send() {
                        break;
                    }
                    match sock.send_slice(front) {
                        Ok(n) if n == front.len() => {
                            c.pending.pop_front();
                        }
                        Ok(n) => {
                            let rest = front[n..].to_vec();
                            c.pending.pop_front();
                            c.pending.push_front(rest);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                if !sock.is_open() && c.pending.is_empty() {
                    c.closed = true;
                    dead.push(id);
                }
            }
            for id in dead {
                if let Some(c) = conns.remove(&id) {
                    log::debug!("TCP 连接 {id} 关闭 ({})", c.dst);
                    sockets.remove(c.handle);
                }
            }

            // 3) 写回 TUN
            let mut out: Vec<Vec<u8>> = Vec::new();
            if let Ok(mut q) = dev.tx.lock() {
                while let Some(p) = q.pop_front() {
                    out.push(p);
                }
            }
            for pkt in out {
                if io.send(&pkt).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// TCP 4 元组（用于 SYN 去重，避免重传导致连接风暴）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

/// 解析 TCP 元信息：(4 元组, 是否 SYN)
fn parse_tcp_meta(pkt: &[u8]) -> Option<(FourTuple, bool)> {
    if pkt.len() < 40 || pkt[0] >> 4 != 4 || pkt[9] != 6 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl + 20 {
        return None;
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let flags = pkt[ihl + 13];
    Some((
        FourTuple {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        },
        flags & 0x02 != 0,
    ))
}

async fn pump_direct(
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    dst: SocketAddr,
    protect: Option<Arc<dyn SocketProtect>>,
) -> Result<()> {
    let std_sock = std::net::TcpStream::connect(dst)?;
    std_sock.set_nonblocking(true)?;
    if let Some(p) = &protect {
        p.protect_tcp(&std_sock);
    }
    let stream = TcpStream::from_std(std_sock)?;
    let (mut r, mut w) = stream.into_split();
    let up = tokio::spawn(async move {
        let mut b = vec![0u8; 16 * 1024];
        loop {
            match r.read(&mut b).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(b[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    while let Some(d) = rx.recv().await {
        if w.write_all(&d).await.is_err() {
            break;
        }
    }
    up.abort();
    Ok(())
}

async fn pump_upstream(
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    up: Box<dyn UpstreamIo>,
) -> Result<()> {
    let (mut r, mut w) = tokio::io::split(up);
    let reader = tokio::spawn(async move {
        let mut b = vec![0u8; 16 * 1024];
        loop {
            match r.read(&mut b).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(b[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    while let Some(d) = rx.recv().await {
        if w.write_all(&d).await.is_err() {
            break;
        }
    }
    reader.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_syn() {
        // 构造最小 TCP SYN 包
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[9] = 6; // TCP
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes()); // dst port
        pkt[33] = 0x02; // SYN
        let (ip, port, syn) = parse_tcp_meta(&pkt).unwrap();
        assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(port, 443);
        assert!(syn);
    }

    #[test]
    fn parse_ignores_udp() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 17;
        assert!(parse_tcp_meta(&pkt).is_none());
    }
}
