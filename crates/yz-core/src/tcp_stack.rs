//! tcp_stack: TCP 用户态终结（基于 netstack-smoltcp，MIT）
//!
//! ⚠️ 状态: 实验性（P4b 未完成）
//! 已验证: netstack-smoltcp 能接受任意目的地址的 TCP 连接（握手成功），
//!         目标地址/客户端地址语义正确，决策与上游直连均能触发
//! 未解决: 数据面（握手后客户端数据未贯通），客户端会反复重连
//!         因此暂不接入 yz-node / Android
//!
//! 设计（方案 B）：成熟实现负责 smoltcp 的连接生命周期，我们只做
//! "决策 + 上游适配"：
//!   TUN 包 → netstack-smoltcp 终结成 TcpStream
//!          → RuleSet 决策：Direct（本机 socket）/ Exit（出口隧道流）/ Block
//!          → 双向 pipe
//!
//! netstack-smoltcp 由 shadowsocks-rust 维护，解决了透明代理的经典问题：
//! 任意目的 IP（any_ip）、每连接 socket 生命周期、SYN 重传、窗口/ACK 时序。

use crate::dns::SocketProtect;
use crate::mesh::PacketIo;
use crate::policy::{Action, RuleSet};
use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener, TcpStream};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream as RealTcpStream;

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

pub struct TcpStackConfig {
    pub mtu: usize,
    pub protect: Option<Arc<dyn SocketProtect>>,
    pub exit: Option<Arc<dyn ExitTcp>>,
    /// 连接数上限
    pub max_conns: usize,
}

pub struct TcpStack {
    rules: Arc<RuleSet>,
    cfg: TcpStackConfig,
    pub stat_direct: Arc<AtomicU64>,
    pub stat_exit: Arc<AtomicU64>,
    pub stat_blocked: Arc<AtomicU64>,
}

impl TcpStack {
    pub fn new(rules: Arc<RuleSet>, cfg: TcpStackConfig) -> Self {
        Self {
            rules,
            cfg,
            stat_direct: Arc::new(AtomicU64::new(0)),
            stat_exit: Arc::new(AtomicU64::new(0)),
            stat_blocked: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 运行：io 负责收发 TUN 包，pkt_rx 提供 TCP 包（由主循环分发）
    pub async fn run(
        self: Arc<Self>,
        io: Arc<dyn PacketIo>,
        mut pkt_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        default_exit: Option<String>,
    ) -> Result<()> {
        let (stack, runner, _udp, listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(false)
            .enable_icmp(false)
            .mtu(self.cfg.mtu)
            .build()
            .map_err(|e| anyhow::anyhow!("netstack build: {e}"))?;
        let mut listener: TcpListener = listener.context("netstack 未启用 TCP")?;
        if let Some(runner) = runner {
            tokio::spawn(runner);
        }

        let (mut stack_sink, mut stack_stream) = stack.split();

        // 出：栈 → TUN
        {
            let io = io.clone();
            tokio::spawn(async move {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if io.send(&pkt).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::debug!("stack stream: {e}");
                            break;
                        }
                    }
                }
            });
        }

        // 入：TUN（由 pkt_rx 提供）→ 栈
        tokio::spawn(async move {
            while let Some(pkt) = pkt_rx.recv().await {
                if stack_sink.send(pkt).await.is_err() {
                    break;
                }
            }
        });

        // 连接分发
        let active = Arc::new(AtomicU64::new(0));
        // netstack 的 Stream item: (stream, 客户端地址, 目标地址)
        while let Some((stream, client_addr, dst_addr)) = listener.next().await {
            let rules = self.rules.clone();
            let cfg = self.cfg.clone_shallow();
            let default_exit = default_exit.clone();
            let active2 = active.clone();
            let stat_direct = self.stat_direct.clone();
            let stat_exit = self.stat_exit.clone();
            let stat_blocked = self.stat_blocked.clone();
            tokio::spawn(async move {
                let n = active2.fetch_add(1, Ordering::Relaxed) + 1;
                if n as usize > cfg.max_conns {
                    active2.fetch_sub(1, Ordering::Relaxed);
                    log::warn!("TCP 连接数达上限 ({}), 拒绝 {dst_addr}", cfg.max_conns);
                    drop(stream);
                    return;
                }
                if let Err(e) = handle_conn(
                    stream,
                    dst_addr,
                    client_addr,
                    rules,
                    cfg,
                    default_exit,
                    stat_direct,
                    stat_exit,
                    stat_blocked,
                )
                .await
                {
                    log::debug!("TCP {dst_addr} <- {client_addr} 结束: {e:#}");
                }
                active2.fetch_sub(1, Ordering::Relaxed);
            });
        }
        Ok(())
    }
}

impl TcpStackConfig {
    fn clone_shallow(&self) -> Self {
        Self {
            mtu: self.mtu,
            protect: self.protect.clone(),
            exit: self.exit.clone(),
            max_conns: self.max_conns,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    client: TcpStream,
    dst: SocketAddr,
    src: SocketAddr,
    rules: Arc<RuleSet>,
    cfg: TcpStackConfig,
    default_exit: Option<String>,
    stat_direct: Arc<AtomicU64>,
    stat_exit: Arc<AtomicU64>,
    stat_blocked: Arc<AtomicU64>,
) -> Result<()> {
    let decision = rules.decide_ip(match dst.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => {
            return Ok(()); // 暂只支持 IPv4
        }
    });

    match decision.action {
        Action::Block => {
            stat_blocked.fetch_add(1, Ordering::Relaxed);
            log::debug!("拦截 TCP {dst} ({})", decision.reason);
            drop(client);
            Ok(())
        }
        Action::Direct => {
            stat_direct.fetch_add(1, Ordering::Relaxed);
            log::debug!("TCP {dst} -> direct ({})", decision.reason);
            let up = connect_direct(dst, cfg.protect.as_ref())?;
            pipe(client, up).await
        }
        Action::Exit(node) => {
            stat_exit.fetch_add(1, Ordering::Relaxed);
            let node = node.or(default_exit);
            match (node, cfg.exit.clone()) {
                (Some(node), Some(exit)) => {
                    log::debug!("TCP {dst} -> exit {node}");
                    let up = exit.open(&node, dst).await?;
                    pipe(client, up).await
                }
                _ => {
                    log::warn!("未配置出口通道, {dst} 回退直连");
                    let up = connect_direct(dst, cfg.protect.as_ref())?;
                    pipe(client, up).await
                }
            }
        }
    }
}

fn connect_direct(
    dst: SocketAddr,
    protect: Option<&Arc<dyn SocketProtect>>,
) -> Result<Box<dyn UpstreamIo>> {
    let std_sock = std::net::TcpStream::connect(dst)?;
    std_sock.set_nonblocking(true)?;
    if let Some(p) = protect {
        p.protect_tcp(&std_sock);
    }
    Ok(Box::new(RealTcpStream::from_std(std_sock)?))
}

async fn pipe<A, B>(mut a: A, mut b: B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let up_bytes = std::sync::Arc::new(AtomicU64::new(0));
    let down_bytes = std::sync::Arc::new(AtomicU64::new(0));
    let (ub, db) = (up_bytes.clone(), down_bytes.clone());
    let (mut ar, mut aw) = tokio::io::split(&mut a);
    let (mut br, mut bw) = tokio::io::split(&mut b);
    let up = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match ar.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    ub.fetch_add(n as u64, Ordering::Relaxed);
                    if bw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = bw.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match br.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    db.fetch_add(n as u64, Ordering::Relaxed);
                    if aw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = aw.shutdown().await;
    };
    tokio::join!(up, down);
    log::debug!(
        "pipe 结束: up={}B down={}B",
        up_bytes.load(Ordering::Relaxed),
        down_bytes.load(Ordering::Relaxed)
    );
    Ok(())
}
