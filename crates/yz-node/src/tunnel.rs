//! 多路复用隧道: 一条加密会话承载多条流 + stream 0 控制消息。
//! 承载: TCP (计数器 nonce + 掩码长度) 或 UDP (yz-rudp 可靠字节流, len(2)|frame)。
//! 流 ID 约定: 隧道发起方用奇数, 响应方用偶数, 双向开流不冲突。

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::timeout;
use yz_crypto::{
    handshake_accept, handshake_finish, handshake_init, unwrap_hs_len, wrap_hs_stream,
    NetworkSecret, PeerInfo, Role, Session, SessionKeys, MSG1_LEN, MSG2_LEN,
};
use yz_proto::{Addr, Frame, MAX_FRAME_LEN};
use yz_rudp::Rudp;

const HS_TIMEOUT: Duration = Duration::from_secs(10);
const IO_BUF: usize = 16 * 1024;
const CHAN_CAP: usize = 64;

pub struct Incoming {
    pub sid: u32,
    pub addr: Addr,
    pub rx: mpsc::Receiver<Frame>,
}

pub struct TunnelHandle {
    pub tunnel: Arc<Tunnel>,
    pub peer: PeerInfo,
    pub ctrl_rx: mpsc::Receiver<Frame>,
    pub accept_rx: mpsc::Receiver<Incoming>,
    /// 组网 IP 包 (由 mesh 模块消费; 未启用 TUN 时丢弃)
    pub mesh_rx: mpsc::Receiver<Vec<u8>>,
    pub closed: watch::Receiver<bool>,
}

enum Link {
    Tcp {
        sess: Arc<Mutex<Session>>,
        w: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send>>>,
    },
    Udp(Arc<Rudp>),
}

pub struct Tunnel {
    link: Link,
    streams: Mutex<HashMap<u32, mpsc::Sender<Frame>>>,
    ctrl_tx: mpsc::Sender<Frame>,
    accept_tx: mpsc::Sender<Incoming>,
    mesh_tx: mpsc::Sender<Vec<u8>>,
    closed_tx: watch::Sender<bool>,
    next_sid: AtomicU32,
}

impl Tunnel {
    fn assemble(
        link: Link,
        sid_base: u32,
        tcp_reader: Option<Box<dyn AsyncRead + Unpin + Send>>,
    ) -> (
        Arc<Tunnel>,
        mpsc::Receiver<Frame>,
        mpsc::Receiver<Incoming>,
        mpsc::Receiver<Vec<u8>>,
        watch::Receiver<bool>,
    ) {
        let (ctrl_tx, ctrl_rx) = mpsc::channel(CHAN_CAP);
        let (accept_tx, accept_rx) = mpsc::channel(CHAN_CAP);
        let (mesh_tx, mesh_rx) = mpsc::channel(256);
        let (closed_tx, closed_rx) = watch::channel(false);
        let t = Arc::new(Tunnel {
            link,
            streams: Mutex::new(HashMap::new()),
            ctrl_tx,
            accept_tx,
            mesh_tx,
            closed_tx,
            next_sid: AtomicU32::new(sid_base),
        });
        match &t.link {
            Link::Tcp { sess, .. } => {
                spawn_reader_tcp(t.clone(), tcp_reader.expect("tcp reader"), sess.clone())
            }
            Link::Udp(r) => spawn_reader_udp(t.clone(), r.clone()),
        }
        (t, ctrl_rx, accept_rx, mesh_rx, closed_rx)
    }

    pub async fn write_frame(&self, f: &Frame) -> Result<()> {
        match &self.link {
            Link::Tcp { sess, w } => {
                let pkt = { sess.lock().await.seal(&yz_proto::encode(f))? };
                w.lock().await.write_all(&pkt).await?;
                Ok(())
            }
            Link::Udp(r) => {
                let f = yz_proto::encode(f);
                let mut wire = Vec::with_capacity(f.len() + 2);
                wire.extend_from_slice(&(f.len() as u16).to_be_bytes());
                wire.extend_from_slice(&f);
                r.send(&wire).await
            }
        }
    }

    /// 主动开流; rx 首帧应为 SYN_ACK
    pub async fn open_stream(&self, addr: Addr) -> Result<(u32, mpsc::Receiver<Frame>)> {
        let sid = self.next_sid.fetch_add(2, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(CHAN_CAP);
        self.streams.lock().await.insert(sid, tx);
        if let Err(e) = self
            .write_frame(&Frame::Syn {
                stream_id: sid,
                addr,
            })
            .await
        {
            self.streams.lock().await.remove(&sid);
            return Err(e);
        }
        Ok((sid, rx))
    }

    async fn close_stream(&self, sid: u32) {
        self.streams.lock().await.remove(&sid);
    }

    pub fn is_closed(&self) -> bool {
        *self.closed_tx.borrow()
    }

    pub fn watch_closed(&self) -> watch::Receiver<bool> {
        self.closed_tx.subscribe()
    }
}

/// 任意字节流上的握手 (发起方)
async fn hs_init_io<S>(io: &mut S, ns: &NetworkSecret, id_pub: &[u8; 32]) -> Result<(SessionKeys, PeerInfo)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (msg1, st) = handshake_init(ns, id_pub)?;
    io.write_all(&wrap_hs_stream(ns, &msg1)?).await?;
    let mut lb = [0u8; 2];
    timeout(HS_TIMEOUT, io.read_exact(&mut lb)).await??;
    let len = unwrap_hs_len(ns, u16::from_be_bytes(lb))?;
    anyhow::ensure!(
        (MSG2_LEN..=MSG2_LEN + 512).contains(&len),
        "bad hs2 len {len}"
    );
    let mut body = vec![0u8; len];
    timeout(HS_TIMEOUT, io.read_exact(&mut body)).await??;
    Ok(handshake_finish(ns, st, &body[len - MSG2_LEN..])?)
}

/// 任意字节流上的握手 (响应方); Ok(None) 表示认证失败
pub(crate) async fn hs_accept_io<S>(
    io: &mut S,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<Option<(SessionKeys, PeerInfo)>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut lb = [0u8; 2];
    timeout(HS_TIMEOUT, io.read_exact(&mut lb)).await??;
    let Ok(len) = unwrap_hs_len(ns, u16::from_be_bytes(lb)) else {
        return Ok(None);
    };
    if !(MSG1_LEN..=MSG1_LEN + 512).contains(&len) {
        return Ok(None);
    }
    let mut body = vec![0u8; len];
    timeout(HS_TIMEOUT, io.read_exact(&mut body)).await??;
    match handshake_accept(ns, id_pub, &body[len - MSG1_LEN..]) {
        Ok((msg2, keys, peer)) => {
            io.write_all(&wrap_hs_stream(ns, &msg2)?).await?;
            Ok(Some((keys, peer)))
        }
        Err(_) => Ok(None),
    }
}

/// 字节流装配为隧道
pub(crate) fn assemble_stream<S>(
    io: S,
    keys: &SessionKeys,
    role: Role,
    sid_base: u32,
    peer_info: PeerInfo,
) -> TunnelHandle
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let sess = Arc::new(Mutex::new(Session::from_keys(keys, role)));
    let (r, w) = tokio::io::split(io);
    let (tunnel, ctrl_rx, accept_rx, mesh_rx, closed) = Tunnel::assemble(
        Link::Tcp {
            sess,
            w: Arc::new(Mutex::new(
                Box::new(w) as Box<dyn AsyncWrite + Unpin + Send>,
            )),
        },
        sid_base,
        Some(Box::new(r)),
    );
    TunnelHandle {
        tunnel,
        peer: peer_info,
        ctrl_rx,
        accept_rx,
        mesh_rx,
        closed,
    }
}

/// 隧道发起方 (TCP)
pub async fn connect(peer: &str, ns: &NetworkSecret, id_pub: &[u8; 32]) -> Result<TunnelHandle> {
    let mut stream = TcpStream::connect(peer)
        .await
        .with_context(|| format!("connect {peer}"))?;
    stream.set_nodelay(true).ok();
    let (keys, peer_info) = hs_init_io(&mut stream, ns, id_pub).await?;
    Ok(assemble_stream(stream, &keys, Role::Initiator, 1, peer_info))
}

/// 隧道发起方 (WSS 模仿模式)
pub async fn connect_wss(
    peer: &str,
    sni: &str,
    insecure: bool,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<TunnelHandle> {
    let stream = TcpStream::connect(peer)
        .await
        .with_context(|| format!("connect {peer}"))?;
    stream.set_nodelay(true).ok();
    let connector = crate::wss::client_connector(insecure)?;
    let mut ws = crate::wss::connect(stream, &connector, sni).await?;
    let (keys, peer_info) = hs_init_io(&mut ws, ns, id_pub).await?;
    Ok(assemble_stream(ws, &keys, Role::Initiator, 1, peer_info))
}

/// 隧道响应方 (TCP)。握手失败的连接转发到 fallback 站点 (抗主动探测);
/// 返回 Ok(None) 表示已按 fallback/静默处理。
pub async fn accept(
    stream: TcpStream,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    fallback: Option<&str>,
) -> Result<Option<TunnelHandle>> {
    stream.set_nodelay(true).ok();
    let mut stream = stream;

    // 读握手线报文: masked_len(2) | pad | core(116)
    let mut raw = Vec::new(); // 已读字节, fallback 时需原样转发
    let mut lb = [0u8; 2];
    let core = match timeout(HS_TIMEOUT, stream.read_exact(&mut lb)).await {
        Ok(Ok(_)) => {
            raw.extend_from_slice(&lb);
            let len = unwrap_hs_len(ns, u16::from_be_bytes(lb)).unwrap_or(usize::MAX);
            if !(MSG1_LEN..=MSG1_LEN + 512).contains(&len) {
                return relay_or_close(stream, raw, fallback).await;
            }
            let mut body = vec![0u8; len];
            match timeout(HS_TIMEOUT, stream.read_exact(&mut body)).await {
                Ok(Ok(_)) => {
                    raw.extend_from_slice(&body);
                    body[len - MSG1_LEN..].to_vec()
                }
                _ => return relay_or_close(stream, raw, fallback).await,
            }
        }
        _ => return relay_or_close(stream, raw, fallback).await,
    };

    match handshake_accept(ns, id_pub, &core) {
        Ok((msg2, keys, peer_info)) => {
            stream.write_all(&wrap_hs_stream(ns, &msg2)?).await?;
            Ok(Some(assemble_stream(
                stream,
                &keys,
                Role::Responder,
                2,
                peer_info,
            )))
        }
        Err(_) => relay_or_close(stream, raw, fallback).await,
    }
}

/// 隧道响应方 (WSS 模仿模式); TLS/WS/YZP 任一失败即断开, 对外表现为普通 HTTPS 站
pub async fn accept_wss(
    stream: TcpStream,
    acceptor: &tokio_rustls::TlsAcceptor,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<Option<TunnelHandle>> {
    stream.set_nodelay(true).ok();
    let mut ws = crate::wss::accept(stream, acceptor).await?;
    match hs_accept_io(&mut ws, ns, id_pub).await? {
        Some((keys, peer_info)) => Ok(Some(assemble_stream(ws, &keys, Role::Responder, 2, peer_info))),
        None => Ok(None),
    }
}

/// 握手失败的连接: 有 fallback 则原样转发到真实站点, 否则静默关闭
async fn relay_or_close(
    stream: TcpStream,
    raw: Vec<u8>,
    fallback: Option<&str>,
) -> Result<Option<TunnelHandle>> {
    if let Some(target) = fallback {
        if let Ok(out) = TcpStream::connect(target).await {
            let (mut sr, mut sw) = stream.into_split();
            let (mut or, mut ow) = out.into_split();
            if ow.write_all(&raw).await.is_ok() {
                tokio::spawn(async move {
                    let a = tokio::io::copy(&mut sr, &mut ow);
                    let b = tokio::io::copy(&mut or, &mut sw);
                    let _ = tokio::join!(a, b);
                });
                log::debug!("relayed probe to fallback {target}");
            }
        }
    }
    Ok(None)
}

/// 隧道发起方 (UDP, 自带临时端点; mesh 节点应复用 yz_rudp::Endpoint)
pub async fn connect_udp(peer: &str, ns: &NetworkSecret, id_pub: &[u8; 32]) -> Result<TunnelHandle> {
    let addr = tokio::net::lookup_host(peer)
        .await?
        .next()
        .with_context(|| format!("resolve {peer}"))?;
    let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind_addr).await?;
    let ep = yz_rudp::Endpoint::bind(sock, ns, *id_pub).await?;
    let (rudp, peer_info) = ep.connect(addr, ns, id_pub).await?;
    Ok(from_rudp_with_base(rudp, peer_info, 1))
}

/// 隧道响应方 (UDP, 由 Endpoint::accept 产出)
pub fn from_rudp(rudp: Rudp, peer_info: PeerInfo) -> TunnelHandle {
    from_rudp_with_base(rudp, peer_info, 2)
}

/// UDP 隧道装配, sid_base: 发起方 1, 响应方 2
pub fn from_rudp_with_base(rudp: Rudp, peer_info: PeerInfo, sid_base: u32) -> TunnelHandle {
    let (tunnel, ctrl_rx, accept_rx, mesh_rx, closed) =
        Tunnel::assemble(Link::Udp(Arc::new(rudp)), sid_base, None);
    TunnelHandle {
        tunnel,
        peer: peer_info,
        ctrl_rx,
        accept_rx,
        mesh_rx,
        closed,
    }
}

// ---------- reader ----------

/// 分发一帧; 返回 false 终止 reader
async fn dispatch(t: &Arc<Tunnel>, f: Frame) -> bool {
    match f {
        Frame::Control { .. } | Frame::Ping { .. } | Frame::Pong { .. } => {
            t.ctrl_tx.send(f).await.is_ok()
        }
        // 组网包: 尽力投递, 未启用 TUN/拥塞时丢弃, 不影响隧道
        Frame::Mesh { payload } => {
            let _ = t.mesh_tx.try_send(payload);
            true
        }
        Frame::Syn { stream_id, addr } => {
            let (tx, rx) = mpsc::channel(CHAN_CAP);
            t.streams.lock().await.insert(stream_id, tx);
            let inc = Incoming {
                sid: stream_id,
                addr,
                rx,
            };
            t.accept_tx.send(inc).await.is_ok()
        }
        f => {
            let sid = f.stream_id();
            let tx = { t.streams.lock().await.get(&sid).cloned() };
            if let Some(tx) = tx {
                if tx.send(f).await.is_err() {
                    t.close_stream(sid).await;
                }
            }
            true
        }
    }
}

async fn reader_close(t: &Arc<Tunnel>) {
    let _ = t.closed_tx.send(true);
    t.streams.lock().await.clear();
}

fn spawn_reader_tcp(
    t: Arc<Tunnel>,
    mut r: Box<dyn AsyncRead + Unpin + Send>,
    sess: Arc<Mutex<Session>>,
) {
    tokio::spawn(async move {
        loop {
            match read_frame_tcp(&mut r, &sess).await {
                Ok(f) => {
                    if !dispatch(&t, f).await {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        reader_close(&t).await;
    });
}

fn spawn_reader_udp(t: Arc<Tunnel>, rudp: Arc<Rudp>) {
    tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::new();
        'outer: loop {
            match rudp.recv().await {
                Ok(chunk) => {
                    buf.extend_from_slice(&chunk);
                    loop {
                        if buf.len() < 2 {
                            break;
                        }
                        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        if len > MAX_FRAME_LEN {
                            break 'outer;
                        }
                        if buf.len() < 2 + len {
                            break;
                        }
                        let fb: Vec<u8> = buf.drain(..2 + len).collect();
                        match yz_proto::decode(&fb[2..]) {
                            Ok(f) => {
                                if !dispatch(&t, f).await {
                                    break 'outer;
                                }
                            }
                            Err(_) => break 'outer,
                        }
                    }
                }
                Err(_) => break,
            }
        }
        reader_close(&t).await;
    });
}

async fn read_frame_tcp(
    r: &mut (dyn AsyncRead + Unpin + Send),
    sess: &Mutex<Session>,
) -> Result<Frame> {
    let mut lb = [0u8; 2];
    r.read_exact(&mut lb).await?;
    let masked = u16::from_be_bytes(lb);
    let len = { sess.lock().await.unmask_len(masked) };
    anyhow::ensure!(len > 16 && len <= MAX_FRAME_LEN + 16, "bad packet len {len}");
    let mut ct = vec![0u8; len];
    r.read_exact(&mut ct).await?;
    let plain = { sess.lock().await.open(masked, &mut ct)? };
    Ok(yz_proto::decode(&plain)?)
}

/// 单流双向转发: 本地 socket <-> 隧道流
pub async fn pump_stream(
    local: TcpStream,
    sid: u32,
    mut rx: mpsc::Receiver<Frame>,
    t: Arc<Tunnel>,
) -> Result<()> {
    local.set_nodelay(true).ok();
    let (mut lr, mut lw) = local.into_split();

    let t2 = t.clone();
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; IO_BUF];
        loop {
            match lr.read(&mut buf).await {
                Ok(0) => {
                    let _ = t2.write_frame(&Frame::Fin { stream_id: sid }).await;
                    break;
                }
                Ok(n) => {
                    let f = Frame::Data {
                        stream_id: sid,
                        payload: buf[..n].to_vec(),
                    };
                    if t2.write_frame(&f).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = t2.write_frame(&Frame::Rst { stream_id: sid }).await;
                    break;
                }
            }
        }
    });

    while let Some(f) = rx.recv().await {
        match f {
            Frame::Data { payload, .. } => {
                if lw.write_all(&payload).await.is_err() {
                    break;
                }
            }
            Frame::Fin { .. } => {
                lw.shutdown().await.ok();
            }
            Frame::Rst { .. } => break,
            _ => {}
        }
    }
    uplink.abort();
    t.close_stream(sid).await;
    Ok(())
}

// ---------- 中继 (P7): 打洞与直连都失败时经 coordinator 转发, 端到端嵌套加密 ----------

/// 中继标记地址: SYN 目标是 Domain(RELAY_MARK, 0) 表示这是中继隧道的服务端点
pub const RELAY_MARK: &str = "yz.relay";

/// 隧道流伪装成 AsyncRead/AsyncWrite (中继上跑嵌套 YZP 隧道)
pub struct StreamIo {
    sid: u32,
    rx: mpsc::Receiver<Frame>,
    tx: mpsc::UnboundedSender<Frame>,
    rbuf: Vec<u8>,
    rpos: usize,
    eof: bool,
}

impl StreamIo {
    pub fn new(t: Arc<Tunnel>, sid: u32, rx: mpsc::Receiver<Frame>) -> Self {
        let (tx, mut wx) = mpsc::unbounded_channel::<Frame>();
        tokio::spawn(async move {
            while let Some(f) = wx.recv().await {
                if t.write_frame(&f).await.is_err() {
                    break;
                }
            }
        });
        Self {
            sid,
            rx,
            tx,
            rbuf: Vec::new(),
            rpos: 0,
            eof: false,
        }
    }
}

impl AsyncRead for StreamIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if self.rpos < self.rbuf.len() {
                let n = buf.remaining().min(self.rbuf.len() - self.rpos);
                buf.put_slice(&self.rbuf[self.rpos..self.rpos + n]);
                self.rpos += n;
                if self.rpos == self.rbuf.len() {
                    self.rbuf.clear();
                    self.rpos = 0;
                }
                return std::task::Poll::Ready(Ok(()));
            }
            if self.eof {
                return std::task::Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(Frame::Data { payload, .. })) => {
                    self.rbuf = payload;
                    self.rpos = 0;
                }
                std::task::Poll::Ready(Some(Frame::Fin { .. }))
                | std::task::Poll::Ready(Some(Frame::Rst { .. }))
                | std::task::Poll::Ready(None) => {
                    self.eof = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(Some(_)) => continue,
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for StreamIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.tx.send(Frame::Data {
            stream_id: self.sid,
            payload: buf.to_vec(),
        }) {
            Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let _ = self.tx.send(Frame::Fin {
            stream_id: self.sid,
        });
        std::task::Poll::Ready(Ok(()))
    }
}

/// 中继发起方: 在 coordinator 隧道上开流 (SYN=Domain(target,0)), 其上跑嵌套握手
pub async fn connect_relayed(
    coord: &Arc<Tunnel>,
    target: &str,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<TunnelHandle> {
    let (sid, mut rx) = coord
        .open_stream(Addr::Domain(target.to_string(), 0))
        .await?;
    match timeout(HS_TIMEOUT, rx.recv()).await? {
        Some(Frame::SynAck { ok: true, .. }) => {}
        Some(Frame::SynAck { ok: false, .. }) => bail!("relay refused by coordinator"),
        _ => bail!("expect SYN_ACK"),
    }
    let mut io = StreamIo::new(coord.clone(), sid, rx);
    let (keys, peer_info) = hs_init_io(&mut io, ns, id_pub).await?;
    Ok(assemble_stream(io, &keys, Role::Initiator, 1, peer_info))
}

/// 两条隧道流对泵 (coordinator 中继数据面)
pub async fn pipe_streams(
    ta: Arc<Tunnel>,
    sa: u32,
    ra: mpsc::Receiver<Frame>,
    tb: Arc<Tunnel>,
    sb: u32,
    rb: mpsc::Receiver<Frame>,
) {
    async fn copy_dir(
        t: Arc<Tunnel>,
        dst_sid: u32,
        mut rx: mpsc::Receiver<Frame>,
    ) {
        while let Some(f) = rx.recv().await {
            let out = match f {
                Frame::Data { payload, .. } => Frame::Data {
                    stream_id: dst_sid,
                    payload,
                },
                Frame::Fin { .. } => Frame::Fin { stream_id: dst_sid },
                Frame::Rst { .. } => Frame::Rst { stream_id: dst_sid },
                _ => continue,
            };
            if t.write_frame(&out).await.is_err() {
                break;
            }
        }
    }
    let a2b = copy_dir(tb.clone(), sb, ra); // A 侧流 → B 侧流
    let b2a = copy_dir(ta, sa, rb);
    let _ = tokio::join!(a2b, b2a);
}
