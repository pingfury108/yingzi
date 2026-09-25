//! 多路复用隧道: 一条加密会话承载多条流 + stream 0 控制消息。
//! 承载: TCP (计数器 nonce + 掩码长度) 或 UDP (yz-rudp 可靠字节流, len(2)|frame)。
//! 流 ID 约定: 隧道发起方用奇数, 响应方用偶数, 双向开流不冲突。

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::timeout;
use yz_crypto::{
    handshake_accept, handshake_finish, handshake_init, NetworkSecret, PeerInfo, Role, Session,
    MSG1_LEN, MSG2_LEN,
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
    pub closed: watch::Receiver<bool>,
}

enum Link {
    Tcp {
        sess: Arc<Mutex<Session>>,
        w: Arc<Mutex<OwnedWriteHalf>>,
    },
    Udp(Arc<Rudp>),
}

pub struct Tunnel {
    link: Link,
    streams: Mutex<HashMap<u32, mpsc::Sender<Frame>>>,
    ctrl_tx: mpsc::Sender<Frame>,
    accept_tx: mpsc::Sender<Incoming>,
    closed_tx: watch::Sender<bool>,
    next_sid: AtomicU32,
}

impl Tunnel {
    fn assemble(
        link: Link,
        sid_base: u32,
        tcp_reader: Option<OwnedReadHalf>,
    ) -> (
        Arc<Tunnel>,
        mpsc::Receiver<Frame>,
        mpsc::Receiver<Incoming>,
        watch::Receiver<bool>,
    ) {
        let (ctrl_tx, ctrl_rx) = mpsc::channel(CHAN_CAP);
        let (accept_tx, accept_rx) = mpsc::channel(CHAN_CAP);
        let (closed_tx, closed_rx) = watch::channel(false);
        let t = Arc::new(Tunnel {
            link,
            streams: Mutex::new(HashMap::new()),
            ctrl_tx,
            accept_tx,
            closed_tx,
            next_sid: AtomicU32::new(sid_base),
        });
        match &t.link {
            Link::Tcp { sess, .. } => {
                spawn_reader_tcp(t.clone(), tcp_reader.expect("tcp reader"), sess.clone())
            }
            Link::Udp(r) => spawn_reader_udp(t.clone(), r.clone()),
        }
        (t, ctrl_rx, accept_rx, closed_rx)
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

/// 隧道发起方 (TCP)
pub async fn connect(peer: &str, ns: &NetworkSecret, id_pub: &[u8; 32]) -> Result<TunnelHandle> {
    let mut stream = TcpStream::connect(peer)
        .await
        .with_context(|| format!("connect {peer}"))?;
    stream.set_nodelay(true).ok();
    let (msg1, st) = handshake_init(ns, id_pub)?;
    stream.write_all(&msg1).await?;
    let mut msg2 = vec![0u8; MSG2_LEN];
    timeout(HS_TIMEOUT, stream.read_exact(&mut msg2)).await??;
    let (keys, peer_info) = handshake_finish(ns, st, &msg2)?;
    let sess = Arc::new(Mutex::new(Session::from_keys(&keys, Role::Initiator)));
    let (r, w) = stream.into_split();
    let (tunnel, ctrl_rx, accept_rx, closed) = Tunnel::assemble(
        Link::Tcp {
            sess,
            w: Arc::new(Mutex::new(w)),
        },
        1,
        Some(r),
    );
    Ok(TunnelHandle {
        tunnel,
        peer: peer_info,
        ctrl_rx,
        accept_rx,
        closed,
    })
}

/// 隧道响应方 (TCP)
pub async fn accept(
    stream: TcpStream,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<TunnelHandle> {
    stream.set_nodelay(true).ok();
    let mut stream = stream;
    let mut msg1 = vec![0u8; MSG1_LEN];
    timeout(HS_TIMEOUT, stream.read_exact(&mut msg1)).await??;
    let (msg2, keys, peer_info) = handshake_accept(ns, id_pub, &msg1)?;
    stream.write_all(&msg2).await?;
    let sess = Arc::new(Mutex::new(Session::from_keys(&keys, Role::Responder)));
    let (r, w) = stream.into_split();
    let (tunnel, ctrl_rx, accept_rx, closed) = Tunnel::assemble(
        Link::Tcp {
            sess,
            w: Arc::new(Mutex::new(w)),
        },
        2,
        Some(r),
    );
    Ok(TunnelHandle {
        tunnel,
        peer: peer_info,
        ctrl_rx,
        accept_rx,
        closed,
    })
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
    let (tunnel, ctrl_rx, accept_rx, closed) =
        Tunnel::assemble(Link::Udp(Arc::new(rudp)), sid_base, None);
    TunnelHandle {
        tunnel,
        peer: peer_info,
        ctrl_rx,
        accept_rx,
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

fn spawn_reader_tcp(t: Arc<Tunnel>, mut r: OwnedReadHalf, sess: Arc<Mutex<Session>>) {
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

async fn read_frame_tcp(r: &mut OwnedReadHalf, sess: &Mutex<Session>) -> Result<Frame> {
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
