//! 多路复用隧道: 一条加密会话承载多条流 + stream 0 控制消息。
//! 流 ID 约定: 隧道发起方用奇数, 响应方用偶数, 双向开流不冲突。

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::timeout;
use yz_crypto::{
    handshake_accept, handshake_finish, handshake_init, NetworkSecret, PeerInfo, Session,
    MSG1_LEN, MSG2_LEN,
};
use yz_proto::{Addr, Frame, MAX_FRAME_LEN};

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

pub struct Tunnel {
    sess: Mutex<Session>,
    w: Mutex<OwnedWriteHalf>,
    streams: Mutex<HashMap<u32, mpsc::Sender<Frame>>>,
    ctrl_tx: mpsc::Sender<Frame>,
    accept_tx: mpsc::Sender<Incoming>,
    closed_tx: watch::Sender<bool>,
    next_sid: AtomicU32,
}

impl Tunnel {
    fn new(
        stream: TcpStream,
        sess: Session,
        sid_base: u32,
    ) -> (
        Arc<Tunnel>,
        mpsc::Receiver<Frame>,
        mpsc::Receiver<Incoming>,
        watch::Receiver<bool>,
    ) {
        let (r, w) = stream.into_split();
        let (ctrl_tx, ctrl_rx) = mpsc::channel(CHAN_CAP);
        let (accept_tx, accept_rx) = mpsc::channel(CHAN_CAP);
        let (closed_tx, closed_rx) = watch::channel(false);
        let t = Arc::new(Tunnel {
            sess: Mutex::new(sess),
            w: Mutex::new(w),
            streams: Mutex::new(HashMap::new()),
            ctrl_tx,
            accept_tx,
            closed_tx,
            next_sid: AtomicU32::new(sid_base),
        });
        spawn_reader(t.clone(), r);
        (t, ctrl_rx, accept_rx, closed_rx)
    }

    pub async fn write_frame(&self, f: &Frame) -> Result<()> {
        let pkt = { self.sess.lock().await.seal(&yz_proto::encode(f))? };
        self.w.lock().await.write_all(&pkt).await?;
        Ok(())
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

/// 隧道发起方 (dial/节点外连)
pub async fn connect(peer: &str, ns: &NetworkSecret, id_pub: &[u8; 32]) -> Result<TunnelHandle> {
    let mut stream = TcpStream::connect(peer)
        .await
        .with_context(|| format!("connect {peer}"))?;
    stream.set_nodelay(true).ok();
    let (msg1, st) = handshake_init(ns, id_pub)?;
    stream.write_all(&msg1).await?;
    let mut msg2 = vec![0u8; MSG2_LEN];
    timeout(HS_TIMEOUT, stream.read_exact(&mut msg2)).await??;
    let (sess, peer_info) = handshake_finish(ns, st, &msg2)?;
    let (tunnel, ctrl_rx, accept_rx, closed) = Tunnel::new(stream, sess, 1);
    Ok(TunnelHandle {
        tunnel,
        peer: peer_info,
        ctrl_rx,
        accept_rx,
        closed,
    })
}

/// 隧道响应方 (serve/被连节点)
pub async fn accept(
    stream: TcpStream,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<TunnelHandle> {
    stream.set_nodelay(true).ok();
    let mut stream = stream;
    let mut msg1 = vec![0u8; MSG1_LEN];
    timeout(HS_TIMEOUT, stream.read_exact(&mut msg1)).await??;
    let (msg2, sess, peer_info) = handshake_accept(ns, id_pub, &msg1)?;
    stream.write_all(&msg2).await?;
    let (tunnel, ctrl_rx, accept_rx, closed) = Tunnel::new(stream, sess, 2);
    Ok(TunnelHandle {
        tunnel,
        peer: peer_info,
        ctrl_rx,
        accept_rx,
        closed,
    })
}

fn spawn_reader(t: Arc<Tunnel>, mut r: OwnedReadHalf) {
    tokio::spawn(async move {
        loop {
            match read_frame(&mut r, &t.sess).await {
                Ok(f @ Frame::Control { .. })
                | Ok(f @ Frame::Ping { .. })
                | Ok(f @ Frame::Pong { .. }) => {
                    if t.ctrl_tx.send(f).await.is_err() {
                        break;
                    }
                }
                Ok(Frame::Syn { stream_id, addr }) => {
                    let (tx, rx) = mpsc::channel(CHAN_CAP);
                    t.streams.lock().await.insert(stream_id, tx);
                    let inc = Incoming {
                        sid: stream_id,
                        addr,
                        rx,
                    };
                    if t.accept_tx.send(inc).await.is_err() {
                        break;
                    }
                }
                Ok(f) => {
                    let sid = f.stream_id();
                    let tx = { t.streams.lock().await.get(&sid).cloned() };
                    if let Some(tx) = tx {
                        if tx.send(f).await.is_err() {
                            t.close_stream(sid).await;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = t.closed_tx.send(true);
        t.streams.lock().await.clear();
    });
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

async fn read_frame(r: &mut OwnedReadHalf, sess: &Mutex<Session>) -> Result<Frame> {
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
