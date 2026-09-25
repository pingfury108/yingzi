//! YZ-RUDP: UDP 可靠有序字节流传输 + NAT 探测/打洞 (P2)。
//!
//! 数据报: nonce(12) | AEAD(inner) —— 可靠性元数据全部加密, 观察者只见随机报文。
//! inner: type(1) | body
//!   0x01 DATA: seq(4) | payload(<=1300B, 上层字节流的分片)
//!   0x02 ACK:  cum(4) | sack(4)
//!   0x03 FIN
//!
//! Endpoint: 共享 UDP socket, 按来源地址 demux 到各 Rudp;
//! 带外小包 (NS 静态密钥): "PROBE"(探测公网映射) / "PUNCH"(打洞)。
//! 非法报文一律静默丢弃 (抗探测/防反射)。

use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex, Notify};
use tokio::time::timeout;
use yz_crypto::{
    handshake_accept, handshake_finish, handshake_init, wrap_hs, DgramSession, NetworkSecret,
    PeerInfo, Role, StaticKey, HS_WIRE_MAX, MSG1_LEN, MSG2_LEN,
};

const T_DATA: u8 = 0x01;
const T_ACK: u8 = 0x02;
const T_FIN: u8 = 0x03;

const MAX_DGRAM: usize = 1400; // 避开 IP 分片
const MAX_CHUNK: usize = MAX_DGRAM - 12 - 16 - 5; // nonce/tag/type/seq
const CHAN_CAP: usize = 512;
const RTO_INIT: Duration = Duration::from_millis(200);
const RTO_MAX: Duration = Duration::from_secs(3);
const RTX_TICK: Duration = Duration::from_millis(50);
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const CWND_INIT: f64 = 8.0;
const CWND_MAX: f64 = 512.0;
const MAX_PENDING_DIST: u32 = 4096;

/// PUNCH 报文长度: nonce12 + 5 + tag16
const PUNCH_PKT_LEN: usize = 12 + 5 + 16;
/// 打孔请求 / 回射确认 (等长, 回射防止对称 NAT 下收不到对端包)
const PUNCH_REQ: &[u8] = b"PUNCH";
const PUNCH_ECHO: &[u8] = b"PUNKE";
const PROBE_SALT: &[u8] = b"yz-probe-v1";

/// NAT 探测/打洞共享的静态密钥
pub fn probe_key(ns: &NetworkSecret) -> Result<StaticKey> {
    Ok(StaticKey::derive(ns, PROBE_SALT)?)
}

type PeersMap = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

// ---------- Endpoint ----------

struct EpInner {
    sock: Arc<UdpSocket>,
    probe_key: StaticKey,
    peers: PeersMap,
    punch_tx: mpsc::Sender<SocketAddr>,
    punch_rx: Mutex<mpsc::Receiver<SocketAddr>>,
    incoming: Mutex<mpsc::Receiver<(Rudp, PeerInfo)>>,
}

/// 共享 UDP socket 端点: accept/connect/punch/probe 共用同一 NAT 映射
pub struct Endpoint {
    inner: Arc<EpInner>,
}

impl Endpoint {
    pub async fn bind(sock: UdpSocket, ns: &NetworkSecret, id_pub: [u8; 32]) -> Result<Endpoint> {
        let sock = Arc::new(sock);
        let (incoming_tx, incoming_rx) = mpsc::channel(64);
        let (punch_tx, punch_rx) = mpsc::channel(64);
        let inner = Arc::new(EpInner {
            sock: sock.clone(),
            probe_key: StaticKey::derive(ns, PROBE_SALT)?,
            peers: Default::default(),
            punch_tx,
            punch_rx: Mutex::new(punch_rx),
            incoming: Mutex::new(incoming_rx),
        });
        tokio::spawn(demux_loop(inner.clone(), ns.clone(), id_pub, incoming_tx));
        Ok(Endpoint { inner })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.sock.local_addr()?)
    }

    /// 接受对端隧道 (P2P 被打入方/serve)
    pub async fn accept(&self) -> Option<(Rudp, PeerInfo)> {
        self.inner.incoming.lock().await.recv().await
    }

    /// 主动向 addr 建立可靠隧道
    pub async fn connect(
        &self,
        peer: SocketAddr,
        ns: &NetworkSecret,
        id_pub: &[u8; 32],
    ) -> Result<(Rudp, PeerInfo)> {
        let (tx, rx) = mpsc::channel(CHAN_CAP);
        self.inner.peers.lock().await.insert(peer, tx);
        let res = self.hs_connect(peer, ns, id_pub, rx).await;
        if res.is_err() {
            self.inner.peers.lock().await.remove(&peer);
        }
        res
    }

    async fn hs_connect(
        &self,
        peer: SocketAddr,
        ns: &NetworkSecret,
        id_pub: &[u8; 32],
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> Result<(Rudp, PeerInfo)> {
        let (msg1, st) = handshake_init(ns, id_pub)?;
        let wire1 = wrap_hs(&msg1); // 随机填充, 消除固定尺寸
        let mut st = Some(st);
        let mut wait = Duration::from_millis(600);
        for _ in 0..4 {
            self.inner.sock.send_to(&wire1, peer).await?;
            match timeout(wait, rx.recv()).await {
                Ok(Some(d)) if (MSG2_LEN..=HS_WIRE_MAX).contains(&d.len()) => {
                    let (keys, peer_info) =
                        handshake_finish(ns, st.take().unwrap(), &d[d.len() - MSG2_LEN..])?;
                    let sess = DgramSession::from_keys(&keys, Role::Initiator);
                    let rudp = Rudp::new(
                        self.inner.sock.clone(),
                        peer,
                        sess,
                        rx,
                        Some(self.inner.peers.clone()),
                    );
                    return Ok((rudp, peer_info));
                }
                Ok(Some(_)) => continue,
                Ok(None) => bail!("demux closed"),
                Err(_) => wait *= 2, // 重传 msg1
            }
        }
        bail!("handshake timeout")
    }

    /// NAT 探测: 经 server 观察本端点的公网映射地址
    pub async fn probe_via(&self, server: SocketAddr) -> Result<SocketAddr> {
        let (tx, mut rx) = mpsc::channel(8);
        self.inner.peers.lock().await.insert(server, tx);
        let res = self.probe_inner(server, &mut rx).await;
        self.inner.peers.lock().await.remove(&server);
        res
    }

    async fn probe_inner(
        &self,
        server: SocketAddr,
        rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<SocketAddr> {
        let pkt = self.inner.probe_key.seal(b"PROBE")?;
        let mut wait = Duration::from_millis(500);
        for _ in 0..3 {
            self.inner.sock.send_to(&pkt, server).await?;
            if let Ok(Some(d)) = timeout(wait, rx.recv()).await {
                if let Ok(plain) = self.inner.probe_key.open(&d) {
                    if let Some(rest) = plain.strip_prefix(b"PROBR") {
                        let s = String::from_utf8(rest.to_vec()).context("bad probe resp")?;
                        return s.parse().context("bad observed addr");
                    }
                }
            }
            wait *= 2;
        }
        bail!("probe timeout")
    }

    /// 打洞: 向 candidates 散射 PUNCH 并等待对端打孔包, 返回打通的地址。
    /// PUNCH 包经 NS 认证, 任一合法来源即可信 (对称 NAT 端口可能与目录不同)。
    pub async fn punch(&self, candidates: &[SocketAddr], dur: Duration) -> Result<SocketAddr> {
        let pkt = self.inner.probe_key.seal(PUNCH_REQ)?;
        let sock = self.inner.sock.clone();
        let cands = candidates.to_vec();
        let sprayer = tokio::spawn(async move {
            let end = Instant::now() + dur;
            while Instant::now() < end {
                for a in &cands {
                    let _ = sock.send_to(&pkt, *a).await;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let r = {
            let mut rx = self.inner.punch_rx.lock().await;
            timeout(dur, async {
                let from = rx.recv().await.context("punch channel closed")?;
                Ok(from)
            })
            .await
        };
        sprayer.abort();
        match r {
            Ok(inner) => inner,
            Err(_) => bail!("punch timeout"),
        }
    }
}

async fn demux_loop(
    inner: Arc<EpInner>,
    ns: NetworkSecret,
    id_pub: [u8; 32],
    incoming_tx: mpsc::Sender<(Rudp, PeerInfo)>,
) {
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = match inner.sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => break,
        };
        let dgram = buf[..n].to_vec();
        let known = { inner.peers.lock().await.get(&from).cloned() };
        if let Some(tx) = known {
            let _ = tx.send(dgram).await;
            continue;
        }
        // 打洞包 (NS 认证): PUNCH=请求(回射到达源), PUNKE=回射确认(不再回, 防风暴)
        if dgram.len() == PUNCH_PKT_LEN {
            if let Ok(plain) = inner.probe_key.open(&dgram) {
                if plain == PUNCH_REQ {
                    if let Ok(echo) = inner.probe_key.seal(PUNCH_ECHO) {
                        let _ = inner.sock.send_to(&echo, from).await;
                    }
                    let _ = inner.punch_tx.send(from).await;
                    continue;
                } else if plain == PUNCH_ECHO {
                    let _ = inner.punch_tx.send(from).await;
                    continue;
                }
            }
        }
        // 新隧道握手: 随机填充包装, 取尾部 core; 非法则静默丢弃 (抗探测)
        if !(MSG1_LEN..=HS_WIRE_MAX).contains(&dgram.len()) {
            continue;
        }
        let core = &dgram[dgram.len() - MSG1_LEN..];
        let Ok((msg2_core, keys, peer_info)) = handshake_accept(&ns, &id_pub, core) else {
            continue;
        };
        let wire2 = wrap_hs(&msg2_core);
        if inner.sock.send_to(&wire2, from).await.is_err() {
            continue;
        }
        let (tx, rx) = mpsc::channel(CHAN_CAP);
        inner.peers.lock().await.insert(from, tx);
        let sess = DgramSession::from_keys(&keys, Role::Responder);
        let rudp = Rudp::new(inner.sock.clone(), from, sess, rx, Some(inner.peers.clone()));
        let _ = incoming_tx.send((rudp, peer_info)).await;
    }
}

/// NAT 探测应答器 (coordinator 用): 对合法 PROBE 回复观察到的来源地址
pub fn spawn_probe_responder(sock: UdpSocket, key: StaticKey) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 256];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => break,
            };
            if let Ok(plain) = key.open(&buf[..n]) {
                if plain == b"PROBE" {
                    let resp = format!("PROBR{from}");
                    if let Ok(ct) = key.seal(resp.as_bytes()) {
                        let _ = sock.send_to(&ct, from).await;
                    }
                }
            }
        }
    });
}

// ---------- 尺寸桶填充 (隐匿: 加密内填充, 观察者只见随机长度的随机报文) ----------

/// type | padlen(1) | body | rand_pad —— 填充到尺寸桶+抖动
fn pad_inner(inner: &[u8]) -> Vec<u8> {
    const BUCKETS: [usize; 6] = [64, 160, 320, 640, 1024, 1380];
    let base = inner.len() + 1;
    let bucket = BUCKETS.iter().copied().find(|b| *b >= base).unwrap_or(base);
    let jitter = yz_crypto::random_bytes(1)[0] as usize % 33;
    let target = (bucket + jitter).min(1380);
    let pad = target.saturating_sub(base).min(255);
    let mut out = Vec::with_capacity(base + pad);
    out.push(inner[0]);
    out.push(pad as u8);
    out.extend_from_slice(&inner[1..]);
    out.extend_from_slice(&yz_crypto::random_bytes(pad));
    out
}

/// pad_inner 的逆: 返回 (type, body)
fn unpad(pkt: &[u8]) -> Option<(u8, &[u8])> {
    if pkt.len() < 2 {
        return None;
    }
    let pad = pkt[1] as usize;
    if pkt.len() < 2 + pad {
        return None;
    }
    Some((pkt[0], &pkt[2..pkt.len() - pad]))
}

// ---------- Rudp ----------

struct Unacked {
    ct: Vec<u8>,
    sent_at: Instant,
}

struct TxState {
    next_seq: u32,
    unacked: BTreeMap<u32, Unacked>,
    cwnd: f64,
    rto: Duration,
    last_cum: Option<u32>,
    dup: u8,
}

struct RxState {
    expect: u32,
    pending: BTreeMap<u32, Vec<u8>>,
}

struct Inner {
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    sess: DgramSession,
    tx: Mutex<TxState>,
    win: Notify,
    closed_tx: watch::Sender<bool>,
    user_tx: mpsc::Sender<Vec<u8>>,
    last_rx: Mutex<Instant>,
}

pub struct Rudp {
    inner: Arc<Inner>,
    user_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl Rudp {
    fn new(
        sock: Arc<UdpSocket>,
        peer: SocketAddr,
        sess: DgramSession,
        rx: mpsc::Receiver<Vec<u8>>,
        peers: Option<PeersMap>,
    ) -> Rudp {
        let (closed_tx, _) = watch::channel(false);
        let (user_tx, user_rx) = mpsc::channel(CHAN_CAP);
        let inner = Arc::new(Inner {
            sock,
            peer,
            sess,
            tx: Mutex::new(TxState {
                next_seq: 0,
                unacked: BTreeMap::new(),
                cwnd: CWND_INIT,
                rto: RTO_INIT,
                last_cum: None,
                dup: 0,
            }),
            win: Notify::new(),
            closed_tx,
            user_tx,
            last_rx: Mutex::new(Instant::now()),
        });
        tokio::spawn(rx_loop(inner.clone(), rx, peers));
        tokio::spawn(rtx_loop(inner.clone()));
        Rudp {
            inner,
            user_rx: Mutex::new(user_rx),
        }
    }

    /// 可靠有序发送字节流 (自动分片)
    pub async fn send(&self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        for chunk in bytes.chunks(MAX_CHUNK) {
            loop {
                if self.is_closed() {
                    bail!("rudp closed");
                }
                {
                    let mut st = self.inner.tx.lock().await;
                    if (st.unacked.len() as f64) < st.cwnd {
                        let seq = st.next_seq;
                        st.next_seq = st.next_seq.wrapping_add(1);
                        let mut pkt = Vec::with_capacity(5 + chunk.len());
                        pkt.push(T_DATA);
                        pkt.extend_from_slice(&seq.to_be_bytes());
                        pkt.extend_from_slice(chunk);
                        let ct = self.inner.sess.seal(&pad_inner(&pkt))?;
                        self.inner.sock.send_to(&ct, self.inner.peer).await?;
                        st.unacked.insert(
                            seq,
                            Unacked {
                                ct,
                                sent_at: Instant::now(),
                            },
                        );
                        break;
                    }
                }
                self.inner.win.notified().await;
            }
        }
        Ok(())
    }

    /// 有序接收 (流语义, 无消息边界)
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut closed = self.inner.closed_tx.subscribe();
        let mut rx = self.user_rx.lock().await;
        tokio::select! {
            m = rx.recv() => m.context("rudp closed"),
            _ = closed.changed() => Err(anyhow::anyhow!("rudp closed")),
        }
    }

    pub fn is_closed(&self) -> bool {
        *self.inner.closed_tx.borrow()
    }

    /// 主动关闭 (best-effort FIN)
    pub async fn close(&self) {
        do_close(&self.inner, true).await;
    }
}

async fn rx_loop(inner: Arc<Inner>, mut c: mpsc::Receiver<Vec<u8>>, peers: Option<PeersMap>) {
    let mut rx = RxState {
        expect: 0,
        pending: BTreeMap::new(),
    };
    loop {
        let Some(dgram) = c.recv().await else { break };
        *inner.last_rx.lock().await = Instant::now();
        let Ok(pkt) = inner.sess.open(&dgram) else {
            continue; // 解密失败静默丢弃
        };
        let Some((t, body)) = unpad(&pkt) else {
            continue;
        };
        match t {
            T_DATA => {
                if body.len() < 4 {
                    continue;
                }
                let seq = u32::from_be_bytes(body[..4].try_into().unwrap());
                let payload = body[4..].to_vec();
                if seq == rx.expect {
                    if !deliver(&inner, &mut rx, seq, payload).await {
                        break;
                    }
                } else {
                    let dist = seq.wrapping_sub(rx.expect);
                    if dist < MAX_PENDING_DIST {
                        rx.pending.insert(seq, payload);
                    }
                }
                send_ack(&inner, rx.expect.wrapping_sub(1), &rx.pending).await;
            }
            T_ACK => {
                if body.len() < 8 {
                    continue;
                }
                let cum = u32::from_be_bytes(body[..4].try_into().unwrap());
                let sack = u32::from_be_bytes(body[4..8].try_into().unwrap());
                process_ack(&inner, cum, sack).await;
            }
            T_FIN => break,
            _ => {}
        }
    }
    do_close(&inner, false).await;
    if let Some(peers) = peers {
        peers.lock().await.remove(&inner.peer);
    }
}

/// 交付 seq 并冲刷连续的 pending; 返回 false 表示用户侧已断开
async fn deliver(inner: &Inner, rx: &mut RxState, seq: u32, payload: Vec<u8>) -> bool {
    if inner.user_tx.send(payload).await.is_err() {
        return false;
    }
    rx.expect = seq.wrapping_add(1);
    while let Some(p) = rx.pending.remove(&rx.expect) {
        if inner.user_tx.send(p).await.is_err() {
            return false;
        }
        rx.expect = rx.expect.wrapping_add(1);
    }
    true
}

async fn send_ack(inner: &Inner, cum: u32, pending: &BTreeMap<u32, Vec<u8>>) {
    let mut sack = 0u32;
    for i in 0..32u32 {
        if pending.contains_key(&cum.wrapping_add(1 + i)) {
            sack |= 1 << i;
        }
    }
    let mut pkt = Vec::with_capacity(9);
    pkt.push(T_ACK);
    pkt.extend_from_slice(&cum.to_be_bytes());
    pkt.extend_from_slice(&sack.to_be_bytes());
    if let Ok(ct) = inner.sess.seal(&pad_inner(&pkt)) {
        let _ = inner.sock.send_to(&ct, inner.peer).await;
    }
}

async fn process_ack(inner: &Inner, cum: u32, sack: u32) {
    let mut fast_rtx = None;
    {
        let mut st = inner.tx.lock().await;
        let before = st.unacked.len();
        // 移除 <= cum
        let rest = st.unacked.split_off(&cum.wrapping_add(1));
        st.unacked = rest;
        // sack 位图
        for i in 0..32u32 {
            if sack & (1 << i) != 0 {
                st.unacked.remove(&cum.wrapping_add(1 + i));
            }
        }
        let acked = before - st.unacked.len();
        if acked > 0 {
            st.cwnd = (st.cwnd + acked as f64 / st.cwnd).min(CWND_MAX);
            st.rto = RTO_INIT;
            st.dup = 0;
            st.last_cum = Some(cum);
        } else if st.last_cum == Some(cum) && !st.unacked.is_empty() {
            st.dup += 1;
            if st.dup >= 3 {
                fast_rtx = st.unacked.keys().next().copied();
                st.dup = 0;
            }
        }
    }
    inner.win.notify_waiters();
    if let Some(seq) = fast_rtx {
        let ct = {
            let st = inner.tx.lock().await;
            st.unacked.get(&seq).map(|u| u.ct.clone())
        };
        if let Some(ct) = ct {
            log::debug!("fast rtx seq={seq}");
            let _ = inner.sock.send_to(&ct, inner.peer).await;
        }
    }
}

async fn rtx_loop(inner: Arc<Inner>) {
    loop {
        tokio::time::sleep(RTX_TICK).await;
        if *inner.closed_tx.borrow() {
            break;
        }
        if inner.last_rx.lock().await.elapsed() > IDLE_TIMEOUT {
            log::debug!("rudp idle timeout");
            break;
        }
        let mut resend = vec![];
        {
            let mut st = inner.tx.lock().await;
            let now = Instant::now();
            let rto = st.rto;
            for u in st.unacked.values_mut() {
                if now.duration_since(u.sent_at) >= rto {
                    resend.push(u.ct.clone());
                    u.sent_at = now;
                }
            }
            if !resend.is_empty() {
                st.cwnd = (st.cwnd / 2.0).max(1.0);
                st.rto = (st.rto * 2).min(RTO_MAX);
            }
        }
        for ct in resend {
            let _ = inner.sock.send_to(&ct, inner.peer).await;
        }
    }
    do_close(&inner, false).await;
}

async fn do_close(inner: &Inner, send_fin: bool) {
    if *inner.closed_tx.borrow() {
        return;
    }
    if send_fin {
        if let Ok(ct) = inner.sess.seal(&pad_inner(&[T_FIN])) {
            let _ = inner.sock.send_to(&ct, inner.peer).await;
        }
    }
    let _ = inner.closed_tx.send(true);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回环: Endpoint connect/accept + 200 条随机长度消息保序完整
    #[tokio::test]
    async fn rudp_endpoint_stream() {
        let ns = NetworkSecret::generate();
        let (_, id_s) = yz_crypto::generate_identity().unwrap();
        let (_, id_c) = yz_crypto::generate_identity().unwrap();

        let ep_s = Endpoint::bind(
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            &ns,
            id_s,
        )
        .await
        .unwrap();
        let ep_c = Endpoint::bind(
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            &ns,
            id_c,
        )
        .await
        .unwrap();
        let addr_s = ep_s.local_addr().unwrap();

        let (client, _) = ep_c.connect(addr_s, &ns, &id_c).await.unwrap();
        let (server, _) = ep_s.accept().await.unwrap();

        tokio::spawn(async move {
            while let Ok(m) = server.recv().await {
                if server.send(&m).await.is_err() {
                    break;
                }
            }
        });

        let mut want = Vec::new();
        let mut msgs = vec![];
        for i in 0..200usize {
            let size = (i * 37) % 9000 + 1;
            let m: Vec<u8> = (0..size).map(|j| ((i + j) % 251) as u8).collect();
            want.extend_from_slice(&m);
            msgs.push(m);
        }

        let client = Arc::new(client);
        let c2 = client.clone();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            while got.len() < want.len() {
                got.extend_from_slice(&c2.recv().await.unwrap());
            }
            assert_eq!(got, want);
        });
        for m in msgs {
            client.send(&m).await.unwrap();
        }
        timeout(Duration::from_secs(30), reader).await.unwrap().unwrap();
    }

    /// 打洞: 双方互射 PUNCH 后 connect/accept 成功
    #[tokio::test]
    async fn punch_loopback() {
        let ns = NetworkSecret::generate();
        let (_, id_a) = yz_crypto::generate_identity().unwrap();
        let (_, id_b) = yz_crypto::generate_identity().unwrap();
        let ep_a = Endpoint::bind(UdpSocket::bind("127.0.0.1:0").await.unwrap(), &ns, id_a)
            .await
            .unwrap();
        let ep_b = Endpoint::bind(UdpSocket::bind("127.0.0.1:0").await.unwrap(), &ns, id_b)
            .await
            .unwrap();
        let addr_a = ep_a.local_addr().unwrap();
        let addr_b = ep_b.local_addr().unwrap();

        // B 被叫: 散射 + 等 accept
        let ep_b2 = ep_b; // 占位清晰
        let b_task = tokio::spawn(async move {
            let _ = ep_b2.punch(&[addr_a], Duration::from_secs(4)).await;
            ep_b2.accept().await
        });
        // A 主叫: 打洞 + connect
        let punched = ep_a
            .punch(&[addr_b], Duration::from_secs(4))
            .await
            .unwrap();
        let (ra, _) = ep_a.connect(punched, &ns, &id_a).await.unwrap();
        let (rb, _) = timeout(Duration::from_secs(5), b_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        ra.send(b"p2p hello").await.unwrap();
        let got = timeout(Duration::from_secs(3), rb.recv()).await.unwrap().unwrap();
        assert_eq!(got, b"p2p hello");
    }

    /// probe: responder 回复观察地址
    #[tokio::test]
    async fn probe_observed_addr() {
        let ns = NetworkSecret::generate();
        let (_, id) = yz_crypto::generate_identity().unwrap();
        let resp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resp_addr = resp_sock.local_addr().unwrap();
        spawn_probe_responder(resp_sock, StaticKey::derive(&ns, PROBE_SALT).unwrap());

        let ep = Endpoint::bind(UdpSocket::bind("127.0.0.1:0").await.unwrap(), &ns, id)
            .await
            .unwrap();
        let observed = ep.probe_via(resp_addr).await.unwrap();
        assert_eq!(observed, ep.local_addr().unwrap());
    }

    /// 错误 NS 的握手报文被静默忽略
    #[tokio::test]
    async fn bad_handshake_ignored() {
        let ns = NetworkSecret::generate();
        let ns_bad = NetworkSecret::generate();
        let (_, id_s) = yz_crypto::generate_identity().unwrap();
        let (_, id_c) = yz_crypto::generate_identity().unwrap();

        let ep_s = Endpoint::bind(UdpSocket::bind("127.0.0.1:0").await.unwrap(), &ns, id_s)
            .await
            .unwrap();
        let ep_c = Endpoint::bind(UdpSocket::bind("127.0.0.1:0").await.unwrap(), &ns_bad, id_c)
            .await
            .unwrap();
        let r = ep_c.connect(ep_s.local_addr().unwrap(), &ns_bad, &id_c).await;
        assert!(r.is_err());
        assert!(timeout(Duration::from_millis(200), ep_s.accept()).await.is_err());
    }
}
