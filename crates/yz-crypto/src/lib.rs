//! YZP 加密层（plan.md §3.1-3.3）：
//! 网络密钥 NS、节点身份(Ed25519)、双向认证握手(X25519+NS)、AEAD 会话(ChaCha20-Poly1305)。
//! 密码学原语全部来自 ring, 协议自研。

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::digest;
use ring::hkdf::{self, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MSG1_LEN: usize = 32 + 12 + 56 + 16; // 116
pub const MSG2_LEN: usize = 32 + 12 + 64 + 16; // 124
/// 握手时间戳容忍窗口
const TS_WINDOW_SECS: u64 = 120;

const HS1_SALT: &[u8] = b"yz-hs1-v1";
const HS2_SALT: &[u8] = b"yz-hs2-v1";

#[derive(Debug)]
pub enum Error {
    Crypto,
    BadMessage,
    /// 对端无法证明持有 NS / 回显校验失败
    Auth,
    /// 时间戳超窗
    Stale,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Crypto => write!(f, "crypto error"),
            Error::BadMessage => write!(f, "malformed handshake message"),
            Error::Auth => write!(f, "authentication failed"),
            Error::Stale => write!(f, "handshake timestamp out of window"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::Crypto
    }
}

impl From<ring::error::KeyRejected> for Error {
    fn from(_: ring::error::KeyRejected) -> Self {
        Error::Crypto
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ---------- 网络密钥 ----------

#[derive(Clone)]
pub struct NetworkSecret([u8; 32]);

impl NetworkSecret {
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let mut s = [0u8; 32];
        rng.fill(&mut s).expect("rng");
        Self(s)
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let b = from_hex(s)?;
        let arr: [u8; 32] = b.try_into().map_err(|_| Error::BadMessage)?;
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

// ---------- 节点身份 ----------

/// 生成 Ed25519 身份, 返回 (pkcs8 持久化字节, id_pub)
pub fn generate_identity() -> Result<(Vec<u8>, [u8; 32])> {
    let rng = SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng)?;
    let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref())?;
    let mut id_pub = [0u8; 32];
    id_pub.copy_from_slice(kp.public_key().as_ref());
    Ok((doc.as_ref().to_vec(), id_pub))
}

pub fn load_identity(pkcs8: &[u8]) -> Result<[u8; 32]> {
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8)?;
    let mut id_pub = [0u8; 32];
    id_pub.copy_from_slice(kp.public_key().as_ref());
    Ok(id_pub)
}

pub fn node_id(id_pub: &[u8; 32]) -> String {
    let h = digest::digest(&digest::SHA256, id_pub);
    to_hex(&h.as_ref()[..8])
}

// ---------- 握手 ----------

pub struct PeerInfo {
    pub id_pub: [u8; 32],
}

impl PeerInfo {
    pub fn node_id(&self) -> String {
        node_id(&self.id_pub)
    }
}

/// 会话角色: 决定使用双向密钥的方向
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Initiator,
    Responder,
}

/// 握手产出的原始密钥材料
pub struct SessionKeys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
    pub mask: [u8; 16],
}

pub struct InitiatorState {
    eph: Option<EphemeralPrivateKey>,
    nonce_i: [u8; 16],
    msg1: Vec<u8>,
}

/// 发起方: 生成 msg1
pub fn handshake_init(ns: &NetworkSecret, id_pub: &[u8; 32]) -> Result<(Vec<u8>, InitiatorState)> {
    let rng = SystemRandom::new();
    let eph = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let pub_key = eph.compute_public_key()?;
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(pub_key.as_ref());

    let mut nonce_hs = [0u8; 12];
    rng.fill(&mut nonce_hs)?;
    let mut nonce_i = [0u8; 16];
    rng.fill(&mut nonce_i)?;

    let mut plain = Vec::with_capacity(56);
    plain.extend_from_slice(id_pub);
    plain.extend_from_slice(&now_secs().to_be_bytes());
    plain.extend_from_slice(&nonce_i);

    let key = hs_key(ns, HS1_SALT)?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_hs),
        Aad::from(&eph_pub),
        &mut plain,
    )?;

    let mut msg1 = Vec::with_capacity(MSG1_LEN);
    msg1.extend_from_slice(&eph_pub);
    msg1.extend_from_slice(&nonce_hs);
    msg1.extend_from_slice(&plain);
    debug_assert_eq!(msg1.len(), MSG1_LEN);

    Ok((
        msg1.clone(),
        InitiatorState {
            eph: Some(eph),
            nonce_i,
            msg1,
        },
    ))
}

/// 发起方: 处理 msg2, 产出会话密钥
pub fn handshake_finish(
    ns: &NetworkSecret,
    mut st: InitiatorState,
    msg2: &[u8],
) -> Result<(SessionKeys, PeerInfo)> {
    if msg2.len() != MSG2_LEN {
        return Err(Error::BadMessage);
    }
    let eph_pub_r: [u8; 32] = msg2[..32].try_into().unwrap();
    let nonce_hs: [u8; 12] = msg2[32..44].try_into().unwrap();
    let mut ct = msg2[44..].to_vec();

    let key = hs_key(ns, HS2_SALT)?;
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_hs),
            Aad::from(&st.msg1),
            &mut ct,
        )
        .map_err(|_| Error::Auth)?;
    if plain.len() != 64 {
        return Err(Error::BadMessage);
    }
    // nonce_i 回显校验
    if plain[48..64] != st.nonce_i {
        return Err(Error::Auth);
    }
    let id_pub_r: [u8; 32] = plain[..32].try_into().unwrap();

    let eph = st.eph.take().ok_or(Error::BadMessage)?;
    let peer_pub = UnparsedPublicKey::new(&X25519, &eph_pub_r);
    let msg1 = st.msg1.clone();
    let material = agreement::agree_ephemeral(eph, &peer_pub, |shared| {
        derive_session(shared, &msg1, msg2)
    })?;
    let (c2s, s2c, mask) = material?;
    Ok((
        SessionKeys { c2s, s2c, mask },
        PeerInfo { id_pub: id_pub_r },
    ))
}

/// 响应方: 处理 msg1, 产出 msg2 与会话密钥
pub fn handshake_accept(
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    msg1: &[u8],
) -> Result<(Vec<u8>, SessionKeys, PeerInfo)> {
    if msg1.len() != MSG1_LEN {
        return Err(Error::BadMessage);
    }
    let eph_pub_i: [u8; 32] = msg1[..32].try_into().unwrap();
    let nonce_hs_i: [u8; 12] = msg1[32..44].try_into().unwrap();
    let mut ct = msg1[44..].to_vec();

    let key = hs_key(ns, HS1_SALT)?;
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_hs_i),
            Aad::from(&eph_pub_i),
            &mut ct,
        )
        .map_err(|_| Error::Auth)?;
    if plain.len() != 56 {
        return Err(Error::BadMessage);
    }
    let id_pub_i: [u8; 32] = plain[..32].try_into().unwrap();
    let ts = u64::from_be_bytes(plain[32..40].try_into().unwrap());
    if now_secs().abs_diff(ts) > TS_WINDOW_SECS {
        return Err(Error::Stale);
    }
    let nonce_i: [u8; 16] = plain[40..56].try_into().unwrap();

    // 构造 msg2
    let rng = SystemRandom::new();
    let eph = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let pub_key = eph.compute_public_key()?;
    let mut eph_pub_r = [0u8; 32];
    eph_pub_r.copy_from_slice(pub_key.as_ref());
    let mut nonce_hs_r = [0u8; 12];
    rng.fill(&mut nonce_hs_r)?;
    let mut nonce_r = [0u8; 16];
    rng.fill(&mut nonce_r)?;

    let mut plain2 = Vec::with_capacity(64);
    plain2.extend_from_slice(id_pub);
    plain2.extend_from_slice(&nonce_r);
    plain2.extend_from_slice(&nonce_i);

    let key2 = hs_key(ns, HS2_SALT)?;
    key2.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_hs_r),
        Aad::from(&msg1[..]),
        &mut plain2,
    )?;

    let mut msg2 = Vec::with_capacity(MSG2_LEN);
    msg2.extend_from_slice(&eph_pub_r);
    msg2.extend_from_slice(&nonce_hs_r);
    msg2.extend_from_slice(&plain2);
    debug_assert_eq!(msg2.len(), MSG2_LEN);

    let peer_pub = UnparsedPublicKey::new(&X25519, &eph_pub_i);
    let msg2_ref = msg2.clone();
    let material = agreement::agree_ephemeral(eph, &peer_pub, |shared| {
        derive_session(shared, msg1, &msg2_ref)
    })?;
    let (c2s, s2c, mask) = material?;
    Ok((
        msg2,
        SessionKeys { c2s, s2c, mask },
        PeerInfo { id_pub: id_pub_i },
    ))
}

fn hs_key(ns: &NetworkSecret, salt: &[u8]) -> Result<LessSafeKey> {
    let prk = hkdf::Salt::new(HKDF_SHA256, salt).extract(&ns.0);
    let okm = prk.expand(&[b"hs"], OkmLen(32))?;
    let mut kb = [0u8; 32];
    okm.fill(&mut kb)?;
    let uk = UnboundKey::new(&CHACHA20_POLY1305, &kb)?;
    Ok(LessSafeKey::new(uk))
}

struct OkmLen(usize);
impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

type SessionMaterial = ([u8; 32], [u8; 32], [u8; 16]);

fn derive_session(
    shared: &[u8],
    msg1: &[u8],
    msg2: &[u8],
) -> std::result::Result<SessionMaterial, ring::error::Unspecified> {
    let mut t = Vec::with_capacity(msg1.len() + msg2.len());
    t.extend_from_slice(msg1);
    t.extend_from_slice(msg2);
    let th = digest::digest(&digest::SHA256, &t);
    let prk = hkdf::Salt::new(HKDF_SHA256, th.as_ref()).extract(shared);
    let mut k_c2s = [0u8; 32];
    prk.expand(&[b"yz session c2s"], OkmLen(32))?.fill(&mut k_c2s)?;
    let mut k_s2c = [0u8; 32];
    prk.expand(&[b"yz session s2c"], OkmLen(32))?.fill(&mut k_s2c)?;
    let mut mask = [0u8; 16];
    prk.expand(&[b"yz len mask"], OkmLen(16))?.fill(&mut mask)?;
    Ok((k_c2s, k_s2c, mask))
}

// ---------- 会话 ----------

/// 单会话: packet = masked_len(2) | AEAD(frame)+tag(16)
pub struct Session {
    send_key: LessSafeKey,
    recv_key: LessSafeKey,
    mask: [u8; 16],
    send_ctr: u64,
    recv_ctr: u64,
}

impl Session {
    fn new(send: [u8; 32], recv: [u8; 32], mask: [u8; 16]) -> Self {
        let mk = |b: &[u8; 32]| {
            LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, b).expect("32-byte key"))
        };
        Self {
            send_key: mk(&send),
            recv_key: mk(&recv),
            mask,
            send_ctr: 0,
            recv_ctr: 0,
        }
    }

    pub fn from_keys(k: &SessionKeys, role: Role) -> Self {
        match role {
            Role::Initiator => Self::new(k.c2s, k.s2c, k.mask),
            Role::Responder => Self::new(k.s2c, k.c2s, k.mask),
        }
    }

    /// 加密一帧, 输出完整 packet
    pub fn seal(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let mut buf = frame.to_vec();
        self.send_key.seal_in_place_append_tag(
            nonce_of(self.send_ctr),
            Aad::empty(),
            &mut buf,
        )?;
        let len = buf.len() as u16;
        let masked = len ^ self.mask_word(self.send_ctr);
        self.send_ctr += 1;
        let mut out = Vec::with_capacity(2 + buf.len());
        out.extend_from_slice(&masked.to_be_bytes());
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// 用接收计数器解掩长度（在 read_exact 密文之前调用）
    pub fn unmask_len(&self, masked: u16) -> usize {
        (masked ^ self.mask_word(self.recv_ctr)) as usize
    }

    /// 解密一个包, 返回帧明文
    pub fn open(&mut self, _masked: u16, ct: &mut [u8]) -> Result<Vec<u8>> {
        let plain = self
            .recv_key
            .open_in_place(nonce_of(self.recv_ctr), Aad::empty(), ct)
            .map_err(|_| Error::Auth)?;
        self.recv_ctr += 1;
        Ok(plain.to_vec())
    }

    fn mask_word(&self, ctr: u64) -> u16 {
        let i = (ctr % 15) as usize;
        u16::from_be_bytes([self.mask[i], self.mask[i + 1]])
    }
}

fn nonce_of(ctr: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

/// UDP 数据报会话: 每报文随机 nonce, 报文自带长度边界, 无需掩码长度
pub struct DgramSession {
    send_key: LessSafeKey,
    recv_key: LessSafeKey,
}

impl DgramSession {
    pub fn from_keys(k: &SessionKeys, role: Role) -> Self {
        let (send, recv) = match role {
            Role::Initiator => (&k.c2s, &k.s2c),
            Role::Responder => (&k.s2c, &k.c2s),
        };
        let mk = |b: &[u8; 32]| {
            LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, b).expect("32-byte key"))
        };
        Self {
            send_key: mk(send),
            recv_key: mk(recv),
        }
    }

    /// nonce(12) | ct+tag
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        dgram_seal(&self.send_key, plaintext)
    }

    pub fn open(&self, dgram: &[u8]) -> Result<Vec<u8>> {
        dgram_open(&self.recv_key, dgram)
    }
}

fn dgram_seal(key: &LessSafeKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)?;
    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::empty(),
        &mut buf,
    )?;
    let mut out = Vec::with_capacity(12 + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

fn dgram_open(key: &LessSafeKey, dgram: &[u8]) -> Result<Vec<u8>> {
    if dgram.len() < 12 + 16 {
        return Err(Error::BadMessage);
    }
    let nonce: [u8; 12] = dgram[..12].try_into().unwrap();
    let mut ct = dgram[12..].to_vec();
    let plain = key
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut ct)
        .map_err(|_| Error::Auth)?;
    Ok(plain.to_vec())
}

/// NS 派生的静态密钥: 用于 NAT 探测/打洞等会话前带外小包, 只有网络成员可解码
pub struct StaticKey(LessSafeKey);

impl StaticKey {
    pub fn derive(ns: &NetworkSecret, salt: &[u8]) -> Result<Self> {
        Ok(Self(hs_key(ns, salt)?))
    }

    pub fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        dgram_seal(&self.0, plain)
    }

    pub fn open(&self, dgram: &[u8]) -> Result<Vec<u8>> {
        dgram_open(&self.0, dgram)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------- hex ----------

pub fn to_hex(b: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(T[(x >> 4) as usize] as char);
        s.push(T[(x & 0xf) as usize] as char);
    }
    s
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(Error::BadMessage);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::BadMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (NetworkSecret, [u8; 32], [u8; 32]) {
        let ns = NetworkSecret::generate();
        let (_, id_a) = generate_identity().unwrap();
        let (_, id_b) = generate_identity().unwrap();
        (ns, id_a, id_b)
    }

    #[test]
    fn handshake_and_session() {
        let (ns, id_a, id_b) = pair();
        let (msg1, st) = handshake_init(&ns, &id_a).unwrap();
        assert_eq!(msg1.len(), MSG1_LEN);

        let (msg2, keys_r, peer_r) = handshake_accept(&ns, &id_b, &msg1).unwrap();
        assert_eq!(msg2.len(), MSG2_LEN);
        assert_eq!(peer_r.node_id(), node_id(&id_a));

        let (keys_i, peer_i) = handshake_finish(&ns, st, &msg2).unwrap();
        assert_eq!(peer_i.node_id(), node_id(&id_b));

        let mut sess_i = Session::from_keys(&keys_i, Role::Initiator);
        let mut sess_r = Session::from_keys(&keys_r, Role::Responder);

        // i -> r
        let pkt = sess_i.seal(b"\x03\x00\x00\x00\x01hi").unwrap();
        let masked = u16::from_be_bytes([pkt[0], pkt[1]]);
        let len = sess_r.unmask_len(masked);
        assert_eq!(len, pkt.len() - 2);
        let mut ct = pkt[2..].to_vec();
        let frame = sess_r.open(masked, &mut ct).unwrap();
        assert_eq!(frame, b"\x03\x00\x00\x00\x01hi");

        // r -> i
        let pkt2 = sess_r.seal(b"pong").unwrap();
        let masked2 = u16::from_be_bytes([pkt2[0], pkt2[1]]);
        let mut ct2 = pkt2[2..].to_vec();
        let frame2 = sess_i.open(masked2, &mut ct2).unwrap();
        assert_eq!(frame2, b"pong");

        // 多包计数器递增
        for _ in 0..100 {
            let p = sess_i.seal(b"x").unwrap();
            let m = u16::from_be_bytes([p[0], p[1]]);
            let mut c = p[2..].to_vec();
            sess_r.open(m, &mut c).unwrap();
        }

        // UDP 数据报会话
        let d_i = DgramSession::from_keys(&keys_i, Role::Initiator);
        let d_r = DgramSession::from_keys(&keys_r, Role::Responder);
        let d = d_i.seal(b"udp hello").unwrap();
        assert_eq!(d_r.open(&d).unwrap(), b"udp hello");
        let d2 = d_r.seal(b"udp pong").unwrap();
        assert_eq!(d_i.open(&d2).unwrap(), b"udp pong");
    }

    #[test]
    fn wrong_network_secret_rejected() {
        let (ns, id_a, _) = pair();
        let ns_bad = NetworkSecret::generate();
        let (_, id_b) = generate_identity().unwrap();
        let (msg1, _st) = handshake_init(&ns, &id_a).unwrap();
        assert!(matches!(
            handshake_accept(&ns_bad, &id_b, &msg1),
            Err(Error::Auth)
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (ns, id_a, id_b) = pair();
        let (msg1, st) = handshake_init(&ns, &id_a).unwrap();
        let (msg2, keys_r, _) = handshake_accept(&ns, &id_b, &msg1).unwrap();
        let (keys_i, _) = handshake_finish(&ns, st, &msg2).unwrap();
        let mut sess_i = Session::from_keys(&keys_i, Role::Initiator);
        let mut sess_r = Session::from_keys(&keys_r, Role::Responder);
        let mut pkt = sess_i.seal(b"data").unwrap();
        let last = pkt.len() - 1;
        pkt[last] ^= 1;
        let masked = u16::from_be_bytes([pkt[0], pkt[1]]);
        let mut ct = pkt[2..].to_vec();
        assert!(matches!(sess_r.open(masked, &mut ct), Err(Error::Auth)));
    }

    #[test]
    fn hex_roundtrip() {
        let ns = NetworkSecret::generate();
        let h = ns.to_hex();
        let ns2 = NetworkSecret::from_hex(&h).unwrap();
        assert_eq!(ns.to_hex(), ns2.to_hex());
    }
}
