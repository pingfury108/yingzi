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
#[derive(Clone, Copy)]
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
    /// 上一代接收密钥 (换钥瞬间的在途包仍能解开; 与当前密钥共用同一计数器)
    prev_recv_key: Option<LessSafeKey>,
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
            prev_recv_key: None,
            mask,
            send_ctr: 0,
            recv_ctr: 0,
        }
    }

    /// 轮换会话密钥 (计数器只增不减; mask 在握手后保持不变)
    pub fn set_keys(&mut self, k: &SessionKeys, role: Role) {
        self.set_recv_keys(k, role);
        self.set_send_keys(k, role);
        // 注意: 不更新 mask —— 换钥时 mask 必须两侧一致且终身不变,
        // 否则长度掩码解错会导致 TCP 字节流错位(连接永久损坏)
    }

    /// 只切接收方向 (保留上一代, 兼容在途旧包)
    pub fn set_recv_keys(&mut self, k: &SessionKeys, role: Role) {
        let r = match role {
            Role::Initiator => &k.s2c,
            Role::Responder => &k.c2s,
        };
        let mk = |b: &[u8; 32]| {
            LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, b).expect("32-byte key"))
        };
        self.prev_recv_key = Some(std::mem::replace(&mut self.recv_key, mk(r)));
        // 注意: 不改 mask、不重置 recv_ctr、也不单独记 prev 计数器 ——
        // 收发方向各只有一个单调计数器, 新旧密钥共用同一 nonce 序列, 否则换钥后无法对齐
    }

    /// 只切发送方向
    pub fn set_send_keys(&mut self, k: &SessionKeys, role: Role) {
        let s = match role {
            Role::Initiator => &k.c2s,
            Role::Responder => &k.s2c,
        };
        let mk = |b: &[u8; 32]| {
            LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, b).expect("32-byte key"))
        };
        self.send_key = mk(s);
        // send_ctr 继续累加 (计数器只增不减)
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

    /// (recv_ctr, 是否有prev) —— 诊断用
    pub fn ctr_info(&self) -> (u64, bool) {
        (self.recv_ctr, self.prev_recv_key.is_some())
    }

    /// 用接收计数器解掩长度（在 read_exact 密文之前调用）
    pub fn unmask_len(&self, masked: u16) -> usize {
        (masked ^ self.mask_word(self.recv_ctr)) as usize
    }

    /// 解密一个包, 返回帧明文
    ///
    /// 注意: ring 的 `open_in_place` 认证失败时会就地覆写缓冲区,
    /// 因此重试上一代密钥前必须保留未受污染的原始密文。
    pub fn open(&mut self, _masked: u16, ct: &mut [u8]) -> Result<Vec<u8>> {
        let pristine = self.prev_recv_key.is_some().then(|| ct.to_vec());
        if let Ok(plain) =
            self.recv_key
                .open_in_place(nonce_of(self.recv_ctr), Aad::empty(), ct)
        {
            self.recv_ctr += 1;
            return Ok(plain.to_vec());
        }
        // 换钥瞬间的在途包: 用上一代密钥 + 原始密文 + 同一计数器
        if let (Some(prev), Some(mut buf)) = (&self.prev_recv_key, pristine) {
            if let Ok(plain) =
                prev.open_in_place(nonce_of(self.recv_ctr), Aad::empty(), &mut buf)
            {
                self.recv_ctr += 1;
                return Ok(plain.to_vec());
            }
        }
        Err(Error::Auth)
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
    prev_recv_key: Option<LessSafeKey>,
    /// 收发方向各自密钥指纹 (诊断)
    fp_send: String,
    fp_recv: String,
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
            prev_recv_key: None,
            fp_send: key_fingerprint(k),
            fp_recv: key_fingerprint(k),
        }
    }

    pub fn set_keys(&mut self, k: &SessionKeys, role: Role) {
        self.set_recv_keys(k, role);
        self.set_send_keys(k, role);
    }

    /// (send_fp, recv_fp) —— 诊断
    pub fn fingerprints(&self) -> (&str, &str) {
        (&self.fp_send, &self.fp_recv)
    }

    pub fn set_recv_keys(&mut self, k: &SessionKeys, role: Role) {
        let r = match role {
            Role::Initiator => &k.s2c,
            Role::Responder => &k.c2s,
        };
        let mk = |b: &[u8; 32]| {
            LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, b).expect("32-byte key"))
        };
        self.prev_recv_key = Some(std::mem::replace(&mut self.recv_key, mk(r)));
        self.fp_recv = key_fingerprint(k);
    }

    pub fn set_send_keys(&mut self, k: &SessionKeys, role: Role) {
        let s = match role {
            Role::Initiator => &k.c2s,
            Role::Responder => &k.s2c,
        };
        let mk = |b: &[u8; 32]| {
            LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, b).expect("32-byte key"))
        };
        self.send_key = mk(s);
        self.fp_send = key_fingerprint(k);
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

/// 密钥指纹 (诊断: 两侧比对是否派生出一致的会话密钥)
pub fn key_fingerprint(k: &SessionKeys) -> String {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&k.c2s);
    buf.extend_from_slice(&k.s2c);
    let d = digest::digest(&digest::SHA256, &buf);
    to_hex(&d.as_ref()[..4])
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

/// 密码学安全随机字节
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    SystemRandom::new().fill(&mut v).expect("rng");
    v
}

/// SHA1 (仅用于 WebSocket 协议要求的 accept 密钥)
pub fn sha1(data: &[u8]) -> [u8; 20] {
    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .try_into()
        .expect("sha1 is 20 bytes")
}

// ---------- 握手线格式 (抗指纹: 长度随机化) ----------

const HS_PAD_MIN: usize = 32;
const HS_PAD_MAX: usize = 160; // 不含
/// UDP 侧握手报文最大长度
pub const HS_WIRE_MAX: usize = HS_PAD_MAX + MSG2_LEN + 16;

/// 通用包装 (UDP): rand_pad || core —— 消除固定尺寸特征, 对端取尾部 core_len
pub fn wrap_hs(core: &[u8]) -> Vec<u8> {
    let pad_len = HS_PAD_MIN + random_bytes(1)[0] as usize % (HS_PAD_MAX - HS_PAD_MIN);
    let mut out = random_bytes(pad_len);
    out.extend_from_slice(core);
    out
}

/// TCP 长度掩码: NS 派生, 只有网络成员能解出报文边界
pub fn hs_len_mask(ns: &NetworkSecret) -> Result<u16> {
    let prk = hkdf::Salt::new(HKDF_SHA256, b"yz-hs-len-v1").extract(&ns.0);
    let okm = prk.expand(&[b"m"], OkmLen(2))?;
    let mut b = [0u8; 2];
    okm.fill(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

/// TCP 包装: masked_len(2) | rand_pad | core
pub fn wrap_hs_stream(ns: &NetworkSecret, core: &[u8]) -> Result<Vec<u8>> {
    let body = wrap_hs(core);
    let masked = (body.len() as u16) ^ hs_len_mask(ns)?;
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&masked.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// TCP 读侧: masked -> body 长度
pub fn unwrap_hs_len(ns: &NetworkSecret, masked: u16) -> Result<usize> {
    Ok((masked ^ hs_len_mask(ns)?) as usize)
}

// ---------- 密钥轮换 (rekey) ----------

/// 轮换态: 本端临时公钥报文 (eph_pub(32) || nonce(16))
pub struct RekeyState {
    eph: Option<EphemeralPrivateKey>,
    wire: Vec<u8>,
}

pub const REKEY_WIRE_LEN: usize = 48;

/// 生成本端 rekey 报文
pub fn rekey_init() -> Result<(Vec<u8>, RekeyState)> {
    let rng = SystemRandom::new();
    let eph = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let pk = eph.compute_public_key()?;
    let mut wire = pk.as_ref().to_vec();
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce)?;
    wire.extend_from_slice(&nonce);
    Ok((
        wire.clone(),
        RekeyState {
            eph: Some(eph),
            wire,
        },
    ))
}

/// 发起方: 收到对端报文后派生新密钥 (transcript = 我方 || 对方)
pub fn rekey_finish(mut st: RekeyState, peer_wire: &[u8], role: Role) -> Result<SessionKeys> {
    if peer_wire.len() != REKEY_WIRE_LEN {
        return Err(Error::BadMessage);
    }
    let peer_pub = UnparsedPublicKey::new(&X25519, &peer_wire[..32]);
    let eph = st.eph.take().ok_or(Error::BadMessage)?;
    let mine = st.wire.clone();
    let material = agreement::agree_ephemeral(eph, &peer_pub, |shared| {
        derive_session(shared, &mine, peer_wire)
    })?;
    let (c2s, s2c, mask) = material?;
    let _ = role;
    Ok(SessionKeys { c2s, s2c, mask })
}

/// 响应方: 收到对端报文后生成本端报文并派生密钥 (transcript = 对方 || 我方)
pub fn rekey_respond(st: RekeyState, peer_wire: &[u8]) -> Result<(Vec<u8>, SessionKeys)> {
    if peer_wire.len() != REKEY_WIRE_LEN {
        return Err(Error::BadMessage);
    }
    let (mine, st2) = (st.wire.clone(), st);
    let peer_pub = UnparsedPublicKey::new(&X25519, &peer_wire[..32]);
    let eph = st2.eph.ok_or(Error::BadMessage)?;
    let material = agreement::agree_ephemeral(eph, &peer_pub, |shared| {
        derive_session(shared, peer_wire, &mine)
    })?;
    let (c2s, s2c, mask) = material?;
    Ok((mine, SessionKeys { c2s, s2c, mask }))
}

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
    fn hs_wrap_randomized() {
        let (ns, _, _) = pair();
        let core = [7u8; MSG1_LEN];
        let a = wrap_hs_stream(&ns, &core).unwrap();
        let b = wrap_hs_stream(&ns, &core).unwrap();
        // 同一 core 两次包装, 线格式不同且长度随机
        assert_ne!(a, b);
        let masked_a = u16::from_be_bytes([a[0], a[1]]);
        let masked_b = u16::from_be_bytes([b[0], b[1]]);
        let la = unwrap_hs_len(&ns, masked_a).unwrap();
        let lb = unwrap_hs_len(&ns, masked_b).unwrap();
        assert_eq!(la, a.len() - 2);
        assert_eq!(lb, b.len() - 2);
        // core 在尾部
        assert_eq!(&a[a.len() - MSG1_LEN..], &core);
        // 非成员解出的长度无意义
        let ns_bad = NetworkSecret::generate();
        assert_ne!(unwrap_hs_len(&ns_bad, masked_a).unwrap(), la);
    }

    #[test]
    fn hex_roundtrip() {
        let ns = NetworkSecret::generate();
        let h = ns.to_hex();
        let ns2 = NetworkSecret::from_hex(&h).unwrap();
        assert_eq!(ns.to_hex(), ns2.to_hex());
    }
}

#[cfg(test)]
mod rekey_tests {
    use super::*;

    #[test]
    fn rekey_both_sides_agree() {
        for role_pair in [(Role::Initiator, Role::Responder)] {
            let (wi, st_i) = rekey_init().unwrap();
            let (wr, st_r) = rekey_init().unwrap();
            let keys_r = rekey_respond(st_r, &wi).unwrap().1;
            let keys_i = rekey_finish(st_i, &wr, role_pair.0).unwrap();
            // 双方 c2s/s2c 必须一致
            assert_eq!(keys_i.c2s, keys_r.c2s);
            assert_eq!(keys_i.s2c, keys_r.s2c);
            assert_eq!(keys_i.mask, keys_r.mask);
            // 换钥后仍能互通
            let mut a = Session::from_keys(&keys_i, Role::Initiator);
            let mut b = Session::from_keys(&keys_r, Role::Responder);
            let pkt = a.seal(b"after rekey").unwrap();
            let masked = u16::from_be_bytes([pkt[0], pkt[1]]);
            let mut ct = pkt[2..].to_vec();
            assert_eq!(b.open(masked, &mut ct).unwrap(), b"after rekey");
        }
    }

    #[test]
    fn set_keys_switches_session() {
        let (ns, id_a, id_b) = {
            let ns = NetworkSecret::generate();
            let (_, a) = generate_identity().unwrap();
            let (_, b) = generate_identity().unwrap();
            (ns, a, b)
        };
        let (msg1, st) = handshake_init(&ns, &id_a).unwrap();
        let (msg2, keys_r, _) = handshake_accept(&ns, &id_b, &msg1).unwrap();
        let (keys_i, _) = handshake_finish(&ns, st, &msg2).unwrap();
        let mut sa = Session::from_keys(&keys_i, Role::Initiator);
        let mut sb = Session::from_keys(&keys_r, Role::Responder);
        // 计数器连续: 换钥前先把旧钥帧正常交付
        let p0 = sa.seal(b"old").unwrap();
        let m0 = u16::from_be_bytes([p0[0], p0[1]]);
        let mut c0 = p0[2..].to_vec();
        assert_eq!(sb.open(m0, &mut c0).unwrap(), b"old");
        // 触发轮换
        let (wi, si) = rekey_init().unwrap();
        let (wr, sr) = rekey_init().unwrap();
        let new_r = rekey_respond(sr, &wi).unwrap().1;
        let new_i = rekey_finish(si, &wr, Role::Initiator).unwrap();
        sa.set_keys(&new_i, Role::Initiator);
        sb.set_keys(&new_r, Role::Responder);
        let pkt = sa.seal(b"new key").unwrap();
        let masked = u16::from_be_bytes([pkt[0], pkt[1]]);
        let mut ct = pkt[2..].to_vec();
        assert_eq!(sb.open(masked, &mut ct).unwrap(), b"new key");
    }
}

#[cfg(test)]
mod rekey_switch_tests {
    use super::*;

    /// 模拟不对称切换: 响应方先切收钥, 延迟切发钥; 发起方收到 ack 后立即双切。
    /// 断言: 切换窗口内两个方向的在途旧钥帧都能被解开, 且计数器连续。
    #[test]
    fn asymmetric_switch_keeps_inflight_frames() {
        let ns = NetworkSecret::generate();
        let (_, id_a) = generate_identity().unwrap();
        let (_, id_b) = generate_identity().unwrap();
        let (msg1, st) = handshake_init(&ns, &id_a).unwrap();
        let (msg2, keys_r, _) = handshake_accept(&ns, &id_b, &msg1).unwrap();
        let (keys_i, _) = handshake_finish(&ns, st, &msg2).unwrap();
        // a = 发起方(链路 Initiator), b = 响应方(链路 Responder)
        let mut a = Session::from_keys(&keys_i, Role::Initiator);
        let mut b = Session::from_keys(&keys_r, Role::Responder);

        // 若干正常帧
        for _ in 0..5 {
            let p = a.seal(b"hello").unwrap();
            let m = u16::from_be_bytes([p[0], p[1]]);
            let mut ct = p[2..].to_vec();
            assert_eq!(b.open(m, &mut ct).unwrap(), b"hello");
        }

        // rekey: a 发起, b 响应
        let (wi, si) = rekey_init().unwrap();
        let (wr, sr) = rekey_init().unwrap();
        let (ack_wire, keys_b) = rekey_respond(sr, &wi).unwrap();
        let keys_a = rekey_finish(si, &wr, Role::Initiator).unwrap();
        let _ = (&ack_wire, &wr);
        assert_eq!(key_fingerprint(&keys_a), key_fingerprint(&keys_b));

        // 1) b(响应方) 立即切收钥
        b.set_recv_keys(&keys_b, Role::Responder);
        // 2) a(发起方) 收到 ack 后双切
        a.set_keys(&keys_a, Role::Initiator);
        // 3) b 仍在宽限期用旧钥发送 (在途帧)
        let inflight_from_b = b.seal(b"inflight-old").unwrap();
        // 4) a 用新钥发送
        let from_a = a.seal(b"new-key").unwrap();

        // a 能解开 b 的旧钥在途帧 (走 prev 窗口)
        let m = u16::from_be_bytes([inflight_from_b[0], inflight_from_b[1]]);
        let mut ct = inflight_from_b[2..].to_vec();
        assert_eq!(
            a.open(m, &mut ct).unwrap(),
            b"inflight-old",
            "发起方必须能用上一代密钥解开在途旧钥帧"
        );
        // b 能解开 a 的新钥帧
        let m2 = u16::from_be_bytes([from_a[0], from_a[1]]);
        let mut ct2 = from_a[2..].to_vec();
        assert_eq!(b.open(m2, &mut ct2).unwrap(), b"new-key");

        // 5) b 宽限期结束切换发钥后, 双向继续可用
        b.set_send_keys(&keys_b, Role::Responder);
        let p = b.seal(b"after-grace").unwrap();
        let m3 = u16::from_be_bytes([p[0], p[1]]);
        let mut ct3 = p[2..].to_vec();
        assert_eq!(a.open(m3, &mut ct3).unwrap(), b"after-grace");
        let p2 = a.seal(b"still-fine").unwrap();
        let m4 = u16::from_be_bytes([p2[0], p2[1]]);
        let mut ct4 = p2[2..].to_vec();
        assert_eq!(b.open(m4, &mut ct4).unwrap(), b"still-fine");
    }
}
