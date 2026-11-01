//! dns: 客户端 DNS 代理（防投毒 + 按规则分流 + 缓存）
//!
//! 设计参考 SagerNet/v2ray：
//! - `remote_dns`（代理域名用）：默认加密 DNS（DoT），端点用 IP + 固定 SNI，避免引导投毒
//! - `direct_dns`（直连域名用）：默认本地/国内明文 DNS
//! - 按 `RuleSet::decide_domain` 的决策选择上游；命中 Block 直接返回 0.0.0.0 / NXDOMAIN
//! - 缓存 domain → (IPs, TTL)，并维护 IP → domain 反查（供 IP 判定复用域名规则）
//!
//! 本模块只做"报文 + 决策 + 上游解析"，虚拟网卡与 socket protect 由调用方注入。

use crate::policy::{Action, RuleSet};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

// ---------- 上游配置 ----------

/// DNS 上游
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// 明文 UDP，如 udp://223.5.5.5:53
    Udp(SocketAddr),
    /// 明文 TCP，如 tcp://223.5.5.5:53
    Tcp(SocketAddr),
    /// DoT：TLS + 固定 SNI，如 tls://1.1.1.1:853 + sni=cloudflare-dns.com
    Dot { addr: SocketAddr, sni: String },
    /// 经出口节点转发（UDP 53）：出口侧发出，地理正确 + 不受本地投毒/封锁影响
    /// 写法: exit://<node>/<server-ip>[:port]
    Exit { node: String, server: SocketAddr },
}

impl Upstream {
    /// 解析 "udp://1.1.1.1" / "tcp://1.1.1.1:53" / "tls://1.1.1.1:853#cloudflare-dns.com"
    /// 也接受裸 IP（默认 UDP 53）
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (scheme, rest) = match s.split_once("://") {
            Some((a, b)) => (a, b),
            None => ("udp", s),
        };
        // exit://<node>/<ip[:port]>
        if scheme == "exit" {
            let (node, server) = rest
                .split_once('/')
                .with_context(|| format!("exit:// 需为 exit://<node>/<server-ip>: {s}"))?;
            let (host, port) = split_host_port(server, "udp")?;
            let ip: IpAddr = host
                .parse()
                .with_context(|| format!("exit DNS 服务器必须是 IP: {host}"))?;
            return Ok(Upstream::Exit {
                node: node.to_string(),
                server: SocketAddr::new(ip, port),
            });
        }
        // DoT 的 SNI 用 # 分隔
        let (hostport, sni) = match rest.split_once('#') {
            Some((h, sni)) => (h, Some(sni.to_string())),
            None => (rest, None),
        };
        let (host, port) = split_host_port(hostport, scheme)?;
        let ip: IpAddr = host
            .parse()
            .with_context(|| format!("DNS 上游必须是 IP（避免引导投毒）: {host}"))?;
        let addr = SocketAddr::new(ip, port);
        match scheme {
            "udp" => Ok(Upstream::Udp(addr)),
            "tcp" => Ok(Upstream::Tcp(addr)),
            "tls" | "dot" => Ok(Upstream::Dot {
                addr,
                sni: sni.unwrap_or_else(|| default_dot_sni(ip)),
            }),
            other => bail!("不支持的 DNS 上游类型: {other}"),
        }
    }
}

fn split_host_port(s: &str, scheme: &str) -> Result<(String, u16)> {
    // 支持 [v6]:port
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').context("bad ipv6")?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().context("bad port")?,
            None => default_port(scheme),
        };
        return Ok((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), p.parse().context("bad port")?)),
        _ => Ok((s.to_string(), default_port(scheme))),
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "tls" | "dot" => 853,
        _ => 53,
    }
}

/// DoT 未指定 SNI 时按 IP 推断常用 SNI（仅方便起见；建议显式写 #sni）
fn default_dot_sni(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => match v4.octets() {
            [1, 1, 1, 1] | [1, 0, 0, 1] => "cloudflare-dns.com".into(),
            [8, 8, 8, 8] | [8, 8, 4, 4] => "dns.google".into(),
            [9, 9, 9, 9] => "dns.quad9.net".into(),
            [223, 5, 5, 5] => "dns.alidns.com".into(),
            [119, 29, 29, 29] => "dot.pub".into(),
            _ => String::new(),
        },
        IpAddr::V6(_) => String::new(),
    }
}

// ---------- socket protect（Android 用） ----------

/// 经出口节点转发 DNS 查询（由调用方实现，内部复用 mesh 隧道）
pub trait ExitDnsQuery: Send + Sync {
    fn query<'a>(
        &'a self,
        node: &'a str,
        server: SocketAddr,
        raw_query: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>,
    >;
}

/// 让 socket 绕过 VPN（Android VpnService.protect）；桌面实现为空操作
pub trait SocketProtect: Send + Sync {
    fn protect(&self, sock: &std::net::UdpSocket);
    fn protect_tcp(&self, sock: &std::net::TcpStream);
}

// ---------- DNS 报文编解码 ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    /// 答案里的 A/AAAA（仅解析类型 1/28）
    pub answers: Vec<(String, u16, u32, IpAddr)>,
}

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
const RCODE_NXDOMAIN: u16 = 3;

impl Message {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            bail!("DNS 报文过短");
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let mut pos = 12;
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd {
            let (name, next) = read_name(buf, pos)?;
            pos = next;
            if pos + 4 > buf.len() {
                bail!("question 截断");
            }
            let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            pos += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        let mut answers = Vec::new();
        for _ in 0..an {
            let (name, next) = read_name(buf, pos)?;
            pos = next;
            if pos + 10 > buf.len() {
                break;
            }
            let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            // rclass = u16::from_be_bytes([buf[pos+2], buf[pos+3]]);
            let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
            let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > buf.len() {
                break;
            }
            match (rtype, rdlen) {
                (TYPE_A, 4) => answers.push((
                    name,
                    rtype,
                    ttl,
                    IpAddr::V4(Ipv4Addr::new(
                        buf[pos],
                        buf[pos + 1],
                        buf[pos + 2],
                        buf[pos + 3],
                    )),
                )),
                (TYPE_AAAA, 16) => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&buf[pos..pos + 16]);
                    answers.push((name, rtype, ttl, IpAddr::V6(Ipv6Addr::from(b))));
                }
                _ => {}
            }
            pos += rdlen;
        }
        Ok(Message {
            id,
            flags,
            questions,
            answers,
        })
    }

    pub fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&(rand_id()).to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        write_name(&mut out, name);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out
    }
}

fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (n & 0xffff) as u16
}

fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut after_jump = pos;
    let mut hops = 0;
    loop {
        if pos >= buf.len() {
            bail!("name 越界");
        }
        let len = buf[pos];
        if len & 0xc0 == 0xc0 {
            // 压缩指针
            if pos + 1 >= buf.len() {
                bail!("指针截断");
            }
            let ptr = (((len & 0x3f) as usize) << 8) | buf[pos + 1] as usize;
            if !jumped {
                after_jump = pos + 2;
            }
            jumped = true;
            hops += 1;
            if hops > 16 {
                bail!("name 指针循环");
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let end = pos + 1 + len as usize;
        if end > buf.len() {
            bail!("label 截断");
        }
        labels.push(String::from_utf8_lossy(&buf[pos + 1..end]).to_string());
        pos = end;
    }
    Ok((labels.join("."), if jumped { after_jump } else { pos }))
}

fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        let n = b.len().min(63);
        out.push(n as u8);
        out.extend_from_slice(&b[..n]);
    }
    out.push(0);
}

/// 构造应答（把答案列表写回）
pub fn build_response(
    id: u16,
    question: &Question,
    answers: &[(u32, IpAddr)],
    rcode: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&id.to_be_bytes());
    // QR=1, RD=1, RA=1, rcode
    let flags: u16 = 0x8180 | (rcode & 0xf);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QD
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // AN
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    write_name(&mut out, &question.name);
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&question.qclass.to_be_bytes());
    for (ttl, ip) in answers {
        // 名字用压缩指针指向 offset 12
        out.extend_from_slice(&[0xc0, 0x0c]);
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&TYPE_A.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

pub fn nxdomain(id: u16, question: &Question) -> Vec<u8> {
    build_response(id, question, &[], RCODE_NXDOMAIN)
}

// ---------- 上游解析 ----------

async fn resolve_udp(addr: SocketAddr, query: &[u8], protect: Option<&Arc<dyn SocketProtect>>) -> Result<Vec<u8>> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let std_sock = std::net::UdpSocket::bind(bind)?;
    std_sock.set_nonblocking(true)?;
    if let Some(p) = protect {
        p.protect(&std_sock);
    }
    let sock = UdpSocket::from_std(std_sock)?;
    sock.connect(addr).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf)).await??;
    buf.truncate(n);
    Ok(buf)
}

async fn resolve_tcp(addr: SocketAddr, query: &[u8], protect: Option<&Arc<dyn SocketProtect>>) -> Result<Vec<u8>> {
    let std_sock = std::net::TcpStream::connect(addr)?;
    std_sock.set_nonblocking(true)?;
    if let Some(p) = protect {
        p.protect_tcp(&std_sock);
    }
    let mut stream = TcpStream::from_std(std_sock)?;
    send_tcp_query(&mut stream, query).await
}

async fn send_tcp_query<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let len = query.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut lb = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut lb)).await??;
    let n = u16::from_be_bytes(lb) as usize;
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await??;
    Ok(buf)
}

async fn resolve_dot(addr: SocketAddr, sni: &str, query: &[u8]) -> Result<Vec<u8>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .with_context(|| format!("非法 SNI: {sni}"))?;
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = connector.connect(server_name, tcp).await?;
    send_tcp_query(&mut tls, query).await
}

pub async fn resolve_upstream(
    up: &Upstream,
    query: &[u8],
    protect: Option<&Arc<dyn SocketProtect>>,
    exit: Option<&Arc<dyn ExitDnsQuery>>,
) -> Result<Vec<u8>> {
    match up {
        Upstream::Udp(a) => resolve_udp(*a, query, protect).await,
        Upstream::Tcp(a) => resolve_tcp(*a, query, protect).await,
        Upstream::Dot { addr, sni } => resolve_dot(*addr, sni, query).await,
        Upstream::Exit { node, server } => {
            let ex = exit.context("未配置出口 DNS 通道")?;
            tokio::time::timeout(Duration::from_secs(8), ex.query(node, *server, query)).await?
        }
    }
}

// ---------- 缓存 ----------

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub ips: Vec<IpAddr>,
    pub expires: Instant,
    /// 决定该域名走向的动作（供 IP 反查）
    pub action: Action,
}

#[derive(Default)]
pub struct DnsCache {
    by_name: HashMap<(String, u16), CacheEntry>,
    /// IP → 域名（供 IP 判定复用域名规则）
    by_ip: HashMap<IpAddr, (String, Instant)>,
}

impl DnsCache {
    pub fn get(&self, name: &str, qtype: u16) -> Option<&CacheEntry> {
        self.by_name
            .get(&(name.to_ascii_lowercase(), qtype))
            .filter(|e| e.expires > Instant::now())
    }

    pub fn put(&mut self, name: &str, qtype: u16, ips: Vec<IpAddr>, ttl: u32, action: Action) {
        let ttl = ttl.clamp(10, 3600);
        let expires = Instant::now() + Duration::from_secs(ttl as u64);
        let key = (name.to_ascii_lowercase(), qtype);
        for ip in &ips {
            self.by_ip.insert(*ip, (key.0.clone(), expires));
        }
        self.by_name.insert(
            key,
            CacheEntry {
                ips,
                expires,
                action,
            },
        );
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Option<&str> {
        self.by_ip
            .get(&ip)
            .filter(|(_, exp)| *exp > Instant::now())
            .map(|(n, _)| n.as_str())
    }

    pub fn prune(&mut self) {
        let now = Instant::now();
        self.by_name.retain(|_, e| e.expires > now);
        self.by_ip.retain(|_, (_, exp)| *exp > now);
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

// ---------- DNS 服务 ----------

pub struct DnsConfig {
    /// 代理域名用的上游（建议 DoT/DoH）
    pub remote: Vec<Upstream>,
    /// 直连域名用的上游（建议本地/国内 DNS）
    pub direct: Vec<Upstream>,
    /// 拦截时返回的地址（默认 0.0.0.0）
    pub block_ip: IpAddr,
    /// 拦截时返回 NXDOMAIN 还是 0.0.0.0
    pub block_nxdomain: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            // 默认加密 DNS，IP + 固定 SNI，避免引导投毒
            remote: vec![
                Upstream::Dot {
                    addr: "1.1.1.1:853".parse().unwrap(),
                    sni: "cloudflare-dns.com".into(),
                },
                Upstream::Dot {
                    addr: "8.8.8.8:853".parse().unwrap(),
                    sni: "dns.google".into(),
                },
            ],
            direct: vec![Upstream::Udp("223.5.5.5:53".parse().unwrap())],
            block_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            block_nxdomain: false,
        }
    }
}

pub struct DnsService {
    /// fake-IP 池（None = 关闭）
    pub fakeip: Option<Arc<crate::fakeip::FakeIp>>,
    rules: Arc<RuleSet>,
    cfg: DnsConfig,
    cache: Mutex<DnsCache>,
    protect: Option<Arc<dyn SocketProtect>>,
    exit: Option<Arc<dyn ExitDnsQuery>>,
    /// 统计
    pub stat_blocked: std::sync::atomic::AtomicU64,
    pub stat_cache_hit: std::sync::atomic::AtomicU64,
    pub stat_remote: std::sync::atomic::AtomicU64,
    pub stat_direct: std::sync::atomic::AtomicU64,
}

impl DnsService {
    pub fn new(rules: Arc<RuleSet>, cfg: DnsConfig, protect: Option<Arc<dyn SocketProtect>>) -> Self {
        Self {
            fakeip: None,
            rules,
            cfg,
            cache: Mutex::new(DnsCache::default()),
            protect,
            exit: None,
            stat_blocked: Default::default(),
            stat_cache_hit: Default::default(),
            stat_remote: Default::default(),
            stat_direct: Default::default(),
        }
    }

    /// 启用 fake-IP：被代理的域名立即返回假地址
    pub fn with_fake_ip(mut self, pool: Arc<crate::fakeip::FakeIp>) -> Self {
        self.fakeip = Some(pool);
        self
    }

    /// 供 TCP/UDP 栈使用：解析域名（走本服务的规则与上游）
    /// 注意：这里必须返回真实地址，不能再走 fake-IP 分支（否则死循环）
    pub async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>> {
        let query = Message::query(name, 1);
        let resp = self.handle_query_opt(&query, false).await?;
        let parsed = Message::parse(&resp)?;
        Ok(parsed
            .answers
            .iter()
            .map(|(_, _, _, ip)| *ip)
            .filter(|ip| !ip.is_unspecified())
            .collect())
    }

    /// 诊断用：绕过规则/fake-IP，直接问某一侧上游
    pub async fn probe_raw(&self, name: &str, remote: bool) -> Result<Vec<IpAddr>> {
        let ups = if remote { &self.cfg.remote } else { &self.cfg.direct };
        let query = Message::query(name, 1);
        for up in ups {
            if let Ok(resp) =
                resolve_upstream(up, &query, self.protect.as_ref(), self.exit.as_ref()).await
            {
                if let Ok(parsed) = Message::parse(&resp) {
                    let ips: Vec<IpAddr> = parsed
                        .answers
                        .iter()
                        .map(|(_, _, _, ip)| *ip)
                        .filter(|ip| !ip.is_unspecified())
                        .collect();
                    return Ok(ips);
                }
            }
        }
        bail!("上游无应答")
    }

    /// 注入"经出口节点解析"的通道
    pub fn with_exit_query(mut self, exit: Arc<dyn ExitDnsQuery>) -> Self {
        self.exit = Some(exit);
        self
    }

    /// 处理一条 DNS 查询报文，返回应答报文
    pub async fn handle_query(&self, raw: &[u8]) -> Result<Vec<u8>> {
        self.handle_query_opt(raw, true).await
    }

    async fn handle_query_opt(&self, raw: &[u8], allow_fake: bool) -> Result<Vec<u8>> {
        let msg = Message::parse(raw)?;
        let q = msg
            .questions
            .first()
            .context("DNS 查询没有 question")?
            .clone();
        let name = q.name.to_ascii_lowercase();

        // 1) 规则决策
        let decision = self.rules.decide_domain(&name);
        match decision.action {
            Action::Block => {
                self.stat_blocked
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if self.cfg.block_nxdomain {
                    return Ok(nxdomain(msg.id, &q));
                }
                let ans = vec![(60u32, self.cfg.block_ip)];
                return Ok(build_response(msg.id, &q, &ans, 0));
            }
            _ => {}
        }

        // 1.4) IPv6：栈只支持 IPv4，AAAA/HTTPS(65) 直接返回空记录
        //      —— 否则应用会先尝试 IPv6 连接、超时后才回退，明显拖慢首屏
        if q.qtype == 28 || q.qtype == 65 {
            return Ok(build_response(msg.id, &q, &[], 0));
        }

        // 1.5) fake-IP：被代理的域名直接给假地址（A 记录）
        //      直连域名仍走真实解析，避免国内站点受假地址影响
        if let Some(pool) = &self.fakeip {
            if allow_fake && q.qtype == 1 && matches!(decision.action, Action::Exit(_)) {
                let ip = pool.alloc(&name);
                self.stat_remote
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(build_response(msg.id, &q, &[(30u32, IpAddr::V4(ip))], 0));
            }
        }

        // 2) 缓存
        {
            let cache = self.cache.lock().await;
            if let Some(e) = cache.get(&name, q.qtype) {
                self.stat_cache_hit
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let ttl = e.expires.saturating_duration_since(Instant::now()).as_secs() as u32;
                let ans: Vec<(u32, IpAddr)> = e.ips.iter().map(|ip| (ttl.max(1), *ip)).collect();
                return Ok(build_response(msg.id, &q, &ans, 0));
            }
        }

        // 3) 选择上游
        let (ups, is_remote) = match &decision.action {
            Action::Direct => (&self.cfg.direct, false),
            _ => (&self.cfg.remote, true),
        };
        if ups.is_empty() {
            bail!("没有可用的 DNS 上游");
        }

        let mut last_err = None;
        for up in ups {
            let query = Message::query(&name, q.qtype);
            match resolve_upstream(up, &query, self.protect.as_ref(), self.exit.as_ref()).await {
                Ok(resp) => {
                    let parsed = match Message::parse(&resp) {
                        Ok(p) => p,
                        Err(e) => {
                            last_err = Some(e);
                            continue;
                        }
                    };
                    let ips: Vec<(u32, IpAddr)> = parsed
                        .answers
                        .iter()
                        .map(|(_, _, ttl, ip)| (*ttl, *ip))
                        .collect();
                    let ttl = ips.iter().map(|(t, _)| *t).min().unwrap_or(60);
                    {
                        let mut cache = self.cache.lock().await;
                        cache.put(
                            &name,
                            q.qtype,
                            ips.iter().map(|(_, ip)| *ip).collect(),
                            ttl,
                            decision.action.clone(),
                        );
                    }
                    if is_remote {
                        self.stat_remote
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        self.stat_direct
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    // 用原始 id 重写应答（上游用随机 id）
                    let mut out = build_response(msg.id, &q, &ips, 0);
                    // 若上游是 NXDOMAIN，保留其 rcode
                    if parsed.answers.is_empty() && parsed.flags & 0xf != 0 {
                        out = build_response(msg.id, &q, &[], parsed.flags & 0xf);
                    }
                    return Ok(out);
                }
                Err(e) => {
                    log::debug!("DNS 上游 {up:?} 失败: {e:#}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DNS 解析失败")))
    }
}

// ---------- 测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Rule, RuleSet};

    #[test]
    fn upstream_parse() {
        assert_eq!(
            Upstream::parse("udp://223.5.5.5").unwrap(),
            Upstream::Udp("223.5.5.5:53".parse().unwrap())
        );
        assert_eq!(
            Upstream::parse("1.1.1.1").unwrap(),
            Upstream::Udp("1.1.1.1:53".parse().unwrap())
        );
        assert_eq!(
            Upstream::parse("tcp://1.1.1.1:5353").unwrap(),
            Upstream::Tcp("1.1.1.1:5353".parse().unwrap())
        );
        assert_eq!(
            Upstream::parse("tls://1.1.1.1").unwrap(),
            Upstream::Dot {
                addr: "1.1.1.1:853".parse().unwrap(),
                sni: "cloudflare-dns.com".into()
            }
        );
        assert_eq!(
            Upstream::parse("tls://8.8.8.8:853#dns.google").unwrap(),
            Upstream::Dot {
                addr: "8.8.8.8:853".parse().unwrap(),
                sni: "dns.google".into()
            }
        );
        // 域名上游被拒绝（防引导投毒）
        assert!(Upstream::parse("tls://dns.google").is_err());
    }

    #[test]
    fn dns_message_roundtrip() {
        let q = Message::query("www.example.com", TYPE_A);
        let parsed = Message::parse(&q).unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "www.example.com");
        assert_eq!(parsed.questions[0].qtype, TYPE_A);

        let question = parsed.questions[0].clone();
        let resp = build_response(
            parsed.id,
            &question,
            &[(120, "1.2.3.4".parse().unwrap())],
            0,
        );
        let rp = Message::parse(&resp).unwrap();
        assert_eq!(rp.id, parsed.id);
        assert_eq!(rp.answers.len(), 1);
        assert_eq!(rp.answers[0].3, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(rp.answers[0].2, 120);
    }

    #[test]
    fn nxdomain_response() {
        let q = Message::query("nope.example", TYPE_A);
        let parsed = Message::parse(&q).unwrap();
        let resp = nxdomain(parsed.id, &parsed.questions[0]);
        let rp = Message::parse(&resp).unwrap();
        assert_eq!(rp.flags & 0xf, RCODE_NXDOMAIN);
        assert!(rp.answers.is_empty());
    }

    #[test]
    fn cache_ttl_and_ip_lookup() {
        let mut c = DnsCache::default();
        c.put(
            "a.com",
            TYPE_A,
            vec!["1.1.1.1".parse().unwrap()],
            60,
            Action::Direct,
        );
        assert!(c.get("a.com", TYPE_A).is_some());
        assert!(c.get("A.COM", TYPE_A).is_some());
        assert_eq!(
            c.lookup_ip("1.1.1.1".parse().unwrap()),
            Some("a.com")
        );
        // 过期后失效
        let mut c2 = DnsCache::default();
        c2.put(
            "b.com",
            TYPE_A,
            vec!["2.2.2.2".parse().unwrap()],
            0, // 会被 clamp 到 10s，仍有效
            Action::Direct,
        );
        assert!(c2.get("b.com", TYPE_A).is_some());
    }

    #[tokio::test]
    async fn block_returns_zero_ip() {
        let rules = vec![Rule::parse("domain-suffix:ads=block").unwrap()];
        let rs = RuleSet::new(rules, None, None, Action::Exit(None));
        let svc = DnsService::new(Arc::new(rs), DnsConfig::default(), None);
        let q = Message::query("x.ads", TYPE_A);
        let resp = svc.handle_query(&q).await.unwrap();
        let rp = Message::parse(&resp).unwrap();
        assert_eq!(rp.answers.len(), 1);
        assert_eq!(rp.answers[0].3, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
}
