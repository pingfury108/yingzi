//! yz-android: JNI 桥（Kotlin UI ⇄ yz-core）
//!
//! 暴露面极小：
//!   nativeStart(configJson, vpnService)  → 启动（含 TUN fd、NS、协调器、规则）
//!   nativeStop()
//!   nativeStatus()   → JSON（连接/节点/流量/拦截/规则命中）
//!   nativeEvents()   → JSON（事件流）
//!   nativeSetRules(json)
//!
//! VpnService 对象用于调用 protect(fd)：栈自己的上游 socket 必须绕过 VPN，
//! 否则流量会套娃（这是 Android 透明代理的必备步骤）。

use anyhow::Result;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use yz_core::dns::{DnsConfig, DnsService, SocketProtect, Upstream};
use yz_core::geo::{GeoIpDb, GeoSiteDb};
use yz_core::mesh::PacketIo;
use yz_core::policy::{Action, Rule, RuleSet};
use yz_core::stack::{Stack, StackConfig};
use yz_core::state::CoreState;
use yz_core::tcp_stack::{TcpStack, TcpStackConfig};

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static VM: OnceLock<JavaVM> = OnceLock::new();
static VPN: OnceLock<GlobalRef> = OnceLock::new();
static RUNNING: AtomicBool = AtomicBool::new(false);
/// 运行中的节点（用于 stop）
static NODE: Mutex<Option<NodeRuntime>> = Mutex::new(None);
static EVENTS: OnceLock<Arc<std::sync::Mutex<Vec<(i64, String, String)>>>> = OnceLock::new();

use std::sync::Mutex;

fn rt() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .build()
            .expect("tokio runtime")
    })
}

// ---------- 配置 ----------

#[derive(Deserialize)]
struct StartConfig {
    network_secret: String,
    identity_file: String,
    coordinator: String,
    #[serde(default = "default_name")]
    name: String,
    default_exit: Option<String>,
    #[serde(default)]
    geoip: Option<String>,
    #[serde(default)]
    geosite: Option<String>,
    #[serde(default)]
    rules: Vec<String>,
    tun_fd: i32,
    #[serde(default = "default_mtu")]
    mtu: usize,
    /// 代理域名用的 DNS（默认经出口节点解析）
    #[serde(default)]
    remote_dns: Option<String>,
    /// 直连域名用的 DNS
    #[serde(default)]
    direct_dns: Option<String>,
    /// fake-IP 模式（被代理域名返回 198.18.x.x 假地址）
    #[serde(default = "default_true")]
    fake_ip: bool,
    /// IPv6 分流（默认关；geoip6 数据精度有限）
    #[serde(default)]
    ipv6: bool,
}

fn default_true() -> bool {
    true
}

fn default_name() -> String {
    "android".into()
}
fn default_mtu() -> usize {
    1400
}

// ---------- protect ----------

struct VpnProtect {
    vm: &'static JavaVM,
    vpn: GlobalRef,
}

impl SocketProtect for VpnProtect {
    fn protect(&self, sock: &std::net::UdpSocket) {
        self.protect_fd(sock.as_raw_fd());
    }
    fn protect_tcp(&self, sock: &std::net::TcpStream) {
        self.protect_fd(sock.as_raw_fd());
    }
}

use std::os::unix::io::AsRawFd;

impl VpnProtect {
    fn protect_fd(&self, fd: i32) {
        static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Ok(mut env) = self.vm.attach_current_thread() else {
            log::warn!("protect: attach_current_thread 失败");
            return;
        };
        match env.call_method(
            self.vpn.as_obj(),
            "protect",
            "(I)Z",
            &[JValue::Int(fd)],
        ) {
            Ok(v) => {
                if let Ok(ok) = v.z() {
                    if n < 3 {
                        log::info!("protect({fd}) -> {ok}");
                    }
                    if !ok {
                        log::warn!("VpnService.protect({fd}) 返回 false");
                    }
                }
            }
            Err(e) => log::warn!("VpnService.protect 调用失败: {e}"),
        }
    }
}

// ---------- TUN fd → PacketIo ----------

struct FdIo {
    read_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    write_fd: i32,
}

impl PacketIo for FdIo {
    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut rx = self.read_rx.lock().await;
            match rx.recv().await {
                Some(pkt) => {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    Ok(n)
                }
                None => Err(anyhow::anyhow!("tun closed")),
            }
        })
    }

    fn send<'a>(
        &'a self,
        pkt: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let fd = self.write_fd;
            let data = pkt.to_vec();
            // 阻塞写放到 blocking 线程，避免占用 async worker
            tokio::task::spawn_blocking(move || unsafe {
                let n = libc_write(fd, &data);
                if n < 0 {
                    return Err(anyhow::anyhow!("tun write failed"));
                }
                Ok(())
            })
            .await?
        })
    }
}

unsafe fn libc_write(fd: i32, data: &[u8]) -> isize {
    let mut written = 0usize;
    while written < data.len() {
        let n = jni_write(fd, &data[written..]);
        if n <= 0 {
            return n;
        }
        written += n as usize;
    }
    written as isize
}

unsafe fn jni_write(fd: i32, data: &[u8]) -> isize {
    extern "C" {
        fn write(fd: i32, buf: *const std::ffi::c_void, count: usize) -> isize;
    }
    write(fd, data.as_ptr() as *const std::ffi::c_void, data.len())
}

fn spawn_tun_reader(fd: i32) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
    std::thread::spawn(move || {
        extern "C" {
            fn read(fd: i32, buf: *mut std::ffi::c_void, count: usize) -> isize;
        }
        let mut buf = vec![0u8; 4096];
        loop {
            let n = unsafe { read(fd, buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len()) };
            if n < 0 {
                // EAGAIN/EWOULDBLOCK: fd 非阻塞, 稍等再试
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                log::warn!("tun read 结束: {err}");
                break;
            }
            if n == 0 {
                continue;
            }
            if tx.blocking_send(buf[..n as usize].to_vec()).is_err() {
                break;
            }
        }
    });
    rx
}

// ---------- 运行时 ----------

struct NodeRuntime {
    state: Arc<CoreState>,
    ruleset: Arc<RuleSet>,
    started: std::time::Instant,
    exit: String,
    self_id: String,
    #[allow(dead_code)]
    protect: Option<Arc<dyn SocketProtect>>,
    ns: yz_crypto::NetworkSecret,
    id_pub: [u8; 32],
    stop_tx: tokio::sync::watch::Sender<bool>,
    dns: Arc<DnsService>,
    tcp: Arc<TcpStack>,
    udp: Arc<Stack>,
}

impl NodeRuntime {
    fn status(&self) -> StatusJson {
        let state = self.state.clone();
        let (tx_bytes, rx_bytes, streams, peers, rtt_ms, nodes, domains) = rt().block_on(async move {
            let traffic = state.traffic().await;
            // 注意：不要持着 tunnels 锁去取其它锁（会跟 adopt_tunnel 等形成锁序反转）
            let peers = state.tunnels.lock().await.len();
            let rtt = state.rtt.read().await.clone();
            let path = state.path.read().await.clone();
            let dir = state.dir.read().await.clone();
            let self_id = self.self_id.clone();
            // 连接状态单独取一次锁（内层全部同步，不 await）
            let connected_ids: std::collections::HashSet<String> = state
                .tunnels
                .lock()
                .await
                .iter()
                .filter(|(_, t)| !t.is_closed())
                .map(|(k, _)| k.clone())
                .collect();
            let mut nodes: Vec<NodeStatus> = dir
                .values()
                .filter(|n| n.node_id != self_id)
                .map(|n| NodeStatus {
                    node_id: n.node_id.clone(),
                    name: n.name.clone(),
                    vip: yz_core::util::vip_of(&n.node_id).to_string(),
                    addrs: n.addrs.clone(),
                    rtt: rtt.get(&n.node_id).copied().unwrap_or(0),
                    path: path.get(&n.node_id).cloned().unwrap_or_default(),
                    is_exit: n.caps & yz_proto::caps::EXIT != 0,
                    connected: connected_ids.contains(&n.node_id),
                })
                .collect();
            nodes.sort_by_key(|n| (n.rtt == 0, n.rtt));
            let mut domains: Vec<DomainStat> = state
                .domains
                .read()
                .await
                .iter()
                .map(|(k, (hits, action))| DomainStat {
                    name: k.clone(),
                    hits: *hits,
                    action: action.clone(),
                })
                .collect();
            domains.sort_by(|a, b| b.hits.cmp(&a.hits));
            domains.truncate(20);
            let rtt_ms = rtt
                .get(&self.exit)
                .copied()
                .or_else(|| {
                    dir.values()
                        .find(|n| n.name == self.exit)
                        .and_then(|n| rtt.get(&n.node_id).copied())
                })
                .unwrap_or(0);
            (traffic.0, traffic.1, traffic.2, peers, rtt_ms, nodes, domains)
        });
        StatusJson {
            running: true,
            peers,
            exit: self.exit.clone(),
            rtt_ms,
            uptime_s: self.started.elapsed().as_secs(),
            nodes,
            domains,
            tx_bytes,
            rx_bytes,
            streams,
            dns_remote: self
                .dns
                .stat_remote
                .load(std::sync::atomic::Ordering::Relaxed),
            dns_direct: self
                .dns
                .stat_direct
                .load(std::sync::atomic::Ordering::Relaxed),
            dns_blocked: self
                .dns
                .stat_blocked
                .load(std::sync::atomic::Ordering::Relaxed),
            tcp_direct: self.tcp.stat_direct.load(std::sync::atomic::Ordering::Relaxed),
            tcp_exit: self.tcp.stat_exit.load(std::sync::atomic::Ordering::Relaxed),
            tcp_blocked: self.tcp.stat_blocked.load(std::sync::atomic::Ordering::Relaxed),
            udp_direct: self.udp.stat_udp_direct.load(std::sync::atomic::Ordering::Relaxed),
            udp_exit: self.udp.stat_udp_exit.load(std::sync::atomic::Ordering::Relaxed),
            udp_dns: self.udp.stat_udp_dns.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

#[derive(Serialize)]
struct DomainStat {
    name: String,
    hits: u64,
    action: String,
}

#[derive(Serialize)]
struct NodeStatus {
    node_id: String,
    name: String,
    vip: String,
    addrs: Vec<String>,
    rtt: u32,
    path: String,
    is_exit: bool,
    connected: bool,
}

#[derive(Serialize)]
struct StatusJson {
    running: bool,
    peers: usize,
    exit: String,
    rtt_ms: u32,
    uptime_s: u64,
    nodes: Vec<NodeStatus>,
    domains: Vec<DomainStat>,
    tx_bytes: u64,
    rx_bytes: u64,
    streams: u64,
    dns_remote: u64,
    dns_direct: u64,
    dns_blocked: u64,
    tcp_direct: u64,
    tcp_exit: u64,
    tcp_blocked: u64,
    udp_direct: u64,
    udp_exit: u64,
    udp_dns: u64,
}

fn start_async(cfg: StartConfig, protect: Option<Arc<dyn SocketProtect>>) -> Result<NodeRuntime> {
    let ns = yz_crypto::NetworkSecret::from_hex(&cfg.network_secret)?;
    let id_pub = match std::fs::read(&cfg.identity_file) {
        Ok(b) => yz_crypto::load_identity(&b)?,
        Err(_) => {
            let (pkcs8, id_pub) = yz_crypto::generate_identity()?;
            std::fs::write(&cfg.identity_file, pkcs8)?;
            id_pub
        }
    };

    // 规则
    let geoip = cfg
        .geoip
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| GeoIpDb::parse(&b).ok());
    let geosite = cfg
        .geosite
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| GeoSiteDb::parse(&b).ok());
    let default_action = Action::Exit(cfg.default_exit.clone());
    let rules: Vec<Rule> = cfg
        .rules
        .iter()
        .filter_map(|r| Rule::parse(r).ok())
        .collect();
    let ruleset = Arc::new(RuleSet::new(rules, geoip, geosite, default_action));

    let state = Arc::new(CoreState::default());
    // 出口自动选路需要排除自己
    state.set_self_id(&yz_crypto::node_id(&id_pub));
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);

    // 连接协调器 + 目录同步
    {
        let state = state.clone();
        let ns = ns.clone();
        let coord = cfg.coordinator.clone();
        let name = cfg.name.clone();
        rt().spawn(async move {
            let mut backoff = std::time::Duration::from_secs(1);
            loop {
                match yz_core::tunnel::connect(&coord, &ns, &id_pub).await {
                    Ok(mut h) => {
                        backoff = std::time::Duration::from_secs(1);
                        *state.coord_tunnel.write().await = Some(h.tunnel.clone());
                        let hello = yz_proto::encode_control(&yz_proto::ControlMsg::Hello {
                            version: 1,
                            name: name.clone(),
                            addrs: vec![],
                            udp_addr: String::new(),
                            caps: 0,
                        });
                        let _ = h
                            .tunnel
                            .write_frame(&yz_proto::Frame::Control { payload: hello })
                            .await;
                        log::info!("connected to coordinator {coord}");
                        // 存活探测: 假死时 mark_closed, 让下面的 select 跳出并重连
                        {
                            let t = h.tunnel.clone();
                            rt().spawn(async move {
                                loop {
                                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                                    if t.is_closed() {
                                        break;
                                    }
                                    if t
                                        .write_frame(&yz_proto::Frame::Ping {
                                            ts: yz_core::util::now_ms(),
                                        })
                                        .await
                                        .is_err()
                                    {
                                        log::warn!("coordinator 写失败, 触发重连");
                                        t.mark_closed();
                                        break;
                                    }
                                    if t.idle_for().await > std::time::Duration::from_secs(30) {
                                        log::warn!("coordinator 30s 无响应, 触发重连");
                                        t.mark_closed();
                                        break;
                                    }
                                }
                            });
                        }
                        loop {
                            tokio::select! {
                                f = h.ctrl_rx.recv() => match f {
                                    Some(yz_proto::Frame::Control { payload }) => {
                                        if let Ok(yz_proto::ControlMsg::DirSync { nodes }) =
                                            yz_proto::decode_control(&payload)
                                        {
                                            let mut d = state.dir.write().await;
                                            d.clear();
                                            for n in nodes { d.insert(n.node_id.clone(), n); }
                                        }
                                    }
                                    Some(_) => {}
                                    None => break,
                                },
                                _ = h.closed.changed() => break,
                            }
                        }
                        state.dir.write().await.clear();
                        *state.coord_tunnel.write().await = None;
                    }
                    Err(e) => log::warn!("coordinator: {e:#}"),
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = stop_rx.changed() => break,
                }
                backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
            }
        });
    }

    // DNS
    let remote = cfg
        .remote_dns
        .clone()
        .unwrap_or_else(|| "exit://overseas-hk/1.1.1.1:53".into());
    let direct = cfg
        .direct_dns
        .clone()
        .unwrap_or_else(|| "udp://223.5.5.5".into());
    let dns_cfg = DnsConfig {
        remote: vec![Upstream::parse(&remote)?],
        direct: vec![Upstream::parse(&direct)?],
        ipv6: cfg.ipv6,
        ..Default::default()
    };
    let fakeip = if cfg.fake_ip {
        Some(Arc::new(yz_core::fakeip::FakeIp::new()))
    } else {
        None
    };
    let mut dns = DnsService::new(ruleset.clone(), dns_cfg, protect.clone());
    if let Some(pool) = &fakeip {
        dns = dns.with_fake_ip(pool.clone());
    }
    dns = dns.with_exit_query(Arc::new(yz_core::exit_dns::TunnelExitDns::new(
        state.clone(),
        ns.clone(),
        id_pub,
    )));
    let dns = Arc::new(dns);

    // 出口通道
    let exit_udp: Arc<dyn yz_core::stack::ExitUdp> = Arc::new(
        yz_core::exit_udp::TunnelExitUdp::new(state.clone(), ns.clone(), id_pub),
    );
    let exit_tcp: Arc<dyn yz_core::tcp_stack::ExitTcp> = Arc::new(
        yz_core::exit_udp::TunnelExitTcp::new(state.clone(), ns.clone(), id_pub),
    );

    // TUN
    let tun_rx = spawn_tun_reader(cfg.tun_fd);
    let io: Arc<dyn PacketIo> = Arc::new(FdIo {
        read_rx: tokio::sync::Mutex::new(tun_rx),
        write_fd: cfg.tun_fd,
    });

    // UDP 栈
    let udp = Arc::new(Stack::new(
        ruleset.clone(),
        state.clone(),
        StackConfig {
            mtu: cfg.mtu,
            dns: Some(dns.clone()),
            protect: protect.clone(),
            exit: Some(exit_udp),
            fakeip: fakeip.clone(),
            ..Default::default()
        },
    ));

    // TCP 栈
    let tcp = Arc::new(TcpStack::new(
        ruleset.clone(),
        TcpStackConfig {
            events: Some(state.clone()),
            fakeip: fakeip.clone(),
            dns: Some(dns.clone()),
            mtu: cfg.mtu,
            protect: protect.clone(),
            exit: Some(exit_tcp),
            max_conns: 400,
        },
    ));

    // 单读循环分发
    {
        let io_loop = io.clone();
        let udp = udp.clone();
        let tcp = tcp.clone();
        let (tcp_tx, tcp_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let mut stop = stop_tx.subscribe();
        rt().spawn(async move {
            let io = io_loop;
            let mut buf = vec![0u8; cfg.mtu + 64];
            loop {
                tokio::select! {
                    r = io.recv(&mut buf) => {
                        let Ok(n) = r else { break };
                        let pkt = buf[..n].to_vec();
                        if yz_core::stack::parse_udp(&pkt).is_none() {
                            let _ = tcp_tx.try_send(pkt);
                        } else {
                            let io2 = io.clone();
                            let udp2 = udp.clone();
                            tokio::spawn(async move {
                                let _ = udp2.handle_packet(&io2, &pkt).await;
                            });
                        }
                    }
                    _ = stop.changed() => break,
                }
            }
        });
        let default_exit = cfg.default_exit.clone();
        let io_tcp = io.clone();
        rt().spawn(async move {
            let _ = tcp.run(io_tcp, tcp_rx, default_exit).await;
        });
    }

    Ok(NodeRuntime {
        state,
        ruleset,
        started: std::time::Instant::now(),
        exit: cfg.default_exit.clone().unwrap_or_default(),
        self_id: yz_crypto::node_id(&id_pub),
        protect: protect.clone(),
        ns,
        id_pub,
        stop_tx,
        dns,
        tcp,
        udp,
    })
}

// ---------- 诊断 ----------

async fn diagnose(
    state: Arc<CoreState>,
    dns: Arc<DnsService>,
    ns: yz_crypto::NetworkSecret,
    id_pub: [u8; 32],
    self_id: String,
) -> serde_json::Value {
    // 1) 各节点 TCP 连通性 / 延迟（连隧道端口即可测通路）
    let nodes: Vec<(String, String, Vec<String>)> = {
        let dir = state.dir.read().await;
        dir.values()
            .filter(|n| n.node_id != self_id)
            .map(|n| (n.name.clone(), n.node_id.clone(), n.addrs.clone()))
            .collect()
    };
    // 并发建隧道：耗时即"经该节点出网的建连延迟"
    let mut tasks = Vec::new();
    for (name, node_id, addrs) in nodes {
        let state2 = state.clone();
        let ns2 = ns.clone();
        tasks.push(async move {
            let started = std::time::Instant::now();
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                yz_core::peer::tunnel_for(&state2, &ns2, &id_pub, &node_id),
            )
            .await;
            let (ms, err) = match res {
                Ok(Ok(_)) => (started.elapsed().as_millis(), None),
                Ok(Err(e)) => (0, Some(format!("{e:#}"))),
                Err(_) => (0, Some("超时".to_string())),
            };
            serde_json::json!({
                "name": name,
                "addr": addrs.first().cloned().unwrap_or_default(),
                "rtt_ms": ms,
                "error": err,
            })
        });
    }
    let mut node_results: Vec<serde_json::Value> = futures::future::join_all(tasks).await;
    // 隧道建好后等一下心跳，取更准的 RTT
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    {
        let rtt = state.rtt.read().await.clone();
        let dir = state.dir.read().await;
        for item in node_results.iter_mut() {
            let name = item["name"].as_str().unwrap_or_default().to_string();
            if let Some(n) = dir.values().find(|n| n.name == name) {
                if let Some(v) = rtt.get(&n.node_id) {
                    if *v > 0 {
                        item["rtt_ms"] = serde_json::json!(*v as u128);
                    }
                }
            }
        }
    }

    // 2) DNS 检测：直连 vs 出口，看是否被污染；再查随机域名看是否被劫持
    let probe_domain = "www.google.com";
    let direct = dns_probe(&dns, probe_domain, false).await;
    let remote = dns_probe(&dns, probe_domain, true).await;
    let rand_domain = format!(
        "yz{}.example.com",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let hijack = dns_probe(&dns, &rand_domain, false).await;

    let polluted = match (&direct, &remote) {
        (Some(d), Some(r)) => {
            // 直连结果与出口结果完全不相交 → 很可能被污染
            !d.0.is_empty() && !r.0.is_empty() && d.0.iter().all(|ip| !r.0.contains(ip))
        }
        _ => false,
    };
    let hijacked = hijack.map(|h| !h.0.is_empty()).unwrap_or(false);

    serde_json::json!({
        "nodes": node_results,
        "dns": {
            "domain": probe_domain,
            "direct": direct.map(|d| serde_json::json!({"ips": d.0, "ms": d.1})),
            "exit": remote.map(|d| serde_json::json!({"ips": d.0, "ms": d.1})),
            "polluted": polluted,
            "hijacked": hijacked,
        },
    })
}

/// 直接问某一侧上游（绕过规则与 fake-IP），返回 (IP 列表, 耗时 ms)
async fn dns_probe(
    dns: &Arc<DnsService>,
    domain: &str,
    want_exit: bool,
) -> Option<(Vec<String>, u128)> {
    let start = std::time::Instant::now();
    let ips = dns.probe_raw(domain, want_exit).await.ok()?;
    let list: Vec<String> = ips
        .iter()
        .filter(|ip| matches!(ip, std::net::IpAddr::V4(_)))
        .map(|ip| ip.to_string())
        .collect();
    Some((list, start.elapsed().as_millis()))
}

// ---------- JNI ----------

fn to_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|j| j.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn read_jstring(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s)
        .map(|v| v.into())
        .unwrap_or_default()
}

/// nativeStart(configJson, vpnService) -> 空串成功 / 错误信息
#[no_mangle]
pub extern "system" fn Java_io_yingzi_app_YzCore_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
    vpn: JObject,
) -> jstring {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Debug),
    );
    let cfg_json = read_jstring(&mut env, &config);

    // 把 panic 写进 logcat（android_logger 默认不接 panic hook，
    // 任务 panic 时只会看到连接莫名失败）
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            log::error!("PANIC: {info}");
        }));
    });

    // 保存 JavaVM + VpnService 全局引用（供 protect 使用）
    if VM.get().is_none() {
        if let Ok(vm) = env.get_java_vm() {
            let _ = VM.set(vm);
        }
    }
    if VPN.get().is_none() {
        if let Ok(g) = env.new_global_ref(vpn) {
            let _ = VPN.set(g);
        }
    }

    let cfg: StartConfig = match serde_json::from_str(&cfg_json) {
        Ok(c) => c,
        Err(e) => return to_jstring(&mut env, &format!("config: {e}")),
    };

    let protect: Option<Arc<dyn SocketProtect>> = match (VM.get(), VPN.get()) {
        (Some(vm), Some(vpn)) => Some(Arc::new(VpnProtect { vm, vpn: vpn.clone() })),
        _ => None,
    };

    match start_async(cfg, protect) {
        Ok(node) => {
            *NODE.lock().unwrap() = Some(node);
            RUNNING.store(true, Ordering::SeqCst);
            to_jstring(&mut env, "")
        }
        Err(e) => to_jstring(&mut env, &format!("{e:#}")),
    }
}

#[no_mangle]
pub extern "system" fn Java_io_yingzi_app_YzCore_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    if let Some(node) = NODE.lock().unwrap().take() {
        let _ = node.stop_tx.send(true);
    }
    RUNNING.store(false, Ordering::SeqCst);
    to_jstring(&mut env, "")
}

#[no_mangle]
pub extern "system" fn Java_io_yingzi_app_YzCore_nativeStatus(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let status = match NODE.lock().unwrap().as_ref() {
        Some(n) => serde_json::to_string(&n.status()).unwrap_or_default(),
        None => "{\"running\":false}".to_string(),
    };
    to_jstring(&mut env, &status)
}

#[no_mangle]
pub extern "system" fn Java_io_yingzi_app_YzCore_nativeEvents(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    // 优先读核心事件环（真实事件），否则用本地缓冲
    let from_core: Vec<(i64, String, String)> = {
        let guard = NODE.lock().unwrap();
        match guard.as_ref() {
            Some(node) => {
                let state = node.state.clone();
                rt().block_on(async move { state.events.read().await.iter().cloned().collect() })
            }
            None => Vec::new(),
        }
    };
    let ev = EVENTS.get_or_init(|| Arc::new(std::sync::Mutex::new(Vec::new())));
    let list = if from_core.is_empty() { ev.lock().unwrap().clone() } else { from_core };
    let arr: Vec<serde_json::Value> = list
        .into_iter()
        .map(|(ts, level, msg)| serde_json::json!({"ts": ts, "level": level, "msg": msg}))
        .collect();
    to_jstring(&mut env, &serde_json::to_string(&arr).unwrap_or_default())
}

/// nativeSetRules(json) —— 热更新规则（JSON 字符串数组），立即生效
#[no_mangle]
pub extern "system" fn Java_io_yingzi_app_YzCore_nativeSetRules(
    mut env: JNIEnv,
    _class: JClass,
    rules: JString,
) -> jboolean {
    let Ok(text) = env.get_string(&rules) else {
        return JNI_FALSE;
    };
    let text: String = text.into();
    let Ok(list) = serde_json::from_str::<Vec<String>>(&text) else {
        log::warn!("nativeSetRules: JSON 解析失败");
        return JNI_FALSE;
    };
    let parsed: Vec<Rule> = list
        .iter()
        .filter_map(|r| match Rule::parse(r) {
            Ok(rule) => Some(rule),
            Err(e) => {
                log::warn!("规则无效 {r}: {e}");
                None
            }
        })
        .collect();
    let n = parsed.len();
    let guard = NODE.lock().unwrap();
    let Some(node) = guard.as_ref() else {
        return JNI_FALSE;
    };
    node.ruleset.replace_rules(parsed);
    log::info!("规则已热更新: {n} 条");
    JNI_TRUE
}

/// nativePushEvent(level, msg) —— 由 Kotlin 侧写入事件（启停/网络切换/规则更新）
/// nativeDiagnose() —— 一键诊断：各节点 TCP 连通/延迟 + DNS 污染与劫持检测
/// 阻塞调用（几秒），Kotlin 侧需放后台线程。
#[no_mangle]
pub extern "system" fn Java_io_yingzi_app_YzCore_nativeDiagnose(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let out = {
        let guard = NODE.lock().unwrap();
        match guard.as_ref() {
            Some(node) => {
                let state = node.state.clone();
                let dns = node.dns.clone();
                let self_id = node.self_id.clone();
                let ns = node.ns.clone();
                let id_pub = node.id_pub;
                rt().block_on(async move {
                    diagnose(state, dns, ns, id_pub, self_id).await
                })
            }
            None => serde_json::json!({"error": "核心未运行"}),
        }
    };
    to_jstring(&mut env, &serde_json::to_string(&out).unwrap_or_default())
}

#[no_mangle]
pub extern "system" fn Java_io_yingzi_app_YzCore_nativePushEvent(
    mut env: JNIEnv,
    _class: JClass,
    level: JString,
    msg: JString,
) {
    let lvl: String = env.get_string(&level).map(Into::into).unwrap_or_else(|_| "INFO".into());
    let text: String = env.get_string(&msg).map(Into::into).unwrap_or_default();
    let guard = NODE.lock().unwrap();
    match guard.as_ref() {
        Some(node) => {
            let state = node.state.clone();
            rt().block_on(async move { state.push_event(&lvl, text).await });
        }
        None => {
            let ev = EVENTS.get_or_init(|| Arc::new(std::sync::Mutex::new(Vec::new())));
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let mut v = ev.lock().unwrap();
            v.push((ts, lvl, text));
            while v.len() > 100 {
                v.remove(0);
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_yingzi_app_YzCore_nativeIsRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    RUNNING.load(Ordering::SeqCst) as jboolean
}
