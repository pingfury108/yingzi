//! 在指定 TUN 设备上运行用户态栈（UDP 分流验证）
//!
//! 用法: stack_run <tun名> <geoip.dat> <geosite.dat> [exit节点名]
//! 环境: YZ_NETWORK_SECRET / YZ_ID_FILE / YZ_COORDINATOR（配置 exit 时需要）

use std::sync::Arc;
use yz_core::dns::{DnsConfig, DnsService, Upstream};
use yz_core::geo::{GeoIpDb, GeoSiteDb};
use yz_core::mesh::PacketIo;
use yz_core::policy::{Action, Rule, RuleSet};
use yz_core::stack::{Stack, StackConfig};

struct TunIo {
    dev: Arc<tun::AsyncDevice>,
}

impl PacketIo for TunIo {
    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<usize>> + Send + 'a>>
    {
        Box::pin(async move { Ok(self.dev.recv(buf).await?) })
    }
    fn send<'a>(
        &'a self,
        pkt: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>>
    {
        Box::pin(async move {
            self.dev.send(pkt).await?;
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    let tun_name = args.get(1).cloned().unwrap_or("yzs0".into());
    let geoip_path = args.get(2).cloned().unwrap_or("/tmp/geodata/geoip.dat".into());
    let geosite_path = args.get(3).cloned().unwrap_or("/tmp/geodata/geosite.dat".into());
    let exit_node = args.get(4).cloned();

    // TUN（地址由外部 ip 命令配置，这里只读写）
    let mut cfg = tun::Configuration::default();
    cfg.tun_name(&tun_name).mtu(1400).up();
    let dev = Arc::new(tun::create_as_async(&cfg)?);
    println!("TUN {tun_name} 就绪");

    // 规则
    let geoip = GeoIpDb::parse(&std::fs::read(&geoip_path)?)?;
    let geosite = GeoSiteDb::parse(&std::fs::read(&geosite_path)?)?;
    let mut rule_specs = vec![
        "geosite:category-ads-all=block".to_string(),
        "geosite:cn=direct".to_string(),
        "geoip:cn=direct".to_string(),
        "geoip:private=direct".to_string(),
    ];
    let default_action = match &exit_node {
        Some(n) => {
            rule_specs.push(format!("domain-suffix:google.com=exit:{n}"));
            Action::Exit(Some(n.clone()))
        }
        None => Action::Direct,
    };
    let rules: Vec<Rule> = rule_specs.iter().map(|r| Rule::parse(r).unwrap()).collect();
    let rs = Arc::new(RuleSet::new(rules, Some(geoip), Some(geosite), default_action));

    // DNS: 有 exit 节点则经出口解析，否则直连
    let remote = match &exit_node {
        Some(n) => vec![Upstream::parse(&format!("exit://{n}/1.1.1.1:53"))?],
        None => vec![Upstream::parse("udp://223.5.5.5")?],
    };
    let dns_cfg = DnsConfig {
        remote,
        direct: vec![Upstream::parse("udp://223.5.5.5")?],
        ..Default::default()
    };

    // 需要出口通道时才连协调器
    let state = Arc::new(yz_core::state::CoreState::default());
    let mut dns = DnsService::new(rs.clone(), dns_cfg, None);
    let mut exit_udp: Option<Arc<dyn yz_core::stack::ExitUdp>> = None;
    let mut exit_tcp: Option<Arc<dyn yz_core::tcp_stack::ExitTcp>> = None;

    if exit_node.is_some() {
        let secret = std::env::var("YZ_NETWORK_SECRET")?;
        let ns = yz_crypto::NetworkSecret::from_hex(&secret)?;
        let id_file = std::env::var("YZ_ID_FILE")?;
        let id_pub = yz_crypto::load_identity(&std::fs::read(&id_file)?)?;
        let node_id = yz_crypto::node_id(&id_pub);
        let coord = std::env::var("YZ_COORDINATOR")?;

        let h = yz_core::tunnel::connect(&coord, &ns, &id_pub).await?;
        let t = h.tunnel.clone();
        *state.coord_tunnel.write().await = Some(t.clone());
        let st = state.clone();
        let mut ctrl = h.ctrl_rx;
        tokio::spawn(async move {
            while let Some(f) = ctrl.recv().await {
                if let yz_proto::Frame::Control { payload } = f {
                    if let Ok(yz_proto::ControlMsg::DirSync { nodes }) =
                        yz_proto::decode_control(&payload)
                    {
                        let mut d = st.dir.write().await;
                        d.clear();
                        for n in nodes {
                            d.insert(n.node_id.clone(), n);
                        }
                    }
                }
            }
        });
        let hello = yz_proto::encode_control(&yz_proto::ControlMsg::Hello {
            version: 1,
            name: format!("stack-{}", &node_id[..6]),
            addrs: vec![],
            udp_addr: String::new(),
            caps: 0,
        });
        t.write_frame(&yz_proto::Frame::Control { payload: hello }).await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        dns = dns.with_exit_query(Arc::new(yz_core::exit_dns::TunnelExitDns::new(
            state.clone(),
            ns.clone(),
            id_pub,
        )));
        exit_udp = Some(Arc::new(yz_core::exit_udp::TunnelExitUdp::new(
            state.clone(),
            ns.clone(),
            id_pub,
        )));
        exit_tcp = Some(Arc::new(yz_core::exit_udp::TunnelExitTcp::new(
            state.clone(),
            ns,
            id_pub,
        )));
        println!("出口通道就绪: {coord}");
    }

    let dns = Arc::new(dns);
    let stack = Arc::new(Stack::new(
        rs.clone(),
        state.clone(),
        StackConfig {
            dns: Some(dns.clone()),
            exit: exit_udp,
            ..Default::default()
        },
    ));

    let io: Arc<dyn PacketIo> = Arc::new(TunIo { dev });
    println!("栈启动");

    // TCP 用户态栈：由主循环把 TCP 包分发进来
    let (tcp_tx, tcp_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    let tcp = Arc::new(yz_core::tcp_stack::TcpStack::new(
        rs.clone(),
        yz_core::tcp_stack::TcpStackConfig {
            events: None,
            mtu: 1400,
            protect: None,
            exit: exit_tcp,
            max_conns: 400,
        },
    ));
    {
        let tcp = tcp.clone();
        let io2 = io.clone();
        let de = exit_node.clone();
        tokio::spawn(async move {
            if let Err(e) = tcp.run(io2, tcp_rx, de).await {
                eprintln!("TCP 栈退出: {e:#}");
            }
        });
    }
    // 单读循环分发：UDP → UDP 栈；TCP → tcp 栈
    let mut buf = vec![0u8; 2048];
    loop {
        let n = io.recv(&mut buf).await?;
        let pkt = buf[..n].to_vec();
        if yz_core::stack::parse_udp(&pkt).is_none() {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n < 5 || n % 200 == 0 {
                log::debug!("TCP 包 #{n} 长度 {} -> 栈", pkt.len());
            }
            let _ = tcp_tx.try_send(pkt);
            continue;
        }
        let stack = stack.clone();
        let io2 = io.clone();
        tokio::spawn(async move {
            if let Err(e) = stack.handle_packet(&io2, &pkt).await {
                log::debug!("handle_packet: {e:#}");
            }
        });
    }
}
