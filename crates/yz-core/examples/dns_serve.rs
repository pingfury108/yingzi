//! 本地 DNS 代理验证工具
//! 用法: cargo run --release -p yz-core --example dns_serve -- <listen> <geoip.dat> <geosite.dat>
//! 例:   dns_serve 127.0.0.1:5353 /tmp/geodata/geoip.dat /tmp/geodata/geosite.dat
//!
//! 规则: 广告拦截 / 国内域名直连 / 其余走 DoT

use std::sync::Arc;
use yz_core::dns::{DnsConfig, DnsService, Upstream};
use yz_core::geo::{GeoIpDb, GeoSiteDb};
use yz_core::policy::{Action, Rule, RuleSet};

/// 自检用: 只有 exit:// 上游时才需要真实隧道，这里由环境变量控制
fn build_cfg() -> anyhow::Result<DnsConfig> {
    let remote_spec = std::env::var("YZ_DNS_REMOTE")
        .unwrap_or_else(|_| "tls://1.1.1.1:853#cloudflare-dns.com".into());
    let direct_spec = std::env::var("YZ_DNS_DIRECT").unwrap_or_else(|_| "udp://223.5.5.5".into());
    let remote = remote_spec
        .split(',')
        .map(|s| Upstream::parse(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let direct = direct_spec
        .split(',')
        .map(|s| Upstream::parse(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(DnsConfig {
        remote,
        direct,
        ..Default::default()
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let listen = args.get(1).cloned().unwrap_or("127.0.0.1:5353".into());
    let geoip_path = args.get(2).cloned().unwrap_or("/tmp/geodata/geoip.dat".into());
    let geosite_path = args.get(3).cloned().unwrap_or("/tmp/geodata/geosite.dat".into());

    let geoip = GeoIpDb::parse(&std::fs::read(&geoip_path)?)?;
    let geosite = GeoSiteDb::parse(&std::fs::read(&geosite_path)?)?;

    let rules: Vec<Rule> = [
        "geosite:category-ads-all=block",
        "geosite:cn=direct",
        "geoip:private=direct",
    ]
    .iter()
    .map(|r| Rule::parse(r).unwrap())
    .collect();
    let rs = RuleSet::new(rules, Some(geoip), Some(geosite), Action::Exit(None));

    let cfg = build_cfg()?;
    let mut svc = DnsService::new(Arc::new(rs), cfg, None);

    // 若配置了 exit:// 上游, 注入隧道通道（需要 NS / 协调器）
    let has_exit = std::env::var("YZ_DNS_REMOTE")
        .map(|v| v.contains("exit://"))
        .unwrap_or(false);
    if has_exit {
        let secret = std::env::var("YZ_NETWORK_SECRET")?;
        let ns = yz_crypto::NetworkSecret::from_hex(&secret)?;
        let id_file = std::env::var("YZ_ID_FILE").unwrap_or_else(|_| "node.key".into());
        let pkcs8 = std::fs::read(&id_file)?;
        let id_pub = yz_crypto::load_identity(&pkcs8)?;
        let node_id = yz_crypto::node_id(&id_pub);

        // 连协调器（仅用于拿目录 + 建隧道）
        let coord = std::env::var("YZ_COORDINATOR")?;
        let state = Arc::new(yz_core::state::CoreState::default());
        let h = yz_core::tunnel::connect(&coord, &ns, &id_pub).await?;
        let t = h.tunnel.clone();
        *state.coord_tunnel.write().await = Some(t.clone());
        let mut ctrl = h.ctrl_rx;
        let state2 = state.clone();
        tokio::spawn(async move {
            while let Some(f) = ctrl.recv().await {
                if let yz_proto::Frame::Control { payload } = f {
                    if let Ok(yz_proto::ControlMsg::DirSync { nodes }) =
                        yz_proto::decode_control(&payload)
                    {
                        let mut d = state2.dir.write().await;
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
            name: format!("dns-test-{}", &node_id[..6]),
            addrs: vec![],
            udp_addr: String::new(),
            caps: 0,
        });
        t.write_frame(&yz_proto::Frame::Control { payload: hello })
            .await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let exit = yz_core::exit_dns::TunnelExitDns::new(state, ns, id_pub);
        svc = svc.with_exit_query(Arc::new(exit));
        println!("已注入出口 DNS 通道 (coordinator {coord})");
    }
    let svc = Arc::new(svc);

    // 自检模式: 不监听端口, 直接内部查询几个域名并打印结果
    if args.get(4).map(|s| s.as_str()) == Some("selftest") {
        use yz_core::dns::Message;
        for name in ["www.google.com", "github.com", "www.baidu.com", "doubleclick.net"] {
            let q = Message::query(name, 1);
            match tokio::time::timeout(std::time::Duration::from_secs(12), svc.handle_query(&q)).await {
                Ok(Ok(resp)) => {
                    let m = Message::parse(&resp)?;
                    let ips: Vec<String> = m.answers.iter().map(|a| a.3.to_string()).collect();
                    println!("{name:<20} -> {ips:?}");
                }
                Ok(Err(e)) => println!("{name:<20} -> 失败: {e:#}"),
                Err(_) => println!("{name:<20} -> 超时"),
            }
        }
        println!(
            "统计: remote={} direct={} blocked={} cache_hit={}",
            svc.stat_remote.load(std::sync::atomic::Ordering::Relaxed),
            svc.stat_direct.load(std::sync::atomic::Ordering::Relaxed),
            svc.stat_blocked.load(std::sync::atomic::Ordering::Relaxed),
            svc.stat_cache_hit.load(std::sync::atomic::Ordering::Relaxed),
        );
        return Ok(());
    }

    let sock = Arc::new(tokio::net::UdpSocket::bind(&listen).await?);
    println!("DNS 代理监听 {listen}");
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        let svc = svc.clone();
        let sock2 = sock.clone();
        let q = buf[..n].to_vec();
        tokio::spawn(async move {
            match svc.handle_query(&q).await {
                Ok(resp) => {
                    let _ = sock2.send_to(&resp, from).await;
                }
                Err(e) => eprintln!("查询失败: {e:#}"),
            }
        });
    }
}
