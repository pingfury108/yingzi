//! 用真实 geoip.dat / geosite.dat 验证解析与匹配
//! 用法: cargo run --release -p yz-core --example geo_check -- <geoip.dat> <geosite.dat>

use std::net::Ipv4Addr;
use yz_core::geo::{GeoIpDb, GeoSiteDb};
use yz_core::policy::{Action, Rule, RuleSet};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let geoip_path = args.get(1).map(|s| s.as_str()).unwrap_or("/tmp/geodata/geoip.dat");
    let geosite_path = args.get(2).map(|s| s.as_str()).unwrap_or("/tmp/geodata/geosite.dat");

    let t0 = std::time::Instant::now();
    let geoip = GeoIpDb::parse(&std::fs::read(geoip_path)?)?;
    let t1 = std::time::Instant::now();
    let geosite = GeoSiteDb::parse(&std::fs::read(geosite_path)?)?;
    let t2 = std::time::Instant::now();

    println!("geoip  解析 {:?}, 类别 {}", t1 - t0, geoip.codes().len());
    println!("geosite 解析 {:?}, 类别 {}", t2 - t1, geosite.codes().len());
    println!("geoip cn 条目数: {}", geoip.set_len("cn"));
    println!("geosite cn 条目数: {}", geosite.set_len("cn"));
    println!("geosite category-ads-all 条目数: {}", geosite.set_len("category-ads-all"));

    // 命中测试
    let cn_ips = ["114.114.114.114", "223.5.5.5", "1.2.4.8", "192.168.1.1"];
    for ip in cn_ips {
        let a: Ipv4Addr = ip.parse().unwrap();
        println!("  geoip:cn {ip} -> {}", geoip.contains("cn", a));
    }
    let foreign = ["8.8.8.8", "1.1.1.1", "142.250.1.1"];
    for ip in foreign {
        let a: Ipv4Addr = ip.parse().unwrap();
        println!("  geoip:cn {ip} -> {}", geoip.contains("cn", a));
    }

    let domains = [
        ("www.baidu.com", "cn"),
        ("www.qq.com", "cn"),
        ("www.google.com", "cn"),
        ("doubleclick.net", "category-ads-all"),
        ("googleads.g.doubleclick.net", "category-ads-all"),
        ("www.google.com", "google"),
    ];
    for (d, code) in domains {
        println!("  geosite:{code} {d} -> {}", geosite.matches(code, d));
    }

    // 规则引擎端到端
    let rules: Vec<Rule> = [
        "geosite:category-ads-all=block",
        "geoip:private=direct",
        "geosite:cn=direct",
        "geoip:cn=direct",
        "domain-suffix:google.com=exit:overseas-hk",
    ]
    .iter()
    .map(|r| Rule::parse(r).unwrap())
    .collect();
    let rs = RuleSet::new(rules, Some(geoip), Some(geosite), Action::Exit(None));

    println!("\n=== 规则判定 ===");
    for d in ["www.baidu.com", "doubleclick.net", "www.google.com", "netflix.com"] {
        let dec = rs.decide_domain(d);
        println!("  {d:<28} -> {:<16} ({})", dec.action.as_str(), dec.reason);
    }
    for ip in ["223.5.5.5", "192.168.1.1", "8.8.8.8", "1.1.1.1"] {
        let dec = rs.decide_ip(ip.parse().unwrap());
        println!("  {ip:<28} -> {:<16} ({})", dec.action.as_str(), dec.reason);
    }

    // 性能: 1 万次查询
    let t = std::time::Instant::now();
    let mut hit = 0;
    for i in 0..10_000u32 {
        let ip = Ipv4Addr::from(0x0e00_0000 + i * 977);
        if matches!(rs.decide_ip(ip).action, Action::Direct) {
            hit += 1;
        }
    }
    // 内存峰值 (Android 上很关键)
    if let Ok(st) = std::fs::read_to_string("/proc/self/status") {
        for line in st.lines() {
            if line.starts_with("VmHWM") || line.starts_with("VmRSS") {
                println!("  {line}");
            }
        }
    }
    println!("\n1万次 IP 判定: {:?} (direct {hit})", t.elapsed());
    let t = std::time::Instant::now();
    for i in 0..10_000u32 {
        let d = format!("host{i}.example{i}.com");
        let _ = rs.decide_domain(&d);
    }
    println!("1万次域名判定: {:?}", t.elapsed());
    Ok(())
}
