//! 地址与时间工具（桌面端与 Android 共用）

use std::time::{SystemTime, UNIX_EPOCH};

pub fn local_addrs(port: u16, explicit: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // 显式 advertise 优先 (通常是公网 IP)
    if let Some(a) = explicit {
        if let Some((host, p)) = a.rsplit_once(':') {
            if !host.is_empty() && host != "0.0.0.0" && host != "::" {
                out.push(format!("{host}:{p}"));
            }
        }
    }
    // 本机网卡地址 (通过 UDP connect 技巧拿到默认出口源 IP)
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                if let std::net::IpAddr::V4(v4) = addr.ip() {
                    if !v4.is_loopback() {
                        out.push(format!("{v4}:{port}"));
                    }
                }
            }
        }
    }
    // 遍历系统网卡 (Linux: /proc/net/route 太重; 用 getifaddrs 简化版: 读 /proc/net/fib_trie 太脏)
    // 折中: 用 `hostname -I` 等外部命令不可靠, 这里靠上面两项 + 下面 /proc/net/route 的本机地址
    #[cfg(target_os = "linux")]
    {
        // fib_trie 里混有网络地址/广播地址/容器网桥, 只保留像主机地址的
        if let Ok(txt) = std::fs::read_to_string("/proc/net/fib_trie") {
            for line in txt.lines() {
                let t = line.trim();
                let Some(rest) = t.strip_prefix("|-- ") else {
                    continue;
                };
                let Ok(ip) = rest.parse::<std::net::Ipv4Addr>() else {
                    continue;
                };
                if !ip.is_private() || ip.is_loopback() {
                    continue;
                }
                let o = ip.octets();
                // 跳过网络地址 / 广播地址
                if o[3] == 0 || o[3] == 255 {
                    continue;
                }
                // 跳过容器网桥段 (docker 默认 172.17-31.x)
                if o[0] == 172 && (17..=31).contains(&o[1]) {
                    continue;
                }
                out.push(format!("{ip}:{port}"));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 本机所有地址 (用于同网段匹配)
pub fn my_addrs() -> Vec<std::net::Ipv4Addr> {
    let mut v = Vec::new();
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:53").is_ok() {
            if let Ok(a) = sock.local_addr() {
                if let std::net::IpAddr::V4(v4) = a.ip() {
                    v.push(v4);
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(txt) = std::fs::read_to_string("/proc/net/fib_trie") {
            for line in txt.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("|-- ") {
                    if let Ok(ip) = rest.parse::<std::net::Ipv4Addr>() {
                        let o = ip.octets();
                        if ip.is_private()
                            && !ip.is_loopback()
                            && o[3] != 0
                            && o[3] != 255
                            && !(o[0] == 172 && (17..=31).contains(&o[1]))
                        {
                            v.push(ip);
                        }
                    }
                }
            }
        }
    }
    v
}

/// 从候选地址里挑一个: 与我方同 /24 网段优先, 其次任一私网, 最后第一个
pub fn pick_addr(addrs: &[String], prefer_lan: bool) -> Option<String> {
    if addrs.is_empty() {
        return None;
    }
    let mine = my_addrs();
    let same_subnet = |a: &String| -> bool {
        let Some((host, _)) = a.rsplit_once(':') else {
            return false;
        };
        let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        let o = ip.octets();
        mine.iter().any(|m| {
            let mo = m.octets();
            mo[0] == o[0] && mo[1] == o[1] && mo[2] == o[2]
        })
    };
    // 同 /24 网段最优
    if let Some(a) = addrs.iter().find(|a| same_subnet(a)) {
        return Some(a.clone());
    }
    if prefer_lan {
        if let Some(a) = addrs.iter().find(|a| is_lan_addr(a)) {
            return Some(a.clone());
        }
    }
    Some(addrs[0].clone())
}


/// 是否为私网/回环来源 (局域网 SOCKS5 只放行这些)
pub fn is_local_source(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}


/// 对端隧道地址是否私网/回环 (同网段可直连, 无需打洞)
pub fn is_lan_addr(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

/// 解析 exit 配置为具体决策

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

