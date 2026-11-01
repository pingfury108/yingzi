//! Fake-IP：给代理域名分配 198.18.0.0/15 的假地址
//!
//! 好处：DNS 立即返回（不等上游）、域名规则在 TCP 连接时仍然生效、
//! 避免本地 DNS 污染影响分流。真实解析推迟到连接建立时（在出口侧完成）。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

/// RFC 2544 基准测试网段，日常不会被真实服务使用
const BASE: u32 = 0xC612_0000; // 198.18.0.0
const SIZE: u32 = 1 << 17; // /15 → 131072 个地址
const MAX_ENTRIES: usize = 8192;

#[derive(Default)]
struct Inner {
    by_domain: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
    next: u32,
}

#[derive(Default)]
pub struct FakeIp {
    inner: RwLock<Inner>,
}

impl FakeIp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        v >= BASE && v < BASE + SIZE
    }

    /// 域名 → 假 IP（同一域名稳定复用）
    pub fn alloc(&self, domain: &str) -> Ipv4Addr {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(ip) = inner.by_domain.get(&domain) {
            return *ip;
        }
        // 满了就先清空（简单可靠；正常使用不会触发）
        if inner.by_domain.len() >= MAX_ENTRIES {
            inner.by_domain.clear();
            inner.by_ip.clear();
        }
        loop {
            let v = BASE + (inner.next % SIZE);
            inner.next = inner.next.wrapping_add(1);
            let ip = Ipv4Addr::from(v);
            // 跳过 .0 / .255 之类看起来像广播的地址（不重要，但便于排查）
            if v & 0xff == 0 || v & 0xff == 0xff {
                continue;
            }
            if inner.by_ip.contains_key(&ip) {
                continue;
            }
            inner.by_domain.insert(domain.clone(), ip);
            inner.by_ip.insert(ip, domain);
            return ip;
        }
    }

    /// 假 IP → 域名
    pub fn domain(&self, ip: Ipv4Addr) -> Option<String> {
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.by_ip.get(&ip).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.by_domain.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_lookup() {
        let f = FakeIp::new();
        let a = f.alloc("www.google.com");
        let b = f.alloc("www.google.com");
        assert_eq!(a, b, "同域名必须稳定");
        assert!(f.contains(a));
        assert_eq!(f.domain(a).as_deref(), Some("www.google.com"));
        let c = f.alloc("github.com");
        assert_ne!(a, c);
        assert!(!f.contains(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
