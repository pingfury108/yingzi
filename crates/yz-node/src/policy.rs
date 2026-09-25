//! 出口策略路由与 ACL (plan.md §5)。
//! 规则格式: "matcher=exit", 例:
//!   domain-suffix:google.com=vps-tokyo
//!   domain:example.com=direct
//!   cidr:192.168.0.0/16=nas-home
//! exit 取值: direct | auto | 节点名/node_id前缀

use std::fmt;
use yz_proto::Addr;

impl fmt::Display for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Matcher::DomainSuffix(s) => write!(f, "domain-suffix:{s}"),
            Matcher::DomainExact(s) => write!(f, "domain:{s}"),
            Matcher::Cidr {
                v6: false,
                base,
                prefix,
            } => write!(f, "cidr:{}/{}", std::net::Ipv4Addr::from(*base as u32), prefix),
            Matcher::Cidr {
                v6: true,
                base,
                prefix,
            } => write!(f, "cidr:{}/{}", std::net::Ipv6Addr::from(*base), prefix),
        }
    }
}

impl fmt::Display for RouteRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.matcher, self.exit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    DomainSuffix(String),
    DomainExact(String),
    /// base 为网络地址的 u128 (v4 映射进低 32 位)
    Cidr { v6: bool, base: u128, prefix: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    pub matcher: Matcher,
    pub exit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitAcl {
    All,
    None,
    List(Vec<String>),
}

impl ExitAcl {
    /// "all" | "none" | "id1,id2,..."
    pub fn parse(s: &str) -> Self {
        match s.trim() {
            "all" => ExitAcl::All,
            "none" | "" => ExitAcl::None,
            s => ExitAcl::List(s.split(',').map(|x| x.trim().to_string()).collect()),
        }
    }

    pub fn allows(&self, node_id: &str) -> bool {
        match self {
            ExitAcl::All => true,
            ExitAcl::None => false,
            ExitAcl::List(l) => l.iter().any(|x| node_id == x || node_id.starts_with(x.as_str())),
        }
    }

    /// 是否对外声明「我可当出口」
    pub fn advertise(&self) -> bool {
        !matches!(self, ExitAcl::None)
    }
}

impl RouteRule {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (m, exit) = s
            .split_once('=')
            .ok_or_else(|| format!("rule must be matcher=exit: {s}"))?;
        let matcher = Matcher::parse(m.trim())?;
        let exit = exit.trim();
        if exit.is_empty() {
            return Err(format!("empty exit in rule: {s}"));
        }
        Ok(RouteRule {
            matcher,
            exit: exit.to_string(),
        })
    }
}

impl Matcher {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (kind, val) = s
            .split_once(':')
            .ok_or_else(|| format!("matcher must be kind:value: {s}"))?;
        let val = val.trim();
        match kind.trim() {
            "domain-suffix" => Ok(Matcher::DomainSuffix(val.to_lowercase())),
            "domain" => Ok(Matcher::DomainExact(val.to_lowercase())),
            "cidr" => parse_cidr(val),
            other => Err(format!("unknown matcher kind: {other}")),
        }
    }

    pub fn matches(&self, addr: &Addr) -> bool {
        match (self, addr) {
            (Matcher::DomainSuffix(suf), Addr::Domain(d, _)) => {
                let d = d.to_lowercase();
                d == *suf || d.ends_with(&format!(".{suf}"))
            }
            (Matcher::DomainExact(want), Addr::Domain(d, _)) => d.to_lowercase() == *want,
            (
                Matcher::Cidr {
                    v6: false,
                    base,
                    prefix,
                },
                Addr::V4(ip, _),
            ) => cidr_match32(*base as u32, *prefix, u32::from_be_bytes(*ip)),
            (
                Matcher::Cidr {
                    v6: true,
                    base,
                    prefix,
                },
                Addr::V6(ip, _),
            ) => cidr_match(*base, *prefix, u128::from_be_bytes(*ip)),
            _ => false,
        }
    }
}

fn parse_cidr(s: &str) -> Result<Matcher, String> {
    let (ip_s, prefix_s) = s
        .split_once('/')
        .ok_or_else(|| format!("cidr must be ip/prefix: {s}"))?;
    let prefix: u8 = prefix_s.parse().map_err(|_| format!("bad prefix: {s}"))?;
    if let Ok(v4) = ip_s.parse::<std::net::Ipv4Addr>() {
        if prefix > 32 {
            return Err(format!("v4 prefix > 32: {s}"));
        }
        let base = (u32::from(v4) & mask32(prefix)) as u128;
        Ok(Matcher::Cidr {
            v6: false,
            base,
            prefix,
        })
    } else if let Ok(v6) = ip_s.parse::<std::net::Ipv6Addr>() {
        if prefix > 128 {
            return Err(format!("v6 prefix > 128: {s}"));
        }
        let base = u128::from(v6) & mask128(prefix);
        Ok(Matcher::Cidr {
            v6: true,
            base,
            prefix,
        })
    } else {
        Err(format!("bad ip: {s}"))
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn cidr_match32(base: u32, prefix: u8, ip: u32) -> bool {
    if prefix == 0 {
        return true;
    }
    (base >> (32 - prefix)) == (ip >> (32 - prefix))
}

fn cidr_match(base: u128, prefix: u8, ip: u128) -> bool {
    if prefix == 0 {
        return true;
    }
    (base >> (128 - prefix)) == (ip >> (128 - prefix))
}

/// 返回第一条命中的 exit; 无命中返回 None (走默认)
pub fn match_route<'r>(rules: &'r [RouteRule], addr: &Addr) -> Option<&'r str> {
    rules
        .iter()
        .find(|r| r.matcher.matches(addr))
        .map(|r| r.exit.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_parse_and_match() {
        let rules = vec![
            RouteRule::parse("domain-suffix:google.com=vps-tokyo").unwrap(),
            RouteRule::parse("domain:example.com=direct").unwrap(),
            RouteRule::parse("cidr:192.168.0.0/16=nas-home").unwrap(),
            RouteRule::parse("cidr:::1/128=local6").unwrap(),
        ];
        assert_eq!(
            match_route(&rules, &Addr::Domain("www.google.com".into(), 443)),
            Some("vps-tokyo")
        );
        assert_eq!(
            match_route(&rules, &Addr::Domain("google.com".into(), 443)),
            Some("vps-tokyo")
        );
        assert_eq!(
            match_route(&rules, &Addr::Domain("example.com".into(), 80)),
            Some("direct")
        );
        assert_eq!(
            match_route(&rules, &Addr::V4([192, 168, 1, 5], 22)),
            Some("nas-home")
        );
        assert_eq!(match_route(&rules, &Addr::V4([10, 0, 0, 1], 22)), None);
        assert_eq!(
            match_route(&rules, &Addr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 22)),
            Some("local6")
        );
        assert!(match_route(&rules, &Addr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 22))
            .is_none());
    }

    #[test]
    fn acl() {
        assert!(ExitAcl::parse("all").allows("anyone"));
        assert!(!ExitAcl::parse("none").allows("anyone"));
        let l = ExitAcl::parse("0123456789abcdef,beef");
        assert!(l.allows("0123456789abcdef"));
        assert!(l.allows("beef0000dead")); // 前缀匹配
        assert!(!l.allows("cafe"));
        assert!(ExitAcl::parse("all").advertise());
        assert!(!ExitAcl::parse("none").advertise());
    }
}
