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

// ============================================================
// 规则引擎（Android 客户端 / 后续桌面 TUN 使用）
// 与上面的 RouteRule（桌面 SOCKS5 现有分流）并存，互不影响。
// ============================================================

use crate::geo::{CidrV4, GeoIpDb, GeoSiteDb};
use std::net::Ipv4Addr;

/// 规则动作
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// 直连（由本机物理网卡发出）
    Direct,
    /// 走出口节点；None = 默认出口
    Exit(Option<String>),
    /// 拦截
    Block,
}

impl Action {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        match s {
            "direct" => Ok(Action::Direct),
            "block" | "reject" => Ok(Action::Block),
            "exit" | "proxy" => Ok(Action::Exit(None)),
            other => {
                if let Some(node) = other.strip_prefix("exit:") {
                    if node.is_empty() {
                        return Err("exit: 需要节点名".into());
                    }
                    Ok(Action::Exit(Some(node.to_string())))
                } else {
                    Err(format!("未知动作: {other}"))
                }
            }
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Action::Direct => "direct".into(),
            Action::Block => "block".into(),
            Action::Exit(None) => "exit".into(),
            Action::Exit(Some(n)) => format!("exit:{n}"),
        }
    }
}

/// 匹配器
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMatcher {
    /// geoip:cn / geoip:private
    GeoIp(String),
    /// geosite:cn / geosite:category-ads-all
    GeoSite(String),
    /// 单个 CIDR
    Cidr(CidrV4),
    /// 域名后缀（含子域）
    DomainSuffix(String),
    /// 域名精确
    DomainFull(String),
    /// 目标端口
    Port(u16),
    /// Android 包名
    App(String),
}

impl RuleMatcher {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(v) = s.strip_prefix("geoip:") {
            return Ok(RuleMatcher::GeoIp(v.to_ascii_lowercase()));
        }
        if let Some(v) = s.strip_prefix("geosite:") {
            return Ok(RuleMatcher::GeoSite(v.to_ascii_lowercase()));
        }
        if let Some(v) = s.strip_prefix("domain-suffix:") {
            return Ok(RuleMatcher::DomainSuffix(v.to_ascii_lowercase()));
        }
        if let Some(v) = s.strip_prefix("domain:") {
            return Ok(RuleMatcher::DomainFull(v.to_ascii_lowercase()));
        }
        if let Some(v) = s.strip_prefix("cidr:") {
            return CidrV4::parse(v).map(RuleMatcher::Cidr);
        }
        if let Some(v) = s.strip_prefix("port:") {
            return v
                .parse::<u16>()
                .map(RuleMatcher::Port)
                .map_err(|_| format!("端口非法: {v}"));
        }
        if let Some(v) = s.strip_prefix("app:") {
            return Ok(RuleMatcher::App(v.to_string()));
        }
        Err(format!("未知匹配器: {s}"))
    }

    /// 是否可用于域名判定
    fn is_domain_matcher(&self) -> bool {
        matches!(
            self,
            RuleMatcher::GeoSite(_) | RuleMatcher::DomainSuffix(_) | RuleMatcher::DomainFull(_)
        )
    }

    /// 是否可用于 IP 判定
    fn is_ip_matcher(&self) -> bool {
        matches!(self, RuleMatcher::GeoIp(_) | RuleMatcher::Cidr(_))
    }
}

/// 一条规则
#[derive(Debug, Clone)]
pub struct Rule {
    pub matcher: RuleMatcher,
    pub action: Action,
    /// 原始文本（展示 / 命中追踪用）
    pub raw: String,
}

impl Rule {
    /// "geosite:category-ads-all=block" 形式
    pub fn parse(s: &str) -> Result<Self, String> {
        let (m, a) = s
            .split_once('=')
            .ok_or_else(|| format!("规则需为 matcher=action: {s}"))?;
        let matcher = RuleMatcher::parse(m)?;
        let action = Action::parse(a)?;
        Ok(Rule {
            matcher,
            action,
            raw: s.trim().to_string(),
        })
    }
}

/// 一次判定的结果（含命中原因，便于 UI 展示）
#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
}

/// 规则集：规则按序匹配 → geo 预设 → 默认动作
pub struct RuleSet {
    rules: std::sync::RwLock<Vec<Rule>>,
    geoip: Option<GeoIpDb>,
    geosite: Option<GeoSiteDb>,
    default_action: Action,
}

impl RuleSet {
    pub fn new(
        rules: Vec<Rule>,
        geoip: Option<GeoIpDb>,
        geosite: Option<GeoSiteDb>,
        default_action: Action,
    ) -> Self {
        Self {
            rules: std::sync::RwLock::new(rules),
            geoip,
            geosite,
            default_action,
        }
    }

    /// 热更新规则（保留 geo 库与默认动作）
    pub fn replace_rules(&self, rules: Vec<Rule>) {
        if let Ok(mut w) = self.rules.write() {
            *w = rules;
        }
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.rules.read().map(|r| r.clone()).unwrap_or_default()
    }

    /// 域名判定（按序，跳过纯 IP 匹配器）
    pub fn decide_domain(&self, domain: &str) -> Decision {
        let d = domain.trim().to_ascii_lowercase();
        let rules = match self.rules.read() {
            Ok(r) => r,
            Err(_) => return Decision { action: self.default_action.clone(), reason: "规则锁异常".into() },
        };
        for r in rules.iter() {
            if !r.matcher.is_domain_matcher() {
                continue;
            }
            let hit = match &r.matcher {
                RuleMatcher::DomainSuffix(suf) => {
                    d == *suf || d.ends_with(&format!(".{suf}"))
                }
                RuleMatcher::DomainFull(want) => d == *want,
                RuleMatcher::GeoSite(code) => self
                    .geosite
                    .as_ref()
                    .map(|db| db.matches(code, &d))
                    .unwrap_or(false),
                _ => false,
            };
            if hit {
                return Decision {
                    action: r.action.clone(),
                    reason: format!("命中规则 {}", r.raw),
                };
            }
        }
        Decision {
            action: self.default_action.clone(),
            reason: "默认动作".into(),
        }
    }

    /// IP 判定（按序，跳过纯域名匹配器）
    pub fn decide_ip(&self, ip: Ipv4Addr) -> Decision {
        let rules = match self.rules.read() {
            Ok(r) => r,
            Err(_) => return Decision { action: self.default_action.clone(), reason: "规则锁异常".into() },
        };
        for r in rules.iter() {
            if !r.matcher.is_ip_matcher() {
                continue;
            }
            let hit = match &r.matcher {
                RuleMatcher::Cidr(c) => c.contains(ip),
                RuleMatcher::GeoIp(code) => self
                    .geoip
                    .as_ref()
                    .map(|db| db.contains(code, ip))
                    .unwrap_or(false),
                _ => false,
            };
            if hit {
                return Decision {
                    action: r.action.clone(),
                    reason: format!("命中规则 {}", r.raw),
                };
            }
        }
        Decision {
            action: self.default_action.clone(),
            reason: "默认动作".into(),
        }
    }
}

#[cfg(test)]
mod rule_engine_tests {
    use super::*;

    fn rs(rules: &[&str]) -> RuleSet {
        let parsed: Vec<Rule> = rules.iter().map(|r| Rule::parse(r).unwrap()).collect();
        RuleSet::new(parsed, None, None, Action::Exit(None))
    }

    #[test]
    fn parse_rules() {
        assert_eq!(
            Rule::parse("geoip:cn=direct").unwrap().action,
            Action::Direct
        );
        assert_eq!(
            Rule::parse("geosite:category-ads-all=block").unwrap().action,
            Action::Block
        );
        assert_eq!(
            Rule::parse("domain-suffix:google.com=exit:vps-tokyo")
                .unwrap()
                .action,
            Action::Exit(Some("vps-tokyo".into()))
        );
        assert!(Rule::parse("cidr:192.168.0.0/16=direct").is_ok());
        assert!(Rule::parse("port:53=direct").is_ok());
        assert!(Rule::parse("app:com.example=direct").is_ok());
        assert!(Rule::parse("bogus=direct").is_err());
        assert!(Rule::parse("geoip:cn=bogus-action").is_err());
    }

    #[test]
    fn domain_decisions() {
        let s = rs(&[
            "domain-suffix:ads.example.com=block",
            "domain:exact.example.com=direct",
            "domain-suffix:google.com=exit:overseas",
        ]);
        assert_eq!(s.decide_domain("x.ads.example.com").action, Action::Block);
        assert_eq!(s.decide_domain("exact.example.com").action, Action::Direct);
        assert_eq!(
            s.decide_domain("www.google.com").action,
            Action::Exit(Some("overseas".into()))
        );
        assert_eq!(s.decide_domain("baidu.com").action, Action::Exit(None));
        assert!(s.decide_domain("www.google.com").reason.contains("google.com"));
    }

    #[test]
    fn ip_decisions() {
        let s = rs(&["cidr:10.0.0.0/8=direct", "cidr:1.1.1.0/24=block"]);
        assert_eq!(s.decide_ip("10.1.2.3".parse().unwrap()).action, Action::Direct);
        assert_eq!(s.decide_ip("1.1.1.1".parse().unwrap()).action, Action::Block);
        assert_eq!(s.decide_ip("8.8.8.8".parse().unwrap()).action, Action::Exit(None));
    }

    #[test]
    fn matchers_are_scoped() {
        // 域名规则不应影响 IP 判定，反之亦然
        let s = rs(&["domain-suffix:google.com=block", "cidr:8.8.8.8/32=direct"]);
        assert_eq!(s.decide_ip("8.8.8.8".parse().unwrap()).action, Action::Direct);
        assert_eq!(s.decide_domain("google.com").action, Action::Block);
        assert_eq!(s.decide_domain("8.8.8.8").action, Action::Exit(None));
    }
}
