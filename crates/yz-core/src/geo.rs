//! geo: 解析 v2ray 的 `geoip.dat` / `geosite.dat`，并提供高效匹配。
//!
//! 格式（protobuf）：
//! ```proto
//! message CIDR      { bytes ip = 1; uint32 prefix = 2; }
//! message GeoIP     { string country_code = 1; repeated CIDR cidr = 2; ... }
//! message GeoIPList { repeated GeoIP entry = 1; }
//! message Domain    { enum Type { Plain=0; Regex=1; Domain=2; Full=3; } Type type=1; string value=2; }
//! message GeoSite   { string country_code = 1; repeated Domain domain = 2; ... }
//! message GeoSiteList { repeated GeoSite entry = 1; }
//! ```
//!
//! 这里手写最小的 protobuf wire 解码（varint + length-delimited），
//! 避免引入 prost/protoc 构建依赖。

use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

// ---------- 极简 protobuf 读取 ----------

struct Pb<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Pb<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }

    fn varint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *self.b.get(self.pos).context("varint eof")?;
            self.pos += 1;
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift > 63 {
                bail!("varint too long");
            }
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()? as usize;
        let end = self.pos.checked_add(n).context("length overflow")?;
        if end > self.b.len() {
            bail!("length-delimited eof");
        }
        let out = &self.b[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// 读取下一个字段 (编号, wire type)，已消费 tag
    fn tag(&mut self) -> Result<Option<(u32, u8)>> {
        if self.done() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x7) as u8;
        Ok(Some((field, wire)))
    }

    fn skip(&mut self, wire: u8) -> Result<()> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.pos += 8,
            2 => {
                self.bytes()?;
            }
            5 => self.pos += 4,
            other => bail!("unsupported wire type {other}"),
        }
        if self.pos > self.b.len() {
            bail!("skip eof");
        }
        Ok(())
    }
}

// ---------- 单个 CIDR ----------

/// 单个 IPv4 CIDR（用于规则里的 cidr: 匹配器）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrV4 {
    pub base: u32,
    pub prefix: u8,
}

impl CidrV4 {
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        let (ip_s, prefix_s) = s
            .split_once('/')
            .ok_or_else(|| format!("cidr 需为 ip/prefix: {s}"))?;
        let ip: Ipv4Addr = ip_s
            .parse()
            .map_err(|_| format!("非法 IPv4: {s}"))?;
        let prefix: u8 = prefix_s.parse().map_err(|_| format!("非法前缀: {s}"))?;
        if prefix > 32 {
            return Err(format!("前缀超过 32: {s}"));
        }
        Ok(Self {
            base: u32::from(ip) & mask(prefix).unwrap_or(0),
            prefix,
        })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let m = mask(self.prefix);
        match m {
            None => true, // /0
            Some(m) => (u32::from(ip) & m) == self.base,
        }
    }
}

// ---------- CIDR 集合 ----------

/// 按前缀长度分桶的 CIDR 集合：单次查询最多 33 次哈希
#[derive(Default, Debug)]
pub struct CidrSet {
    by_prefix: Vec<HashSet<u32>>, // 下标 = 前缀长度 (0..=32)
}

impl CidrSet {
    /// 插入已按前缀掩码过的网络地址（供解析时批量搬运用）
    pub fn by_prefix_insert(&mut self, prefix: u8, masked: u32) {
        if prefix > 32 {
            return;
        }
        if self.by_prefix.is_empty() {
            self.by_prefix = (0..=32).map(|_| HashSet::new()).collect();
        }
        self.by_prefix[prefix as usize].insert(masked);
    }

    pub fn insert(&mut self, ip: u32, prefix: u8) {
        if prefix > 32 {
            return;
        }
        if self.by_prefix.is_empty() {
            self.by_prefix = (0..=32).map(|_| HashSet::new()).collect();
        }
        let masked = mask(prefix).map(|m| ip & m).unwrap_or(0);
        self.by_prefix[prefix as usize].insert(masked);
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.by_prefix.is_empty() {
            return false;
        }
        let v = u32::from(ip);
        for (prefix, set) in self.by_prefix.iter().enumerate() {
            if set.is_empty() {
                continue;
            }
            let key = match mask(prefix as u8) {
                Some(m) => v & m,
                None => 0,
            };
            if set.contains(&key) {
                return true;
            }
        }
        false
    }

    pub fn len(&self) -> usize {
        self.by_prefix.iter().map(|s| s.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn mask(prefix: u8) -> Option<u32> {
    if prefix == 0 {
        None
    } else if prefix >= 32 {
        Some(u32::MAX)
    } else {
        Some(u32::MAX << (32 - prefix))
    }
}

// ---------- 域名集合 ----------

#[derive(Default, Debug)]
pub struct DomainSet {
    /// 后缀匹配 (v2ray type=Domain)
    suffix: HashSet<String>,
    /// 精确匹配 (type=Full)
    full: HashSet<String>,
    /// 子串匹配 (type=Plain，较少用)
    plain: Vec<String>,
    /// 正则条目数量 (暂不支持，仅统计)
    pub regex_count: usize,
}

impl DomainSet {
    pub fn len(&self) -> usize {
        self.suffix.len() + self.full.len() + self.plain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, kind: u64, value: &str) {
        let v = value.trim().to_ascii_lowercase();
        if v.is_empty() {
            return;
        }
        match kind {
            0 => self.plain.push(v),
            1 => self.regex_count += 1, // 正则：暂不支持
            2 => {
                self.suffix.insert(v);
            }
            _ => {
                self.full.insert(v);
            }
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        let d = domain.trim().to_ascii_lowercase();
        if self.full.contains(&d) {
            return true;
        }
        // 逐级剥标签查后缀
        let mut cur = d.as_str();
        loop {
            if self.suffix.contains(cur) {
                return true;
            }
            match cur.find('.') {
                Some(i) => cur = &cur[i + 1..],
                None => break,
            }
        }
        self.plain.iter().any(|p| d.contains(p.as_str()))
    }
}

// ---------- 数据库 ----------

#[derive(Default, Debug)]
pub struct GeoIpDb {
    sets: HashMap<String, CidrSet>,
}

impl GeoIpDb {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut db = GeoIpDb::default();
        let mut pb = Pb::new(bytes);
        while let Some((field, wire)) = pb.tag()? {
            if field == 1 && wire == 2 {
                let entry = pb.bytes()?;
                let (code, cidrs) = parse_geoip_entry(entry)?;
                if !code.is_empty() {
                    let set = db.sets.entry(code).or_default();
                    for (prefix, keys) in cidrs.by_prefix.iter().enumerate() {
                        for k in keys {
                            set.by_prefix_insert(prefix as u8, *k);
                        }
                    }
                }
            } else {
                pb.skip(wire)?;
            }
        }
        Ok(db)
    }

    pub fn codes(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.sets.keys().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }

    pub fn contains(&self, code: &str, ip: Ipv4Addr) -> bool {
        self.sets
            .get(&code.to_ascii_lowercase())
            .map(|s| s.contains(ip))
            .unwrap_or(false)
    }

    pub fn set_len(&self, code: &str) -> usize {
        self.sets
            .get(&code.to_ascii_lowercase())
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

fn parse_geoip_entry(bytes: &[u8]) -> Result<(String, CidrSet)> {
    let mut pb = Pb::new(bytes);
    let mut code = String::new();
    let mut cidrs = CidrSet::default();
    while let Some((field, wire)) = pb.tag()? {
        match (field, wire) {
            (1, 2) => code = String::from_utf8_lossy(pb.bytes()?).to_ascii_lowercase(),
            (2, 2) => {
                let c = pb.bytes()?;
                let (ip, prefix) = parse_cidr(c)?;
                if let Some(ip) = ip {
                    cidrs.insert(ip, prefix);
                }
            }
            _ => pb.skip(wire)?,
        }
    }
    Ok((code, cidrs))
}

fn parse_cidr(bytes: &[u8]) -> Result<(Option<u32>, u8)> {
    let mut pb = Pb::new(bytes);
    let mut ip: Option<u32> = None;
    let mut prefix: u8 = 32;
    while let Some((field, wire)) = pb.tag()? {
        match (field, wire) {
            (1, 2) => {
                let b = pb.bytes()?;
                if b.len() == 4 {
                    ip = Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                } else {
                    ip = None; // IPv6 暂不支持
                }
            }
            (2, 0) => prefix = pb.varint()? as u8,
            _ => pb.skip(wire)?,
        }
    }
    Ok((ip, prefix))
}

#[derive(Default, Debug)]
pub struct GeoSiteDb {
    sets: HashMap<String, DomainSet>,
}

impl GeoSiteDb {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut db = GeoSiteDb::default();
        let mut pb = Pb::new(bytes);
        while let Some((field, wire)) = pb.tag()? {
            if field == 1 && wire == 2 {
                let entry = pb.bytes()?;
                let (code, domains) = parse_geosite_entry(entry)?;
                if !code.is_empty() {
                    let set = db.sets.entry(code).or_default();
                    for (kind, v) in domains {
                        set.insert(kind, &v);
                    }
                }
            } else {
                pb.skip(wire)?;
            }
        }
        Ok(db)
    }

    pub fn codes(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.sets.keys().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }

    pub fn matches(&self, code: &str, domain: &str) -> bool {
        self.sets
            .get(&code.to_ascii_lowercase())
            .map(|s| s.matches(domain))
            .unwrap_or(false)
    }

    pub fn set_len(&self, code: &str) -> usize {
        self.sets
            .get(&code.to_ascii_lowercase())
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

fn parse_geosite_entry(bytes: &[u8]) -> Result<(String, Vec<(u64, String)>)> {
    let mut pb = Pb::new(bytes);
    let mut code = String::new();
    let mut domains = Vec::new();
    while let Some((field, wire)) = pb.tag()? {
        match (field, wire) {
            (1, 2) => code = String::from_utf8_lossy(pb.bytes()?).to_ascii_lowercase(),
            (2, 2) => {
                let d = pb.bytes()?;
                let mut dp = Pb::new(d);
                let mut kind = 0u64;
                let mut value = String::new();
                while let Some((f, w)) = dp.tag()? {
                    match (f, w) {
                        (1, 0) => kind = dp.varint()?,
                        (2, 2) => value = String::from_utf8_lossy(dp.bytes()?).to_string(),
                        _ => dp.skip(w)?,
                    }
                }
                if !value.is_empty() {
                    domains.push((kind, value));
                }
            }
            _ => pb.skip(wire)?,
        }
    }
    Ok((code, domains))
}

// ---------- 测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    // 手工构造 protobuf 以便测试解码器
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn field_bytes(field: u32, data: &[u8], out: &mut Vec<u8>) {
        varint(((field << 3) | 2) as u64, out);
        varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    fn field_varint(field: u32, v: u64, out: &mut Vec<u8>) {
        varint(((field << 3) | 0) as u64, out);
        varint(v, out);
    }

    fn cidr_entry(ip: [u8; 4], prefix: u32) -> Vec<u8> {
        let mut c = Vec::new();
        field_bytes(1, &ip, &mut c);
        field_varint(2, prefix as u64, &mut c);
        c
    }

    fn geoip(code: &str, cidrs: &[([u8; 4], u32)]) -> Vec<u8> {
        let mut e = Vec::new();
        field_bytes(1, code.as_bytes(), &mut e);
        for (ip, p) in cidrs {
            field_bytes(2, &cidr_entry(*ip, *p), &mut e);
        }
        let mut list = Vec::new();
        field_bytes(1, &e, &mut list);
        list
    }

    fn domain(kind: u32, value: &str) -> Vec<u8> {
        let mut d = Vec::new();
        field_varint(1, kind as u64, &mut d);
        field_bytes(2, value.as_bytes(), &mut d);
        d
    }

    fn geosite(code: &str, domains: &[(u32, &str)]) -> Vec<u8> {
        let mut e = Vec::new();
        field_bytes(1, code.as_bytes(), &mut e);
        for (k, v) in domains {
            field_bytes(2, &domain(*k, v), &mut e);
        }
        let mut list = Vec::new();
        field_bytes(1, &e, &mut list);
        list
    }

    #[test]
    fn parse_geoip_and_match() {
        let dat = geoip(
            "cn",
            &[
                ([192, 168, 0, 0], 16),
                ([114, 114, 114, 0], 24),
                ([0, 0, 0, 0], 0), // /0 应匹配一切
            ],
        );
        let db = GeoIpDb::parse(&dat).unwrap();
        assert_eq!(db.codes(), vec!["cn"]);
        assert!(db.contains("cn", Ipv4Addr::new(192, 168, 1, 1)));
        assert!(db.contains("cn", Ipv4Addr::new(114, 114, 114, 114)));
        assert!(db.contains("cn", Ipv4Addr::new(8, 8, 8, 8))); // /0
        assert!(!db.contains("us", Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn parse_geoip_without_slash0() {
        let dat = geoip("private", &[([10, 0, 0, 0], 8), ([192, 168, 0, 0], 16)]);
        let db = GeoIpDb::parse(&dat).unwrap();
        assert!(db.contains("private", Ipv4Addr::new(10, 1, 2, 3)));
        assert!(db.contains("private", Ipv4Addr::new(192, 168, 5, 5)));
        assert!(!db.contains("private", Ipv4Addr::new(11, 0, 0, 1)));
        assert!(!db.contains("private", Ipv4Addr::new(172, 16, 0, 1)));
    }

    #[test]
    fn parse_geosite_and_match() {
        let dat = geosite(
            "category-ads-all",
            &[
                (2, "doubleclick.net"), // Domain 后缀
                (3, "ads.example.com"), // Full 精确
                (0, "adserver"),        // Plain 子串
            ],
        );
        let db = GeoSiteDb::parse(&dat).unwrap();
        assert_eq!(db.codes(), vec!["category-ads-all"]);
        assert!(db.matches("category-ads-all", "doubleclick.net"));
        assert!(db.matches("category-ads-all", "tpc.doubleclick.net"));
        assert!(db.matches("category-ads-all", "ads.example.com"));
        assert!(!db.matches("category-ads-all", "x.ads.example.com")); // Full 不匹配子域
        assert!(db.matches("category-ads-all", "my-adserver-host.com"));
        assert!(!db.matches("category-ads-all", "google.com"));
    }

    #[test]
    fn domain_suffix_does_not_match_similar() {
        let dat = geosite("cn", &[(2, "baidu.com")]);
        let db = GeoSiteDb::parse(&dat).unwrap();
        assert!(db.matches("cn", "www.baidu.com"));
        assert!(db.matches("cn", "baidu.com"));
        assert!(!db.matches("cn", "notbaidu.com")); // 不能误匹配
        assert!(!db.matches("cn", "baidu.com.evil.org"));
    }

    #[test]
    fn empty_and_garbage_input() {
        assert!(GeoIpDb::parse(&[]).unwrap().codes().is_empty());
        assert!(GeoSiteDb::parse(&[]).unwrap().codes().is_empty());
        // 随机字节不应 panic
        let _ = GeoIpDb::parse(&[0xff, 0xff, 0xff]);
        let _ = GeoSiteDb::parse(&[0xff, 0xff, 0xff]);
    }
}
