//! HTTP 代理前端（CONNECT 隧道 + 绝对 URI 转发）
//!
//! 只做协议解析与报文重写，选路/建流复用 `node::open_upstream`。
//!
//! 覆盖三种形态：
//! 1. `CONNECT host:port HTTP/1.1`  → 200 + 裸字节隧道（HTTPS/WSS 走这条）
//! 2. `GET http://host/path HTTP/1.1` → 重写为 origin-form 后转发
//! 3. `Proxy-Authorization: Basic`  → 缺失/错误回 407
//!
//! v1 取舍：明文 HTTP 一律 `Connection: close`（一个连接一个请求）。
//! keep-alive 下浏览器会在同一连接上换目标主机，需要逐请求重解析+重开上游，
//! 而明文 HTTP 在真实流量里占比极小，先保证正确性。

use crate::node::{open_upstream, Upstream};
use anyhow::{bail, Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use yz_core::peer::PeerCtx;
use yz_core::state::CoreState;
use yz_core::tunnel;
use yz_proto::{Addr, Frame};
use yz_crypto::NetworkSecret;

/// 请求头上限
const MAX_HEAD: usize = 16 * 1024;

pub struct HttpProxy {
    pub state: Arc<CoreState>,
    pub ns: NetworkSecret,
    pub id_pub: [u8; 32],
    pub self_id: String,
    /// Some((user, pass)) = 启用 Basic 代理认证
    pub auth: Option<(String, String)>,
}

impl HttpProxy {
    pub async fn handle(&self, mut c: TcpStream) -> Result<()> {
        c.set_nodelay(true).ok();
        let head = match read_head(&mut c).await? {
            Some(h) => h,
            None => return Ok(()), // 客户端直接断开
        };
        let text = String::from_utf8_lossy(&head).to_string();
        let mut lines = text.split("\r\n");
        let req_line = lines.next().unwrap_or_default();
        let (method, target, version) = parse_request_line(req_line)
            .context("请求行格式错误")?;

        // ---- 代理认证 ----
        if let Some((user, pass)) = &self.auth {
            let got = lines
                .clone()
                .find_map(|l| header_value(l, "proxy-authorization"));
            let ok = got
                .and_then(|v| {
                    v.strip_prefix("Basic ")
                        .or_else(|| v.strip_prefix("basic "))
                        .map(|b| b.trim().to_string())
                })
                .and_then(|b| b64_decode(&b))
                .map(|raw| String::from_utf8_lossy(&raw).to_string())
                .map(|cred| cred == format!("{user}:{pass}"))
                .unwrap_or(false);
            if !ok {
                c.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"yingzi\"\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .ok();
                bail!("http proxy: 认证失败");
            }
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            self.handle_connect(c, &target).await
        } else {
            self.handle_plain(c, &method, &target, &version, &lines).await
        }
    }

    /// CONNECT host:port → 200 + 裸隧道
    async fn handle_connect(&self, mut c: TcpStream, authority: &str) -> Result<()> {
        let (host, port) = parse_authority(authority, 443)
            .with_context(|| format!("CONNECT 目标无法解析: {authority}"))?;
        let addr = to_addr(&host, port);

        let up = match self.open(&addr).await {
            Ok(u) => u,
            Err(e) => {
                reply(&mut c, 502, "Bad Gateway").await;
                return Err(e);
            }
        };
        if c.write_all(
            b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: yingzi\r\n\r\n",
        )
        .await
        .is_err()
        {
            return Ok(());
        }
        match up {
            Upstream::Direct(mut o) => {
                let _ = tokio::io::copy_bidirectional(&mut c, &mut o).await;
                Ok(())
            }
            Upstream::Tunnel { t, sid, rx } => tunnel::pump_stream(c, sid, rx, t).await,
        }
    }

    /// 绝对 URI 形式 → 重写为 origin-form 后转发（一次性连接）
    async fn handle_plain(
        &self,
        mut c: TcpStream,
        method: &str,
        target: &str,
        version: &str,
        header_lines: &std::str::Split<'_, &str>,
    ) -> Result<()> {
        let Some((host, port, path)) = parse_absolute_uri(target) else {
            reply(&mut c, 400, "Bad Request").await;
            bail!("只支持绝对 URI 形式的明文 HTTP: {target}");
        };
        let addr = to_addr(&host, port);

        // 重写请求头：request-line → origin-form；丢掉代理专用头，强制 close
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(format!("{method} {path} {version}\r\n").as_bytes());
        for l in header_lines.clone() {
            if l.is_empty() {
                continue;
            }
            let name = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
            match name.as_str() {
                "proxy-authorization" | "proxy-connection" | "connection" | "keep-alive" => {}
                _ => {
                    out.extend_from_slice(l.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
        // 没有 Host 头就用目标主机补一个（HTTP/1.1 必需）
        if !header_lines
            .clone()
            .any(|l| l.to_ascii_lowercase().starts_with("host:"))
        {
            let hp = if port == 80 {
                host.clone()
            } else {
                format!("{host}:{port}")
            };
            out.extend_from_slice(format!("Host: {hp}\r\n").as_bytes());
        }
        out.extend_from_slice(b"Connection: close\r\n\r\n");

        let up = match self.open(&addr).await {
            Ok(u) => u,
            Err(e) => {
                reply(&mut c, 502, "Bad Gateway").await;
                return Err(e);
            }
        };
        match up {
            Upstream::Direct(mut o) => {
                if o.write_all(&out).await.is_err() {
                    return Ok(());
                }
                let _ = tokio::io::copy_bidirectional(&mut c, &mut o).await;
                Ok(())
            }
            Upstream::Tunnel { t, sid, rx } => {
                // 先把重写后的请求头推进隧道，再走通用泵
                if t.write_frame(&Frame::Data {
                    stream_id: sid,
                    payload: out,
                })
                .await
                .is_err()
                {
                    return Ok(());
                }
                tunnel::pump_stream(c, sid, rx, t).await
            }
        }
    }

    async fn open(&self, addr: &Addr) -> Result<Upstream> {
        // 分流规则与 SOCKS5 一致：先查路由表，未命中走默认出口
        let key = {
            let routes = self.state.routes.read().await;
            match yz_core::policy::match_route(&routes, addr) {
                Some(e) => e.to_string(),
                None => self.state.default_exit.read().await.clone(),
            }
        };
        open_upstream(
            &self.state,
            &self.ns,
            &self.id_pub,
            &self.self_id,
            &key,
            addr,
        )
        .await
    }
}

/// 目标主机统一走 `Addr::Domain`：交给出口侧解析，
/// 顺带继承 fake-IP / 防污染的好处；是 IP 就直接用 IP。
fn to_addr(host: &str, port: u16) -> Addr {
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(v4) => Addr::V4(v4.octets(), port),
        Err(_) => match host.parse::<std::net::Ipv6Addr>() {
            Ok(v6) => Addr::V6(v6.octets(), port),
            Err(_) => Addr::Domain(host.to_string(), port),
        },
    }
}

async fn reply(c: &mut TcpStream, code: u16, reason: &str) {
    let body = format!("{code} {reason}");
    let msg = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(msg.as_bytes()).await.ok();
}

/// 读到 `\r\n\r\n`（含）；返回包含头部的完整字节
async fn read_head(c: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = c.read(&mut chunk).await?;
        if n == 0 {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(Some(buf));
        }
        if buf.len() > MAX_HEAD {
            bail!("请求头超过 {MAX_HEAD} 字节");
        }
    }
}

fn parse_request_line(line: &str) -> Option<(String, String, String)> {
    let mut it = line.split_whitespace();
    let m = it.next()?;
    let t = it.next()?;
    let v = it.next().unwrap_or("HTTP/1.1");
    if !v.starts_with("HTTP/") {
        return None;
    }
    Some((m.to_string(), t.to_string(), v.to_string()))
}

fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (k, v) = line.split_once(':')?;
    if k.trim().eq_ignore_ascii_case(name) {
        Some(v.trim())
    } else {
        None
    }
}

/// `host:port` / `[::1]:port` / `host`（默认端口）
fn parse_authority(s: &str, default_port: u16) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return Some((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        // 只有一段冒号且右侧是数字才当成端口（避免误解 IPv6）
        Some((h, p)) if !h.contains(':') && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            Some((h.to_string(), p.parse().ok()?))
        }
        _ => Some((s.to_string(), default_port)),
    }
}

/// `http://host[:port]/path?q` → (host, port, /path?q)
fn parse_absolute_uri(uri: &str) -> Option<(String, u16, String)> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // authority 里可能带 userinfo（极少见），丢掉
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);
    let (host, port) = parse_authority(authority, 80)?;
    Some((host, port, path.to_string()))
}

/// 极简 base64 解码（只给 Proxy-Authorization 用，容忍无填充）
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = val(c)?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// 供 main.rs 装配（PeerCtx 里的字段保持不变，仅是编译期检查引用完整）
#[allow(dead_code)]
fn _assert_ctx(_c: &PeerCtx) {}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_parse() {
        assert_eq!(parse_authority("example.com:8080", 443), Some(("example.com".into(), 8080)));
        assert_eq!(parse_authority("example.com", 443), Some(("example.com".into(), 443)));
        assert_eq!(parse_authority("[::1]:8443", 443), Some(("::1".into(), 8443)));
        assert_eq!(parse_authority("[::1]", 443), Some(("::1".into(), 443)));
    }

    #[test]
    fn absolute_uri_parse() {
        assert_eq!(
            parse_absolute_uri("http://example.com/a/b?c=1"),
            Some(("example.com".into(), 80, "/a/b?c=1".into()))
        );
        assert_eq!(
            parse_absolute_uri("http://example.com:8080"),
            Some(("example.com".into(), 8080, "/".into()))
        );
        assert_eq!(parse_absolute_uri("https://example.com/"), None);
        assert_eq!(parse_absolute_uri("/only-path"), None);
    }

    #[test]
    fn request_line_parse() {
        assert_eq!(
            parse_request_line("GET http://a.com/ HTTP/1.1"),
            Some(("GET".into(), "http://a.com/".into(), "HTTP/1.1".into()))
        );
        assert_eq!(parse_request_line("CONNECT a.com:443 HTTP/1.1").map(|r| r.0), Some("CONNECT".into()));
        assert_eq!(parse_request_line("garbage"), None);
    }

    #[test]
    fn base64_decode_works() {
        assert_eq!(b64_decode("dXNlcjpwYXNz"), Some(b"user:pass".to_vec()));
        assert_eq!(b64_decode("dXNlcjpwYXNz"), Some(b"user:pass".to_vec()));
        assert_eq!(b64_decode("YQ=="), Some(b"a".to_vec()));
    }
}