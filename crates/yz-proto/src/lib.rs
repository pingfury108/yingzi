//! YZP 帧编解码（plan.md §3.4）。
//! 一个加密包承载一个帧: type(1) | fields...
//! 纯编解码, 无 IO 无依赖。

use std::fmt;

/// 单帧明文上限（加密后 +16B tag）
pub const MAX_FRAME_LEN: usize = 18 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    V4([u8; 4], u16),
    V6([u8; 16], u16),
    Domain(String, u16),
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::V4(ip, p) => write!(f, "{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], p),
            Addr::V6(ip, p) => {
                let segs: Vec<u16> = ip
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                write!(
                    f,
                    "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
                    segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7], p
                )
            }
            Addr::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

impl Addr {
    /// "host:port" → Addr; host 为 IP 字面量时转 V4/V6, 否则 Domain
    pub fn parse(s: &str) -> Result<Addr, String> {
        let (host, port_s) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("addr must be host:port: {s}"))?;
        let port: u16 = port_s.parse().map_err(|_| format!("bad port: {s}"))?;
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(match ip {
                std::net::IpAddr::V4(v4) => Addr::V4(v4.octets(), port),
                std::net::IpAddr::V6(v6) => Addr::V6(v6.octets(), port),
            });
        }
        if host.is_empty() || host.len() > 255 {
            return Err(format!("bad host: {s}"));
        }
        Ok(Addr::Domain(host.to_string(), port))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// 开流并指定目标地址
    Syn { stream_id: u32, addr: Addr },
    SynAck { stream_id: u32, ok: bool },
    Data { stream_id: u32, payload: Vec<u8> },
    /// 半关闭
    Fin { stream_id: u32 },
    Rst { stream_id: u32 },
    WindowUpdate { stream_id: u32, delta: u32 },
    /// stream 0 控制消息（plan.md §3.5）
    Control { payload: Vec<u8> },
    Ping { ts: u64 },
    Pong { ts: u64 },
}

const T_SYN: u8 = 0x01;
const T_SYN_ACK: u8 = 0x02;
const T_DATA: u8 = 0x03;
const T_FIN: u8 = 0x04;
const T_RST: u8 = 0x05;
const T_WIN: u8 = 0x06;
const T_CTRL: u8 = 0x10;
const T_PING: u8 = 0x11;
const T_PONG: u8 = 0x12;

impl Frame {
    /// 流帧返回 stream_id; Control/Ping/Pong 返回 0
    pub fn stream_id(&self) -> u32 {
        match self {
            Frame::Syn { stream_id, .. }
            | Frame::SynAck { stream_id, .. }
            | Frame::Data { stream_id, .. }
            | Frame::Fin { stream_id }
            | Frame::Rst { stream_id }
            | Frame::WindowUpdate { stream_id, .. } => *stream_id,
            Frame::Control { .. } | Frame::Ping { .. } | Frame::Pong { .. } => 0,
        }
    }
}

#[derive(Debug)]
pub enum DecodeError {
    Truncated,
    UnknownType(u8),
    BadAddrType(u8),
    BadUtf8,
    Trailing,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "truncated frame"),
            DecodeError::UnknownType(t) => write!(f, "unknown frame type {t:#04x}"),
            DecodeError::BadAddrType(t) => write!(f, "unknown addr type {t:#04x}"),
            DecodeError::BadUtf8 => write!(f, "invalid utf8 in domain"),
            DecodeError::Trailing => write!(f, "trailing bytes after frame"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub fn encode(f: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    match f {
        Frame::Syn { stream_id, addr } => {
            out.push(T_SYN);
            out.extend_from_slice(&stream_id.to_be_bytes());
            encode_addr(addr, &mut out);
        }
        Frame::SynAck { stream_id, ok } => {
            out.push(T_SYN_ACK);
            out.extend_from_slice(&stream_id.to_be_bytes());
            out.push(*ok as u8);
        }
        Frame::Data { stream_id, payload } => {
            out.push(T_DATA);
            out.extend_from_slice(&stream_id.to_be_bytes());
            out.extend_from_slice(payload);
        }
        Frame::Fin { stream_id } => {
            out.push(T_FIN);
            out.extend_from_slice(&stream_id.to_be_bytes());
        }
        Frame::Rst { stream_id } => {
            out.push(T_RST);
            out.extend_from_slice(&stream_id.to_be_bytes());
        }
        Frame::WindowUpdate { stream_id, delta } => {
            out.push(T_WIN);
            out.extend_from_slice(&stream_id.to_be_bytes());
            out.extend_from_slice(&delta.to_be_bytes());
        }
        Frame::Control { payload } => {
            out.push(T_CTRL);
            out.extend_from_slice(payload);
        }
        Frame::Ping { ts } => {
            out.push(T_PING);
            out.extend_from_slice(&ts.to_be_bytes());
        }
        Frame::Pong { ts } => {
            out.push(T_PONG);
            out.extend_from_slice(&ts.to_be_bytes());
        }
    }
    out
}

/// 解码, 要求整个 buf 恰好是一个帧
pub fn decode(buf: &[u8]) -> Result<Frame, DecodeError> {
    let t = *buf.first().ok_or(DecodeError::Truncated)?;
    let b = &buf[1..];
    let frame = match t {
        T_SYN => {
            let (stream_id, rest) = take_u32(b)?;
            let (addr, n) = decode_addr(rest)?;
            if n != rest.len() {
                return Err(DecodeError::Trailing);
            }
            Frame::Syn { stream_id, addr }
        }
        T_SYN_ACK => {
            let (stream_id, rest) = take_u32(b)?;
            let ok = match rest.first() {
                Some(0) => false,
                Some(_) => true,
                None => return Err(DecodeError::Truncated),
            };
            if rest.len() != 1 {
                return Err(DecodeError::Trailing);
            }
            Frame::SynAck { stream_id, ok }
        }
        T_DATA => {
            let (stream_id, rest) = take_u32(b)?;
            Frame::Data {
                stream_id,
                payload: rest.to_vec(),
            }
        }
        T_FIN => {
            let (stream_id, rest) = take_u32(b)?;
            if !rest.is_empty() {
                return Err(DecodeError::Trailing);
            }
            Frame::Fin { stream_id }
        }
        T_RST => {
            let (stream_id, rest) = take_u32(b)?;
            if !rest.is_empty() {
                return Err(DecodeError::Trailing);
            }
            Frame::Rst { stream_id }
        }
        T_WIN => {
            let (stream_id, rest) = take_u32(b)?;
            if rest.len() != 4 {
                return Err(DecodeError::Truncated);
            }
            Frame::WindowUpdate {
                stream_id,
                delta: u32::from_be_bytes(rest[..4].try_into().unwrap()),
            }
        }
        T_CTRL => Frame::Control {
            payload: b.to_vec(),
        },
        T_PING => {
            if b.len() != 8 {
                return Err(DecodeError::Truncated);
            }
            Frame::Ping {
                ts: u64::from_be_bytes(b[..8].try_into().unwrap()),
            }
        }
        T_PONG => {
            if b.len() != 8 {
                return Err(DecodeError::Truncated);
            }
            Frame::Pong {
                ts: u64::from_be_bytes(b[..8].try_into().unwrap()),
            }
        }
        other => return Err(DecodeError::UnknownType(other)),
    };
    Ok(frame)
}

fn take_u32(b: &[u8]) -> Result<(u32, &[u8]), DecodeError> {
    if b.len() < 4 {
        return Err(DecodeError::Truncated);
    }
    Ok((u32::from_be_bytes(b[..4].try_into().unwrap()), &b[4..]))
}

fn encode_addr(a: &Addr, out: &mut Vec<u8>) {
    match a {
        Addr::V4(ip, port) => {
            out.push(0x01);
            out.extend_from_slice(ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Addr::Domain(d, port) => {
            out.push(0x02);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Addr::V6(ip, port) => {
            out.push(0x03);
            out.extend_from_slice(ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

fn decode_addr(b: &[u8]) -> Result<(Addr, usize), DecodeError> {
    let t = *b.first().ok_or(DecodeError::Truncated)?;
    match t {
        0x01 => {
            if b.len() < 1 + 4 + 2 {
                return Err(DecodeError::Truncated);
            }
            let ip: [u8; 4] = b[1..5].try_into().unwrap();
            let port = u16::from_be_bytes(b[5..7].try_into().unwrap());
            Ok((Addr::V4(ip, port), 7))
        }
        0x02 => {
            let dlen = *b.get(1).ok_or(DecodeError::Truncated)? as usize;
            if b.len() < 2 + dlen + 2 {
                return Err(DecodeError::Truncated);
            }
            let d = std::str::from_utf8(&b[2..2 + dlen])
                .map_err(|_| DecodeError::BadUtf8)?
                .to_string();
            let port = u16::from_be_bytes(b[2 + dlen..2 + dlen + 2].try_into().unwrap());
            Ok((Addr::Domain(d, port), 2 + dlen + 2))
        }
        0x03 => {
            if b.len() < 1 + 16 + 2 {
                return Err(DecodeError::Truncated);
            }
            let ip: [u8; 16] = b[1..17].try_into().unwrap();
            let port = u16::from_be_bytes(b[17..19].try_into().unwrap());
            Ok((Addr::V6(ip, port), 19))
        }
        other => Err(DecodeError::BadAddrType(other)),
    }
}

// ---------- 控制消息 (plan.md §3.5) ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry {
    pub node_id: String,
    pub name: String,
    /// 隧道监听地址 host:port (供其他节点直连)
    pub addr: String,
    /// 能力位: caps::EXIT 等
    pub caps: u8,
}

pub mod caps {
    /// 允许被用作出口
    pub const EXIT: u8 = 0x01;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMsg {
    /// 节点上线注册, addr 为隧道监听地址
    Hello {
        version: u16,
        name: String,
        addr: String,
        caps: u8,
    },
    /// 节点目录全量同步 (coordinator → node)
    DirSync { nodes: Vec<NodeEntry> },
    /// 动态入口发布请求 (node → 公网入口节点)
    IngressPub { port: u16, addr: String },
    /// 动态入口发布应答
    IngressPubAck { port: u16, ok: bool, msg: String },
}

const C_HELLO: u8 = 0x01;
const C_DIR_SYNC: u8 = 0x02;
const C_INGRESS_PUB: u8 = 0x09;
const C_INGRESS_PUB_ACK: u8 = 0x0a;

pub fn encode_control(m: &ControlMsg) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    match m {
        ControlMsg::Hello {
            version,
            name,
            addr,
            caps,
        } => {
            out.push(C_HELLO);
            out.extend_from_slice(&version.to_be_bytes());
            push_str(&mut out, name);
            push_str(&mut out, addr);
            out.push(*caps);
        }
        ControlMsg::DirSync { nodes } => {
            out.push(C_DIR_SYNC);
            out.extend_from_slice(&(nodes.len() as u16).to_be_bytes());
            for n in nodes {
                push_str(&mut out, &n.node_id);
                push_str(&mut out, &n.name);
                push_str(&mut out, &n.addr);
                out.push(n.caps);
            }
        }
        ControlMsg::IngressPub { port, addr } => {
            out.push(C_INGRESS_PUB);
            out.extend_from_slice(&port.to_be_bytes());
            push_str(&mut out, addr);
        }
        ControlMsg::IngressPubAck { port, ok, msg } => {
            out.push(C_INGRESS_PUB_ACK);
            out.extend_from_slice(&port.to_be_bytes());
            out.push(*ok as u8);
            push_str(&mut out, msg);
        }
    }
    out
}

pub fn decode_control(b: &[u8]) -> Result<ControlMsg, DecodeError> {
    let t = *b.first().ok_or(DecodeError::Truncated)?;
    let mut cur = &b[1..];
    match t {
        C_HELLO => {
            let version = take_u16(&mut cur)?;
            let name = take_str(&mut cur)?;
            let addr = take_str(&mut cur)?;
            let caps = *cur.first().ok_or(DecodeError::Truncated)?;
            if cur.len() != 1 {
                return Err(DecodeError::Trailing);
            }
            Ok(ControlMsg::Hello {
                version,
                name,
                addr,
                caps,
            })
        }
        C_DIR_SYNC => {
            let count = take_u16(&mut cur)? as usize;
            let mut nodes = Vec::with_capacity(count);
            for _ in 0..count {
                let node_id = take_str(&mut cur)?;
                let name = take_str(&mut cur)?;
                let addr = take_str(&mut cur)?;
                let caps = *cur.first().ok_or(DecodeError::Truncated)?;
                cur = &cur[1..];
                nodes.push(NodeEntry {
                    node_id,
                    name,
                    addr,
                    caps,
                });
            }
            if !cur.is_empty() {
                return Err(DecodeError::Trailing);
            }
            Ok(ControlMsg::DirSync { nodes })
        }
        C_INGRESS_PUB => {
            let port = take_u16(&mut cur)?;
            let addr = take_str(&mut cur)?;
            if !cur.is_empty() {
                return Err(DecodeError::Trailing);
            }
            Ok(ControlMsg::IngressPub { port, addr })
        }
        C_INGRESS_PUB_ACK => {
            let port = take_u16(&mut cur)?;
            let ok = match cur.first() {
                Some(0) => false,
                Some(_) => true,
                None => return Err(DecodeError::Truncated),
            };
            cur = &cur[1..];
            let msg = take_str(&mut cur)?;
            if !cur.is_empty() {
                return Err(DecodeError::Trailing);
            }
            Ok(ControlMsg::IngressPubAck { port, ok, msg })
        }
        other => Err(DecodeError::UnknownType(other)),
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

fn take_u16(cur: &mut &[u8]) -> Result<u16, DecodeError> {
    if cur.len() < 2 {
        return Err(DecodeError::Truncated);
    }
    let v = u16::from_be_bytes(cur[..2].try_into().unwrap());
    *cur = &cur[2..];
    Ok(v)
}

fn take_str(cur: &mut &[u8]) -> Result<String, DecodeError> {
    let len = *cur.first().ok_or(DecodeError::Truncated)? as usize;
    if cur.len() < 1 + len {
        return Err(DecodeError::Truncated);
    }
    let s = std::str::from_utf8(&cur[1..1 + len])
        .map_err(|_| DecodeError::BadUtf8)?
        .to_string();
    *cur = &cur[1 + len..];
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(f: Frame) {
        let enc = encode(&f);
        assert_eq!(decode(&enc).unwrap(), f);
    }

    #[test]
    fn frame_roundtrip() {
        roundtrip(Frame::Syn {
            stream_id: 1,
            addr: Addr::V4([127, 0, 0, 1], 8080),
        });
        roundtrip(Frame::Syn {
            stream_id: 7,
            addr: Addr::Domain("example.com".into(), 443),
        });
        roundtrip(Frame::Syn {
            stream_id: 9,
            addr: Addr::V6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 22),
        });
        roundtrip(Frame::SynAck {
            stream_id: 1,
            ok: true,
        });
        roundtrip(Frame::Data {
            stream_id: 3,
            payload: b"hello yz".to_vec(),
        });
        roundtrip(Frame::Data {
            stream_id: 3,
            payload: vec![],
        });
        roundtrip(Frame::Fin { stream_id: 3 });
        roundtrip(Frame::Rst { stream_id: 3 });
        roundtrip(Frame::WindowUpdate {
            stream_id: 3,
            delta: 65535,
        });
        roundtrip(Frame::Control {
            payload: vec![0x02, 1, 2, 3],
        });
        roundtrip(Frame::Ping { ts: 1_700_000_000 });
        roundtrip(Frame::Pong { ts: 1_700_000_001 });
    }

    #[test]
    fn control_roundtrip() {
        let msgs = [
            ControlMsg::Hello {
                version: 1,
                name: "nas-home".into(),
                addr: "1.2.3.4:9100".into(),
                caps: caps::EXIT,
            },
            ControlMsg::DirSync { nodes: vec![] },
            ControlMsg::DirSync {
                nodes: vec![
                    NodeEntry {
                        node_id: "0123456789abcdef".into(),
                        name: "vps-tokyo".into(),
                        addr: "1.2.3.4:9000".into(),
                        caps: caps::EXIT,
                    },
                    NodeEntry {
                        node_id: "fedcba9876543210".into(),
                        name: "nas-home".into(),
                        addr: "5.6.7.8:9000".into(),
                        caps: 0,
                    },
                ],
            },
            ControlMsg::IngressPub {
                port: 8080,
                addr: "127.0.0.1:80".into(),
            },
            ControlMsg::IngressPubAck {
                port: 8080,
                ok: false,
                msg: "port out of range".into(),
            },
        ];
        for m in msgs {
            assert_eq!(decode_control(&encode_control(&m)).unwrap(), m);
        }
    }

    #[test]
    fn decode_errors() {
        assert!(matches!(decode(&[]), Err(DecodeError::Truncated)));
        assert!(matches!(decode(&[0xff]), Err(DecodeError::UnknownType(0xff))));
        assert!(matches!(decode(&[T_FIN, 0, 0]), Err(DecodeError::Truncated)));
        // trailing
        assert!(matches!(
            decode(&[T_FIN, 0, 0, 0, 1, 9]),
            Err(DecodeError::Trailing)
        ));
    }
}
