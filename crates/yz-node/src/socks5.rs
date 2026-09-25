//! 极简 SOCKS5 服务端: 仅 CONNECT, 无认证 (RFC 1928 子集)。

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use yz_proto::Addr;

/// SOCKS5 请求
#[derive(Debug)]
pub enum Request {
    Connect(Addr),
    UdpAssociate,
}

/// 完成 SOCKS5 协商, 返回请求。就绪前不发 reply。
pub async fn handshake(s: &mut TcpStream) -> Result<Request> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("not socks5");
    }
    let n = head[1] as usize;
    if n == 0 || n > 16 {
        bail!("bad methods len");
    }
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        s.write_all(&[0x05, 0xff]).await.ok();
        bail!("client requires auth");
    }
    s.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("bad socks version");
    }
    let cmd = req[1];
    let addr = match req[3] {
        0x01 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
            Addr::V4(b[..4].try_into().unwrap(), u16::from_be_bytes([b[4], b[5]]))
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut d).await?;
            let port = u16::from_be_bytes([d[d.len() - 2], d[d.len() - 1]]);
            let dom = String::from_utf8(d[..d.len() - 2].to_vec()).context("bad domain")?;
            Addr::Domain(dom, port)
        }
        0x04 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
            Addr::V6(b[..16].try_into().unwrap(), u16::from_be_bytes([b[16], b[17]]))
        }
        t => bail!("bad atype {t}"),
    };
    match cmd {
        0x01 => Ok(Request::Connect(addr)),
        0x03 => Ok(Request::UdpAssociate),
        c => bail!("unsupported command {c:#04x} (仅支持 CONNECT/UDP ASSOCIATE)"),
    }
}

pub async fn reply_ok(s: &mut TcpStream) -> Result<()> {
    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

/// UDP ASSOCIATE 应答: 告诉客户端把 UDP 数据报发到哪个中继地址
pub async fn reply_udp(s: &mut TcpStream, relay: std::net::SocketAddr) -> Result<()> {
    let mut out = vec![0x05, 0x00, 0x00];
    match relay {
        std::net::SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    s.write_all(&out).await?;
    Ok(())
}

/// 解析 SOCKS5 UDP 请求头 (RSV2 FRAG1 ATYP ADDR PORT DATA), 返回 (目标, DATA 起始偏移)
pub fn parse_udp_header(buf: &[u8]) -> Option<(Addr, usize)> {
    if buf.len() < 4 || buf[2] != 0 {
        return None; // FRAG != 0 且不支持分片
    }
    match buf[3] {
        0x01 => {
            if buf.len() < 10 {
                return None;
            }
            let ip: [u8; 4] = buf[4..8].try_into().ok()?;
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Some((Addr::V4(ip, port), 10))
        }
        0x04 => {
            if buf.len() < 22 {
                return None;
            }
            let ip: [u8; 16] = buf[4..20].try_into().ok()?;
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Some((Addr::V6(ip, port), 22))
        }
        0x03 => {
            let len = *buf.get(4)? as usize;
            if buf.len() < 5 + len + 2 {
                return None;
            }
            let dom = std::str::from_utf8(&buf[5..5 + len]).ok()?.to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            Some((Addr::Domain(dom, port), 7 + len))
        }
        _ => None,
    }
}

/// 构造 SOCKS5 UDP 应答头 (回给客户端时带上真实来源地址)
pub fn build_udp_header(addr: &Addr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00];
    match addr {
        Addr::V4(ip, port) => {
            out.push(0x01);
            out.extend_from_slice(ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Addr::V6(ip, port) => {
            out.push(0x04);
            out.extend_from_slice(ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Addr::Domain(d, port) => {
            out.push(0x03);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

pub async fn reply_fail(s: &mut TcpStream) {
    let _ = s
        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_header_v4_roundtrip() {
        let pkt = vec![0, 0, 0, 1, 223, 5, 5, 5, 0, 53, 0xAA, 0xBB];
        let (a, off) = parse_udp_header(&pkt).unwrap();
        assert_eq!(a.to_string(), "223.5.5.5:53");
        assert_eq!(off, 10);
        assert_eq!(&pkt[off..], &[0xAA, 0xBB]);
        assert_eq!(
            build_udp_header(&a, &[1, 2, 3]),
            vec![0, 0, 0, 1, 223, 5, 5, 5, 0, 53, 1, 2, 3]
        );
    }

    #[test]
    fn udp_header_domain_roundtrip() {
        let mut pkt = vec![0, 0, 0, 3, 11];
        pkt.extend_from_slice(b"example.com");
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.push(9);
        let (a, off) = parse_udp_header(&pkt).unwrap();
        assert_eq!(a.to_string(), "example.com:443");
        assert_eq!(off, 7 + 11);
        assert_eq!(pkt[off], 9);
    }

    #[test]
    fn udp_header_rejects_frag() {
        let pkt = vec![0, 0, 1, 1, 1, 1, 1, 1, 0, 53];
        assert!(parse_udp_header(&pkt).is_none());
    }
}
