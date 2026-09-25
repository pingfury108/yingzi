//! 极简 SOCKS5 服务端: 仅 CONNECT, 无认证 (RFC 1928 子集)。

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use yz_proto::Addr;

/// 完成 SOCKS5 协商, 返回目标地址。就绪前不发 reply。
pub async fn handshake(s: &mut TcpStream) -> Result<Addr> {
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
    if req[0] != 0x05 || req[1] != 0x01 {
        bail!("only CONNECT supported");
    }
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
    Ok(addr)
}

pub async fn reply_ok(s: &mut TcpStream) -> Result<()> {
    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

pub async fn reply_fail(s: &mut TcpStream) {
    let _ = s
        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;
}
