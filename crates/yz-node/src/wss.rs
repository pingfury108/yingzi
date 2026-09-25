//! WSS 模仿模式 (P5b): 真实 TLS + 标准 WebSocket 承载 YZP 字节流。
//! 观察者看到合法 HTTPS 与 RFC6455 升级; 内容全在加密帧内, 可挂 CDN。
//! WS 帧层为手写最小实现: 二进制帧、客户端掩码、不分片。

use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SignatureScheme};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskCtx, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTls;
use tokio_rustls::server::TlsStream as ServerTls;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ---------- TLS ----------

pub fn server_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?))
            .collect::<std::io::Result<_>>()?;
    let mut key_file = BufReader::new(File::open(key)?);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_file)?
        .context("no private key in pem")?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

pub fn client_connector(insecure: bool) -> Result<TlsConnector> {
    let cfg = if insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Ok(TlsConnector::from(Arc::new(cfg)))
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

// ---------- WebSocket 握手 ----------

/// 服务端: TLS 终止 + WS 升级; 非 WS 请求直接断开 (对外就是个不爱说话的 HTTPS 站)
pub async fn accept(
    stream: TcpStream,
    acceptor: &TlsAcceptor,
) -> Result<WsStream<ServerTls<TcpStream>>> {
    let mut tls = acceptor.accept(stream).await?;
    let key = read_http_key(&mut tls).await?;
    let accept_key = b64encode(yz_crypto::sha1(format!("{key}{WS_GUID}").as_bytes()).as_slice());
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_key}\r\n\r\n"
    );
    tls.write_all(resp.as_bytes()).await?;
    Ok(WsStream::new(tls, false)) // 服务端发送不掩码
}

/// 客户端: TLS(SNI=真实域名) + WS 升级
pub async fn connect(
    stream: TcpStream,
    connector: &TlsConnector,
    sni: &str,
) -> Result<WsStream<ClientTls<TcpStream>>> {
    let name = ServerName::try_from(sni.to_string())?;
    let mut tls = connector.connect(name, stream).await?;
    let key = b64encode(&yz_crypto::random_bytes(16));
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {sni}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await?;
    // 读 101 响应头
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = tls.read(&mut tmp).await?;
        if n == 0 {
            bail!("eof in ws handshake");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf);
            if !head.contains(" 101") {
                bail!("ws upgrade refused: {}", head.lines().next().unwrap_or(""));
            }
            break;
        }
        if buf.len() > 16384 {
            bail!("http head too large");
        }
    }
    Ok(WsStream::new(tls, true)) // 客户端发送必须掩码
}

async fn read_http_key<S: AsyncRead + Unpin>(io: &mut S) -> Result<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = io.read(&mut tmp).await?;
        if n == 0 {
            bail!("eof in ws handshake");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf);
            return head
                .lines()
                .find_map(|l| {
                    l.split_once(':').and_then(|(k, v)| {
                        k.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| v.trim().to_string())
                    })
                })
                .context("no sec-websocket-key");
        }
        if buf.len() > 16384 {
            bail!("http head too large");
        }
    }
}

fn b64encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

// ---------- WS 帧层: 伪装成 AsyncRead/AsyncWrite 字节流 ----------

pub struct WsStream<S> {
    inner: S,
    masked: bool,
    raw: Vec<u8>,
    payload: Vec<u8>,
    payload_pos: usize,
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> WsStream<S> {
    fn new(inner: S, masked: bool) -> Self {
        Self {
            inner,
            masked,
            raw: Vec::new(),
            payload: Vec::new(),
            payload_pos: 0,
            out: Vec::new(),
            out_pos: 0,
        }
    }
}

/// 解析一帧: 返回 (消耗长度, payload, opcode)
fn parse_frame(raw: &[u8]) -> Option<(usize, Vec<u8>, u8)> {
    if raw.len() < 2 {
        return None;
    }
    let op = raw[0] & 0x0f;
    let masked = raw[1] & 0x80 != 0;
    let mut len = (raw[1] & 0x7f) as usize;
    let mut pos = 2;
    if len == 126 {
        if raw.len() < 4 {
            return None;
        }
        len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        pos = 4;
    } else if len == 127 {
        if raw.len() < 10 {
            return None;
        }
        len = u64::from_be_bytes(raw[2..10].try_into().unwrap()) as usize;
        pos = 10;
    }
    let mask_key = if masked {
        if raw.len() < pos + 4 {
            return None;
        }
        let k: [u8; 4] = raw[pos..pos + 4].try_into().unwrap();
        pos += 4;
        Some(k)
    } else {
        None
    };
    if raw.len() < pos + len {
        return None;
    }
    let mut payload = raw[pos..pos + len].to_vec();
    if let Some(k) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= k[i % 4];
        }
    }
    Some((pos + len, payload, op))
}

fn build_frame(payload: &[u8], op: u8, masked: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | op); // FIN | opcode
    let mbit = if masked { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(mbit | payload.len() as u8);
    } else if payload.len() <= 0xffff {
        out.push(mbit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(mbit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    if masked {
        let k = yz_crypto::random_bytes(4);
        out.extend_from_slice(&k);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ k[i % 4]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    out
}

impl<S: AsyncRead + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.payload_pos < self.payload.len() {
                let n = (self.payload.len() - self.payload_pos).min(buf.remaining());
                buf.put_slice(&self.payload[self.payload_pos..self.payload_pos + n]);
                self.payload_pos += n;
                if self.payload_pos == self.payload.len() {
                    self.payload.clear();
                    self.payload_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if let Some((consumed, payload, op)) = parse_frame(&self.raw) {
                self.raw.drain(..consumed);
                match op {
                    0x0 | 0x2 => {
                        self.payload = payload;
                        self.payload_pos = 0;
                        continue;
                    }
                    0x8 => return Poll::Ready(Ok(())), // close → EOF
                    _ => continue,                    // ping/pong 忽略
                }
            }
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    self.raw.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.out_pos == this.out.len() {
            this.out = build_frame(buf, 0x2, this.masked);
            this.out_pos = 0;
        }
        while this.out_pos < this.out.len() {
            let chunk = &this.out[this.out_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => this.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64() {
        assert_eq!(b64encode(b""), "");
        assert_eq!(b64encode(b"f"), "Zg==");
        assert_eq!(b64encode(b"fo"), "Zm8=");
        assert_eq!(b64encode(b"foo"), "Zm9v");
        assert_eq!(b64encode(b"hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn frame_roundtrip() {
        let payload = vec![7u8; 70000]; // 触发 127 扩展长度
        let f = build_frame(&payload, 0x2, true);
        let (consumed, got, op) = parse_frame(&f).unwrap();
        assert_eq!(consumed, f.len());
        assert_eq!(got, payload);
        assert_eq!(op, 2);

        let f2 = build_frame(b"hi", 0x2, false);
        assert_eq!(parse_frame(&f2).unwrap().1, b"hi");
        // 不完整帧
        assert!(parse_frame(&f2[..3]).is_none());
    }
}
