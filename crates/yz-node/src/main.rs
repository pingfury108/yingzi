//! yz-node: YZP 节点二进制 (P0)
//! - keygen  生成网络密钥与节点身份
//! - serve   隧道出口: 接受加密隧道, 按 SYN 访问目标
//! - dial    隧道入口: 本地监听, 经加密隧道转发到 serve 端
//!
//! P0 范围: TCP 承载, 一条隧道一条流。多流复用/打洞/Web UI 见 docs/plan.md。

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;
use yz_crypto::{
    handshake_accept, handshake_finish, handshake_init, NetworkSecret, Session, MSG1_LEN,
    MSG2_LEN,
};
use yz_proto::{Addr, Frame, MAX_FRAME_LEN};

const HS_TIMEOUT: Duration = Duration::from_secs(10);
const IO_BUF: usize = 16 * 1024;

#[derive(Parser)]
#[command(name = "yz", version, about = "yingzi mesh node")]
struct Cli {
    /// 网络密钥(64位hex), 也可用环境变量 YZ_NETWORK_SECRET
    #[arg(long, env = "YZ_NETWORK_SECRET", global = true)]
    network_secret: Option<String>,

    /// 节点身份密钥文件
    #[arg(long, default_value = "node.key", global = true)]
    id_file: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 生成网络密钥与节点身份
    Keygen,
    /// 隧道出口: 接受隧道连接并访问目标
    Serve {
        #[arg(long, default_value = "0.0.0.0:9000")]
        bind: String,
    },
    /// 隧道入口: 本地监听, 流量经隧道从 peer 出去
    Dial {
        #[arg(long)]
        peer: String,
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
        /// 固定目标 host:port (P0; P3 起由策略路由决定)
        #[arg(long)]
        target: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    if matches!(cli.cmd, Cmd::Keygen) {
        let ns = NetworkSecret::generate();
        println!("network_secret = {}", ns.to_hex());
        let (pkcs8, id_pub) = yz_crypto::generate_identity()?;
        std::fs::write(&cli.id_file, &pkcs8)
            .with_context(|| format!("write {}", cli.id_file.display()))?;
        println!("identity saved to {}", cli.id_file.display());
        println!("node_id = {}", yz_crypto::node_id(&id_pub));
        return Ok(());
    }

    let ns = load_secret(&cli)?;
    let id_pub = load_or_create_identity(&cli.id_file)?;
    log::info!("node_id = {}", yz_crypto::node_id(&id_pub));

    match cli.cmd {
        Cmd::Keygen => unreachable!(),
        Cmd::Serve { bind } => {
            let listener = TcpListener::bind(&bind).await?;
            log::info!("serving tunnel on {bind}");
            loop {
                let (stream, from) = listener.accept().await?;
                let ns = ns.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(stream, &ns, &id_pub).await {
                        // 探测/握手失败属正常噪音, 降级为 debug
                        log::debug!("conn from {from} closed: {e:#}");
                    }
                });
            }
        }
        Cmd::Dial {
            peer,
            listen,
            target,
        } => {
            let target = parse_addr(&target)?;
            let listener = TcpListener::bind(&listen).await?;
            log::info!("entry on {listen}, via {peer} -> {target}");
            loop {
                let (local, from) = listener.accept().await?;
                let ns = ns.clone();
                let peer = peer.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    if let Err(e) = dial_conn(local, &peer, &target, &ns, &id_pub).await {
                        log::warn!("dial for {from} failed: {e:#}");
                    }
                });
            }
        }
    }
}

// ---------- serve 侧 ----------

async fn serve_conn(stream: TcpStream, ns: &NetworkSecret, id_pub: &[u8; 32]) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (mut r, mut w) = stream.into_split();

    let mut msg1 = vec![0u8; MSG1_LEN];
    timeout(HS_TIMEOUT, r.read_exact(&mut msg1)).await??;
    let (msg2, sess, peer) = handshake_accept(ns, id_pub, &msg1)?;
    w.write_all(&msg2).await?;
    log::info!("peer {} authed", peer.node_id());

    let sess = Arc::new(Mutex::new(sess));
    let frame = read_frame(&mut r, &sess).await?;
    let Frame::Syn { stream_id, addr } = frame else {
        bail!("expect SYN, got {frame:?}");
    };

    let target = addr.to_string();
    match TcpStream::connect(&target).await {
        Ok(outbound) => {
            send_frame(
                &mut w,
                &sess,
                &Frame::SynAck {
                    stream_id,
                    ok: true,
                },
            )
            .await?;
            log::info!("stream {stream_id} -> {target}");
            pump(outbound, r, w, sess, stream_id).await
        }
        Err(e) => {
            send_frame(
                &mut w,
                &sess,
                &Frame::SynAck {
                    stream_id,
                    ok: false,
                },
            )
            .await
            .ok();
            Err(e.into())
        }
    }
}

// ---------- dial 侧 ----------

async fn dial_conn(
    local: TcpStream,
    peer: &str,
    target: &Addr,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
) -> Result<()> {
    let stream = TcpStream::connect(peer).await?;
    stream.set_nodelay(true).ok();

    let (msg1, st) = handshake_init(ns, id_pub)?;
    let (mut r, mut w) = stream.into_split();
    w.write_all(&msg1).await?;
    let mut msg2 = vec![0u8; MSG2_LEN];
    timeout(HS_TIMEOUT, r.read_exact(&mut msg2)).await??;
    let (sess, peer_info) = handshake_finish(ns, st, &msg2)?;
    let sess = Arc::new(Mutex::new(sess));

    let stream_id = 1u32;
    send_frame(
        &mut w,
        &sess,
        &Frame::Syn {
            stream_id,
            addr: target.clone(),
        },
    )
    .await?;
    match read_frame(&mut r, &sess).await? {
        Frame::SynAck { ok: true, .. } => {
            log::info!("tunnel to {} ready", peer_info.node_id());
        }
        Frame::SynAck { ok: false, .. } => bail!("remote failed to connect {target}"),
        f => bail!("expect SYN_ACK, got {f:?}"),
    }
    pump(local, r, w, sess, stream_id).await
}

// ---------- 双向转发 ----------

async fn pump(
    local: TcpStream,
    mut tr: OwnedReadHalf,
    mut tw: OwnedWriteHalf,
    sess: Arc<Mutex<Session>>,
    stream_id: u32,
) -> Result<()> {
    local.set_nodelay(true).ok();
    let (mut lr, mut lw) = local.into_split();

    // local -> tunnel
    let s2 = sess.clone();
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; IO_BUF];
        loop {
            match lr.read(&mut buf).await {
                Ok(0) => {
                    let _ = send_frame(&mut tw, &s2, &Frame::Fin { stream_id }).await;
                    break;
                }
                Ok(n) => {
                    let f = Frame::Data {
                        stream_id,
                        payload: buf[..n].to_vec(),
                    };
                    if send_frame(&mut tw, &s2, &f).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = send_frame(&mut tw, &s2, &Frame::Rst { stream_id }).await;
                    break;
                }
            }
        }
    });

    // tunnel -> local
    loop {
        match read_frame(&mut tr, &sess).await {
            Ok(Frame::Data { payload, .. }) => {
                if lw.write_all(&payload).await.is_err() {
                    break;
                }
            }
            Ok(Frame::Fin { .. }) => {
                lw.shutdown().await.ok();
            }
            Ok(Frame::Rst { .. }) => break,
            Ok(_) => {} // PING/PONG/WIN 等 P0 忽略
            Err(_) => break,
        }
    }
    uplink.abort();
    Ok(())
}

// ---------- 帧读写 ----------

async fn read_frame(r: &mut OwnedReadHalf, sess: &Arc<Mutex<Session>>) -> Result<Frame> {
    let mut lb = [0u8; 2];
    r.read_exact(&mut lb).await?;
    let masked = u16::from_be_bytes(lb);
    let len = { sess.lock().await.unmask_len(masked) };
    anyhow::ensure!(
        len > 16 && len <= MAX_FRAME_LEN + 16,
        "bad packet len {len}"
    );
    let mut ct = vec![0u8; len];
    r.read_exact(&mut ct).await?;
    let plain = { sess.lock().await.open(masked, &mut ct)? };
    Ok(yz_proto::decode(&plain)?)
}

async fn send_frame(w: &mut OwnedWriteHalf, sess: &Arc<Mutex<Session>>, f: &Frame) -> Result<()> {
    let pkt = { sess.lock().await.seal(&yz_proto::encode(f))? };
    w.write_all(&pkt).await?;
    Ok(())
}

// ---------- 工具 ----------

fn load_secret(cli: &Cli) -> Result<NetworkSecret> {
    let s = cli
        .network_secret
        .clone()
        .context("missing --network-secret or YZ_NETWORK_SECRET (run `yz keygen` first)")?;
    Ok(NetworkSecret::from_hex(&s)?)
}

fn load_or_create_identity(path: &PathBuf) -> Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(b) => Ok(yz_crypto::load_identity(&b)?),
        Err(_) => {
            let (pkcs8, id_pub) = yz_crypto::generate_identity()?;
            std::fs::write(path, &pkcs8).with_context(|| format!("write {}", path.display()))?;
            log::info!("generated new identity -> {}", path.display());
            Ok(id_pub)
        }
    }
}

fn parse_addr(s: &str) -> Result<Addr> {
    let (host, port_s) = s
        .rsplit_once(':')
        .with_context(|| format!("addr must be host:port, got {s}"))?;
    let port: u16 = port_s.parse().context("bad port")?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(v4) => Addr::V4(v4.octets(), port),
            IpAddr::V6(v6) => Addr::V6(v6.octets(), port),
        });
    }
    anyhow::ensure!(!host.is_empty() && host.len() <= 255, "bad host");
    Ok(Addr::Domain(host.to_string(), port))
}
