//! yz: yingzi 对等组网节点 (P1)
//! - keygen  生成网络密钥与节点身份
//! - coord   协调器: 节点注册/目录广播, 不接触业务明文
//! - node    对等节点: peer 隧道监听 + coordinator 注册 + 目录同步
//! - serve   独立隧道出口(无 mesh)
//! - dial    本地入口: 流量经复用隧道从 peer 出去
//!
//! 见 docs/plan.md。

mod coord;
mod dial;
mod node;
mod tunnel;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;
use yz_crypto::NetworkSecret;
use yz_proto::Addr;

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
    /// 协调器: 节点注册与目录广播
    Coord {
        #[arg(long, default_value = "0.0.0.0:9000")]
        bind: String,
    },
    /// 对等节点
    Node {
        #[arg(long, default_value = "0.0.0.0:9100")]
        bind: String,
        /// coordinator 地址 host:port
        #[arg(long)]
        coordinator: String,
        /// 节点名
        #[arg(long, default_value = "node")]
        name: String,
    },
    /// 独立隧道出口(无 mesh)
    Serve {
        #[arg(long, default_value = "0.0.0.0:9000")]
        bind: String,
    },
    /// 本地入口: 流量经隧道从 peer 出去
    Dial {
        #[arg(long)]
        peer: String,
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
        /// 固定目标 host:port (P3 起由策略路由决定)
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
        Cmd::Coord { bind } => coord::run(&bind, &ns, id_pub).await,
        Cmd::Node {
            bind,
            coordinator,
            name,
        } => node::run(&bind, &coordinator, &name, &ns, id_pub).await,
        Cmd::Serve { bind } => node::serve(&bind, &ns, id_pub).await,
        Cmd::Dial {
            peer,
            listen,
            target,
        } => dial::run(&peer, &listen, parse_addr(&target)?, &ns, id_pub).await,
    }
}

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
