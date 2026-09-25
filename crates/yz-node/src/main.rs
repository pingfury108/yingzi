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
mod ingress;
mod mesh;
mod node;
mod policy;
mod socks5;
mod tunnel;
mod web;
mod wss;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
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
        /// 握手失败连接的伪装转发目标, 如 127.0.0.1:443
        #[arg(long)]
        fallback: Option<String>,
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
        /// 对外公布的隧道监听地址 (默认取 bind; 通配地址由 coordinator 替换为观察到的源IP)
        #[arg(long)]
        advertise: Option<String>,
        /// 本地 SOCKS5 入口地址, 如 127.0.0.1:1080
        #[arg(long)]
        socks5: Option<String>,
        /// Web UI 监听地址, 如 127.0.0.1:9800
        #[arg(long)]
        web: Option<String>,
        /// 静态入口发布 "listen=node/addr", 可多次; 例: 0.0.0.0:8080=nas-home/127.0.0.1:80
        #[arg(long = "ingress")]
        ingress: Vec<String>,
        /// 动态入口发布 ACL: all | none | node_id列表(逗号分隔)
        #[arg(long, default_value = "none")]
        ingress_allow: String,
        /// 动态发布允许的端口范围
        #[arg(long, default_value = "8000-9999")]
        ingress_ports: String,
        /// 分流规则 "matcher=exit", 可多次; matcher: domain-suffix:x / domain:x / cidr:x/n
        #[arg(long = "route")]
        routes: Vec<String>,
        /// 默认出口: direct | auto | 节点名/node_id 前缀
        #[arg(long, default_value = "direct")]
        default_exit: String,
        /// 我当出口的 ACL: all | none | node_id列表(逗号分隔, 支持前缀)
        #[arg(long, default_value = "none")]
        exit_allow: String,
        /// 握手失败连接的伪装转发目标, 如 127.0.0.1:443
        #[arg(long)]
        fallback: Option<String>,
        /// TUN 网卡名, 启用虚拟组网 (需 root/CAP_NET_ADMIN)
        #[arg(long)]
        tun: Option<String>,
    },
    /// 独立隧道出口(无 mesh)
    Serve {
        #[arg(long, default_value = "0.0.0.0:9000")]
        bind: String,
        /// 使用 UDP 可靠传输而非 TCP
        #[arg(long)]
        udp: bool,
        /// 握手失败连接的伪装转发目标, 如 127.0.0.1:443
        #[arg(long)]
        fallback: Option<String>,
        /// WSS 模仿模式: TLS 证书 PEM (需与 --wss-key 同时给)
        #[arg(long)]
        wss_cert: Option<String>,
        /// WSS 模仿模式: TLS 私钥 PEM
        #[arg(long)]
        wss_key: Option<String>,
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
        /// 使用 UDP 可靠传输而非 TCP
        #[arg(long)]
        udp: bool,
        /// WSS 模仿模式: SNI 域名 (挂 CDN 时用 CDN 域名)
        #[arg(long)]
        wss_sni: Option<String>,
        /// WSS 跳过证书校验 (自签测试用)
        #[arg(long)]
        wss_insecure: bool,
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
        Cmd::Coord { bind, fallback } => coord::run(&bind, &ns, id_pub, fallback).await,
        Cmd::Node {
            bind,
            coordinator,
            name,
            advertise,
            socks5,
            web,
            ingress,
            ingress_allow,
            ingress_ports,
            routes,
            default_exit,
            exit_allow,
            fallback,
            tun,
        } => {
            let routes = routes
                .iter()
                .map(|r| policy::RouteRule::parse(r))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("bad --route: {e}"))?;
            let ingress = ingress
                .iter()
                .map(|r| ingress::parse_rule(r))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("bad --ingress: {e}"))?;
            let ingress_ports = parse_port_range(&ingress_ports)?;
            node::run(
                node::NodeOpts {
                    advertise: advertise.unwrap_or_else(|| bind.clone()),
                    bind,
                    coord: coordinator,
                    name,
                    socks5,
                    web,
                    ingress,
                    ingress_acl: policy::ExitAcl::parse(&ingress_allow),
                    ingress_ports,
                    default_exit,
                    routes,
                    exit_acl: policy::ExitAcl::parse(&exit_allow),
                    fallback,
                    tun,
                },
                &ns,
                id_pub,
            )
            .await
        }
        Cmd::Serve {
            bind,
            udp,
            fallback,
            wss_cert,
            wss_key,
        } => {
            let wss = match (wss_cert, wss_key) {
                (Some(c), Some(k)) => Some((c, k)),
                (None, None) => None,
                _ => anyhow::bail!("--wss-cert 与 --wss-key 需同时提供"),
            };
            node::serve(&bind, &ns, id_pub, udp, fallback, wss).await
        }
        Cmd::Dial {
            peer,
            listen,
            target,
            udp,
            wss_sni,
            wss_insecure,
        } => {
            let wss = wss_sni.map(|s| (s, wss_insecure));
            dial::run(&peer, &listen, parse_addr(&target)?, &ns, id_pub, udp, wss).await
        }
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

fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    let (a, b) = s
        .split_once('-')
        .with_context(|| format!("port range must be a-b: {s}"))?;
    let lo: u16 = a.parse().context("bad range start")?;
    let hi: u16 = b.parse().context("bad range end")?;
    anyhow::ensure!(lo <= hi, "empty port range");
    Ok((lo, hi))
}

fn parse_addr(s: &str) -> Result<Addr> {
    Addr::parse(s).map_err(|e| anyhow::anyhow!(e))
}
