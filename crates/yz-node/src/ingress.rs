//! 入口发布 (plan.md §5A): 公网端口 → 组网内节点的服务。
//! 静态: CLI --ingress "listen=node/addr"; 动态: 对端发 INGRESS_PUB 控制消息。

use crate::node::{resolve_node, tunnel_for, NodeState};
use crate::policy::ExitAcl;
use crate::tunnel::{self, Tunnel};
use anyhow::{Context, Result};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use yz_crypto::NetworkSecret;
use yz_proto::{Addr, Frame};

#[derive(Debug, Clone)]
pub struct IngressRule {
    pub listen: String,
    pub node: String,
    pub addr: String,
}

/// "listen=node/addr", 例: 0.0.0.0:8080=nas-home/127.0.0.1:80
pub fn parse_rule(s: &str) -> Result<IngressRule, String> {
    let (listen, rest) = s
        .split_once('=')
        .ok_or_else(|| format!("ingress must be listen=node/addr: {s}"))?;
    let (node, addr) = rest
        .split_once('/')
        .ok_or_else(|| format!("ingress must be listen=node/addr: {s}"))?;
    Addr::parse(addr)?;
    Ok(IngressRule {
        listen: listen.to_string(),
        node: node.to_string(),
        addr: addr.to_string(),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct IngressEntry {
    pub port: u16,
    pub node: String,
    pub addr: String,
    pub dynamic: bool,
}

/// 静态发布: 每个公网连接实时解析目标节点并开流
pub async fn run_static(
    rule: IngressRule,
    state: Arc<NodeState>,
    ns: NetworkSecret,
    id_pub: [u8; 32],
    self_id: String,
) -> Result<()> {
    let addr = Addr::parse(&rule.addr).map_err(|e| anyhow::anyhow!(e))?;
    let listener = TcpListener::bind(&rule.listen).await?;
    let port = listener.local_addr()?.port();
    log::info!("ingress {} -> {}/{}", rule.listen, rule.node, rule.addr);
    state.ingress_pub.write().await.push(IngressEntry {
        port,
        node: rule.node.clone(),
        addr: rule.addr.clone(),
        dynamic: false,
    });
    loop {
        let (stream, from) = listener.accept().await?;
        let state = state.clone();
        let ns = ns.clone();
        let node_key = rule.node.clone();
        let addr = addr.clone();
        let self_id = self_id.clone();
        tokio::spawn(async move {
            if let Err(e) = forward_via_node(stream, &state, &ns, &id_pub, &node_key, addr, &self_id).await
            {
                log::debug!("ingress conn {from}: {e:#}");
            }
        });
    }
}

async fn forward_via_node(
    stream: TcpStream,
    state: &Arc<NodeState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    node_key: &str,
    addr: Addr,
    self_id: &str,
) -> Result<()> {
    let node = resolve_node(state, node_key)
        .await
        .context("ingress target not in directory")?;
    // 目标是自己: 直接本地连, 不走隧道
    if node.node_id == self_id {
        let out = TcpStream::connect(addr.to_string()).await?;
        return pipe(stream, out).await;
    }
    let t = tunnel_for(state, ns, id_pub, &node.node_id).await?;
    open_and_pump(stream, addr, t).await
}

async fn open_and_pump(stream: TcpStream, addr: Addr, t: Arc<Tunnel>) -> Result<()> {
    let (sid, mut rx) = t.open_stream(addr).await?;
    match timeout(Duration::from_secs(10), rx.recv()).await? {
        Some(Frame::SynAck { ok: true, .. }) => tunnel::pump_stream(stream, sid, rx, t).await,
        Some(Frame::SynAck { ok: false, .. }) => anyhow::bail!("target refused stream"),
        _ => anyhow::bail!("expect SYN_ACK"),
    }
}

/// 处理对端的动态发布请求 (INGRESS_PUB), 返回 (ok, msg)
pub async fn handle_pub_request(
    state: &Option<Arc<NodeState>>,
    acl: &ExitAcl,
    range: (u16, u16),
    peer_id: &str,
    port: u16,
    addr: &str,
    t: Arc<Tunnel>,
) -> (bool, String) {
    if !acl.allows(peer_id) {
        log::warn!("ingress denied for peer {} (acl)", &peer_id[..8]);
        return (false, "denied by acl".into());
    }
    if port < range.0 || port > range.1 {
        log::warn!(
            "ingress denied for peer {} (port {port} out of range {}-{})",
            &peer_id[..8],
            range.0,
            range.1
        );
        return (
            false,
            format!("port {port} out of range {}-{}", range.0, range.1),
        );
    }
    let addr = match Addr::parse(addr) {
        Ok(a) => a,
        Err(e) => return (false, e),
    };
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => return (false, format!("bind: {e}")),
    };
    log::info!("ingress :{port} -> {}:{addr} (dynamic)", &peer_id[..8]);
    if let Some(st) = state {
        st.ingress_pub.write().await.push(IngressEntry {
            port,
            node: peer_id[..8].to_string(),
            addr: addr.to_string(),
            dynamic: true,
        });
    }
    let task = tokio::spawn({
        let t = t.clone();
        async move {
            loop {
                match listener.accept().await {
                    Ok((stream, from)) => {
                        let t = t.clone();
                        let addr = addr.clone();
                        tokio::spawn(async move {
                            let r: Result<()> = open_and_pump(stream, addr, t).await;
                            if let Err(e) = r {
                                log::debug!("dyn ingress conn {from}: {e:#}");
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    });
    // 隧道断开则回收监听
    let mut closed = t.watch_closed();
    tokio::spawn(async move {
        let _ = closed.changed().await;
        task.abort();
        log::info!("ingress :{port} recycled (tunnel closed)");
    });
    (true, "ok".into())
}

/// 直连双向转发 (目标为本机时)
async fn pipe(a: TcpStream, b: TcpStream) -> Result<()> {
    let (mut ar, mut aw) = a.into_split();
    let (mut br, mut bw) = b.into_split();
    let x = tokio::io::copy(&mut ar, &mut bw);
    let y = tokio::io::copy(&mut br, &mut aw);
    let _ = tokio::join!(x, y);
    Ok(())
}
