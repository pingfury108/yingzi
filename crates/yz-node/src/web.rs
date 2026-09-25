//! 本地 Web UI (plan.md §6): 节点拓扑 / 出口选择 / 分流规则。
//! 仅监听本地; 轮询模式 (WS 实时推送留待后续)。

use crate::ingress::IngressEntry;
use crate::node::{resolve_node, tunnel_for, NodeState};
use crate::policy::RouteRule;
use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use yz_crypto::NetworkSecret;
use yz_proto::{caps, Addr, ControlMsg, Frame};

pub struct SelfInfo {
    pub node_id: String,
    pub name: String,
    pub socks5: Option<String>,
}

pub struct AppState {
    pub node: Arc<NodeState>,
    pub info: SelfInfo,
    pub ns: NetworkSecret,
    pub id_pub: [u8; 32],
}

#[derive(Serialize)]
struct StatusResp {
    node_id: String,
    name: String,
    socks5: Option<String>,
    default_exit: String,
    peers: usize,
}

#[derive(Serialize)]
struct NodeResp {
    node_id: String,
    name: String,
    addr: String,
    exit_capable: bool,
    is_self: bool,
}

#[derive(Serialize, Deserialize)]
struct ExitReq {
    exit: String,
}

#[derive(Serialize)]
struct RouteResp {
    index: usize,
    rule: String,
}

#[derive(Deserialize)]
struct RouteAddReq {
    rule: String,
}

pub async fn run(bind: &str, app: Arc<AppState>) -> Result<()> {
    let router = Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/nodes", get(nodes))
        .route("/api/exit", get(get_exit).post(set_exit))
        .route("/api/routes", get(list_routes).post(add_route))
        .route("/api/routes/{idx}", delete(del_route))
        .route("/api/ingress", get(list_ingress).post(req_ingress))
        .with_state(app);
    let listener = TcpListener::bind(bind).await?;
    log::info!("web ui on http://{bind}");
    axum::serve(listener, router).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn status(State(app): State<Arc<AppState>>) -> Json<StatusResp> {
    let peers = app.node.dir.read().await.len().saturating_sub(1);
    let default_exit = app.node.default_exit.read().await.clone();
    Json(StatusResp {
        node_id: app.info.node_id.clone(),
        name: app.info.name.clone(),
        socks5: app.info.socks5.clone(),
        default_exit,
        peers,
    })
}

async fn nodes(State(app): State<Arc<AppState>>) -> Json<Vec<NodeResp>> {
    let dir = app.node.dir.read().await;
    let mut v: Vec<NodeResp> = dir
        .values()
        .map(|n| NodeResp {
            node_id: n.node_id.clone(),
            name: n.name.clone(),
            addr: n.addr.clone(),
            exit_capable: n.caps & caps::EXIT != 0,
            is_self: n.node_id == app.info.node_id,
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Json(v)
}

async fn get_exit(State(app): State<Arc<AppState>>) -> Json<ExitReq> {
    Json(ExitReq {
        exit: app.node.default_exit.read().await.clone(),
    })
}

async fn set_exit(State(app): State<Arc<AppState>>, Json(req): Json<ExitReq>) -> StatusCode {
    log::info!("default exit -> {}", req.exit);
    *app.node.default_exit.write().await = req.exit;
    StatusCode::NO_CONTENT
}

async fn list_routes(State(app): State<Arc<AppState>>) -> Json<Vec<RouteResp>> {
    let routes = app.node.routes.read().await;
    Json(
        routes
            .iter()
            .enumerate()
            .map(|(i, r)| RouteResp {
                index: i,
                rule: r.to_string(),
            })
            .collect(),
    )
}

async fn add_route(State(app): State<Arc<AppState>>, Json(req): Json<RouteAddReq>) -> StatusCode {
    match RouteRule::parse(&req.rule) {
        Ok(r) => {
            log::info!("route + {}", req.rule);
            app.node.routes.write().await.push(r);
            StatusCode::CREATED
        }
        Err(e) => {
            log::warn!("bad route '{}': {e}", req.rule);
            StatusCode::BAD_REQUEST
        }
    }
}

async fn del_route(State(app): State<Arc<AppState>>, Path(idx): Path<usize>) -> StatusCode {
    let mut routes = app.node.routes.write().await;
    if idx < routes.len() {
        let r = routes.remove(idx);
        log::info!("route - {r}");
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// ---------- ingress ----------

#[derive(Serialize)]
struct IngressListResp {
    /// 本节点发布的公网映射
    published: Vec<IngressEntry>,
    /// 本节点向其他节点申请的映射
    requested: Vec<IngressEntry>,
}

#[derive(Deserialize)]
struct IngressReq {
    /// 入口节点 (名字/node_id前缀)
    node: String,
    port: u16,
    addr: String,
}

async fn list_ingress(State(app): State<Arc<AppState>>) -> Json<IngressListResp> {
    Json(IngressListResp {
        published: app.node.ingress_pub.read().await.clone(),
        requested: app.node.ingress_req.read().await.clone(),
    })
}

/// 请求远端节点发布端口: 向该节点的隧道发 INGRESS_PUB
async fn req_ingress(State(app): State<Arc<AppState>>, Json(req): Json<IngressReq>) -> StatusCode {
    match do_req_ingress(&app, &req).await {
        Ok(()) => StatusCode::CREATED,
        Err(e) => {
            log::warn!("ingress request: {e:#}");
            StatusCode::BAD_GATEWAY
        }
    }
}

async fn do_req_ingress(app: &AppState, req: &IngressReq) -> Result<()> {
    Addr::parse(&req.addr).map_err(|e| anyhow::anyhow!(e))?;
    let node = resolve_node(&app.node, &req.node)
        .await
        .context("node not in directory")?;
    let t = tunnel_for(&app.node, &app.ns, &app.id_pub, &node.node_id).await?;
    let payload = yz_proto::encode_control(&ControlMsg::IngressPub {
        port: req.port,
        addr: req.addr.clone(),
    });
    t.write_frame(&Frame::Control { payload }).await?;
    app.node.ingress_req.write().await.push(IngressEntry {
        port: req.port,
        node: node.node_id[..8].to_string(),
        addr: req.addr.clone(),
        dynamic: true,
    });
    log::info!("ingress requested: {}:{} -> {}", node.name, req.port, req.addr);
    Ok(())
}
