//! CoreState: 组网引擎的共享状态（桌面端与 Android 共用）

use crate::ingress::IngressEntry;
use crate::policy::RouteRule;
use crate::tunnel::Tunnel;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use yz_proto::NodeEntry;

#[derive(Default)]
pub struct CoreState {
    /// node_id -> 目录条目
    pub dir: RwLock<HashMap<String, NodeEntry>>,
    /// node_id -> 到该节点的隧道
    pub tunnels: Mutex<HashMap<String, Arc<Tunnel>>>,
    /// 分流规则 (Web UI 可热改)
    pub routes: RwLock<Vec<RouteRule>>,
    /// 默认出口 (Web UI 可热改)
    pub default_exit: RwLock<String>,
    /// 本节点发布的入口映射
    pub ingress_pub: RwLock<Vec<IngressEntry>>,
    /// 本节点向其他节点申请的入口映射
    pub ingress_req: RwLock<Vec<IngressEntry>>,
    /// UDP 端点 (P2P 打洞/直连)
    pub udp_ep: RwLock<Option<Arc<yz_rudp::Endpoint>>>,
    /// coordinator 隧道
    pub coord_tunnel: RwLock<Option<Arc<Tunnel>>>,
    /// 打洞等待者: target node_id → PunchStart addrs
    pub punch_pending: Mutex<HashMap<String, oneshot::Sender<Vec<String>>>>,
    /// mesh 收编: 隧道来的 IP 包 → TUN (未启用 TUN 时 None)
    pub mesh_sink: RwLock<Option<mpsc::Sender<Vec<u8>>>>,
    /// node_id → 最近测得 RTT (ms)
    pub rtt: RwLock<HashMap<String, u32>>,
    /// 持久化配置路径
    pub config_path: Option<PathBuf>,
    /// 事件环形缓冲 (Web 展示)
    pub events: RwLock<VecDeque<(i64, String, String)>>,
    /// node_id → 隧道路径 (p2p/direct/relay)
    pub path: RwLock<HashMap<String, String>>,
    /// 当前对外 UDP 映射 (探测成功后更新)
    pub udp_addr: RwLock<String>,
    /// P2P 连续失效计数: node_id → (次数, 降级截止时间)
    pub p2p_fail: RwLock<HashMap<String, (u32, std::time::Instant)>>,
}

impl CoreState {
    /// 追加事件 (环形, 上限 100 条)
    pub async fn push_event(&self, level: &str, msg: String) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut ev = self.events.write().await;
        ev.push_back((ts, level.to_string(), msg));
        while ev.len() > 100 {
            ev.pop_front();
        }
    }
}

/// 落盘的最小配置面 (Web UI 可改的那部分)
#[derive(Serialize, Deserialize, Default)]
pub struct PersistedConfig {
    pub default_exit: Option<String>,
    pub routes: Option<Vec<String>>,
}

impl CoreState {
    /// 汇总全网隧道流量统计: (tx字节, rx字节, 累计开流数)
    pub async fn traffic(&self) -> (u64, u64, u64) {
        let mut tx = 0u64;
        let mut rx = 0u64;
        let mut streams = 0u64;
        let mut add = |s: (u64, u64, u64)| {
            tx += s.0;
            rx += s.1;
            streams += s.2;
        };
        for t in self.tunnels.lock().await.values() {
            add(t.stats());
        }
        if let Some(ct) = &*self.coord_tunnel.read().await {
            add(ct.stats());
        }
        (tx, rx, streams)
    }

    /// 将当前路由/默认出口写入配置文件
    pub async fn save_config(&self) {
        let Some(path) = &self.config_path else { return };
        let cfg = PersistedConfig {
            default_exit: Some(self.default_exit.read().await.clone()),
            routes: Some(self.routes.read().await.iter().map(|r| r.to_string()).collect()),
        };
        match serde_json::to_string_pretty(&cfg) {
            Ok(s) => {
                if let Err(e) = std::fs::write(path, s) {
                    log::warn!("save config {}: {e}", path.display());
                }
            }
            Err(e) => log::warn!("serialize config: {e}"),
        }
    }
}
