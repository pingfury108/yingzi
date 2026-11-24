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
    /// 域名访问统计: 域名 → (次数, 动作)
    pub domains: RwLock<HashMap<String, (u64, String)>>,
    /// 最近一次与协调器成功交互的时间 (unix ms, 0 = 从未)
    /// 用原子量而非锁: 看门狗必须能在任何锁死的情况下读到它
    pub coord_seen_ms: std::sync::atomic::AtomicU64,
    /// 出口自动选路结果: 出口 node_id → 选定路径
    pub exit_path: RwLock<HashMap<String, ExitChoice>>,
    /// 正在后台测路的出口（避免重复探测）
    pub exit_measuring: RwLock<std::collections::HashSet<String>>,
    /// 每对节点的链路诊断计数
    pub peer_diag: RwLock<HashMap<String, PeerDiag>>,
    /// 本机 UDP 映射存活时间估计（秒，0 = 未知）
    pub nat_lifetime_secs: std::sync::atomic::AtomicU64,
    /// 本节点 id（出口选路需要排除自己）
    pub self_id: std::sync::OnceLock<String>,
}

/// 单个对等节点的链路诊断计数（"不稳定"要从这里看）
#[derive(Default, Clone, serde::Serialize)]
pub struct PeerDiag {
    /// 打洞尝试 / 成功 / 失败
    pub punch_try: u64,
    pub punch_ok: u64,
    pub punch_fail: u64,
    /// 最近一次打洞耗时（毫秒）
    pub punch_ms: u64,
    /// 直连（TCP）成功次数 / 经协调器中继次数
    pub direct_ok: u64,
    pub relay_ok: u64,
    /// 被判定失效（僵尸）次数
    pub dead: u64,
    /// 路径切换次数
    pub path_switches: u64,
    /// 最近一次切换距今（秒）
    pub last_switch_secs: u64,
    /// 最近一次已知路径（p2p/direct/relay）
    pub path: String,
}

/// 出口路径选择（直连 or 经中转）
#[derive(Clone)]
pub struct ExitChoice {    /// Some(B) = 经 B 中转; None = 直连出口
    pub via: Option<String>,
    /// 建链耗时（毫秒），用于比较与展示
    pub ms: u64,
    pub at: std::time::Instant,
    /// 经中转时缓存的嵌套隧道（直连时为 None，走 tunnels 表）
    pub tunnel: Option<Arc<Tunnel>>,
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
    /// 记录本节点 id（启动时调一次）
    pub fn set_self_id(&self, id: &str) {
        let _ = self.self_id.set(id.to_string());
    }

    pub fn self_id(&self) -> &str {
        self.self_id.get().map(|s| s.as_str()).unwrap_or("")
    }

    /// 更新某节点的诊断计数（不拿到锁就静默跳过，不影响业务）
    pub fn diag<F: FnOnce(&mut PeerDiag)>(&self, node_id: &str, f: F) {
        let Ok(mut m) = self.peer_diag.try_write() else {
            return;
        };
        f(m.entry(node_id.to_string()).or_default());
    }

    /// 记录一次路径选定/切换
    pub fn note_path(&self, node_id: &str, path: &str) {
        self.diag(node_id, |d| {
            if d.path != path {
                if !d.path.is_empty() {
                    d.path_switches += 1;
                }
                d.path = path.to_string();
                d.last_switch_secs = 0;
            }
        });
    }

    /// 记录一次与协调器的成功交互（注册成功 / 收到 DirSync）
    pub fn touch_coord(&self) {
        self.coord_seen_ms
            .store(crate::util::now_ms(), std::sync::atomic::Ordering::Relaxed);
    }

    /// 距上次与协调器交互的秒数 (None = 尚未成功过)
    pub fn coord_silence_secs(&self) -> Option<u64> {
        let ms = self
            .coord_seen_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if ms == 0 {
            return None;
        }
        let now = crate::util::now_ms();
        Some(now.saturating_sub(ms) / 1000)
    }

    /// 域名访问计数（用于统计页 TOP 榜）
    pub async fn bump_domain(&self, domain: &str, action: &str) {
        let mut m = self.domains.write().await;
        if m.len() > 500 {
            m.clear();
        }
        let e = m
            .entry(domain.to_ascii_lowercase())
            .or_insert((0, action.to_string()));
        e.0 += 1;
        e.1 = action.to_string();
    }

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
