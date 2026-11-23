//! 出口自动选路：直连出口 vs 经其它节点中转（两跳）
//!
//! 动机：A 直连出口 C 可能绕远/丢包，而 A→B 与 B→C 都很顺；
//! 此时让 B 当跳板（B 只转发字节，端到端仍是 A↔C 双加密）。
//!
//! 数据面能力由 `peer::spawn_incoming_handler` 的中转分支提供，
//! 这里只负责「测哪条快、缓存多久、怎么不抖」。

use crate::peer::{spawn_ctrl_handler, tunnel_for};
use crate::state::ExitChoice;
use crate::tunnel;
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use yz_crypto::NetworkSecret;

/// 选路结果缓存时长
pub const TTL: Duration = Duration::from_secs(300);
/// 单条候选路径的握手超时
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
/// 最多尝试几个中转候选（按 A→B 的 RTT 排序取前 N，避免 N² 探测）
const MAX_HOPS: usize = 3;
/// 迟滞：新路径要比旧路径快这么多才切换，避免来回抖
const HYSTERESIS: f64 = 1.25;

use crate::state::CoreState;

/// 取到出口节点的隧道；必要时自动挑选「直连 or 经中转」并缓存。
/// `force_hop = Some(B)` 时只走「经 B 中转」（手动指定 B>C），不做自动挑选。
pub async fn exit_tunnel(
    state: &Arc<CoreState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    self_id: &str,
    exit_id: &str,
    force_hop: Option<&str>,
) -> Result<Arc<Tunnel0>> {
    // 1) 缓存命中（且隧道还活着，且中转段与请求一致）
    {
        let cache = state.exit_path.read().await;
        if let Some(c) = cache.get(exit_id) {
            let same_hop = match force_hop {
                Some(h) => c.via.as_deref() == Some(h),
                None => true,
            };
            if same_hop && c.at.elapsed() < TTL {
                if let Some(t) = &c.tunnel {
                    if !t.is_closed() {
                        return Ok(t.clone());
                    }
                } else {
                    // 直连：走常规隧道表
                    let tunnels = state.tunnels.lock().await;
                    if let Some(t) = tunnels.get(exit_id) {
                        if !t.is_closed() {
                            return Ok(t.clone());
                        }
                    }
                }
            }
        }
    }

    // 2) 重新测量
    let best = measure(state, ns, id_pub, self_id, exit_id, force_hop).await;
    if best.tunnel.is_none() {
        anyhow::bail!("出口 {exit_id} 两条路径都不可用");
    }

    // 3) 迟滞：旧结果还新鲜且没差太多，就沿用旧的（避免抖动）
    {
        let cache = state.exit_path.read().await;
        if let Some(old) = cache.get(exit_id) {
            if old.at.elapsed() < TTL {
                let old_alive = match &old.tunnel {
                    Some(t) => !t.is_closed(),
                    None => true,
                };
                if old_alive && (old.ms as f64) <= (best.ms as f64) * HYSTERESIS {
                    // 沿用旧选择
                    if let Some(t) = &old.tunnel {
                        if !t.is_closed() {
                            return Ok(t.clone());
                        }
                    } else {
                        let tunnels = state.tunnels.lock().await;
                        if let Some(t) = tunnels.get(exit_id) {
                            if !t.is_closed() {
                                return Ok(t.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    // 4) 记录并切换
    let chosen = best.tunnel.clone().expect("上面已校验");
    {
        let mut cache = state.exit_path.write().await;
        let prev = cache.insert(exit_id.to_string(), best.clone());
        let desc = match &best.via {
            Some(b) => format!("via {}", &b[..8.min(b.len())]),
            None => "direct".to_string(),
        };
        if let Some(p) = prev {
            let old_desc = match &p.via {
                Some(b) => format!("via {}", &b[..8.min(b.len())]),
                None => "direct".to_string(),
            };
            if old_desc != desc {
                state
                    .push_event(
                        "info",
                        format!(
                            "出口 {} 路径 {} {}ms → {} {}ms",
                            &exit_id[..8.min(exit_id.len())],
                            old_desc,
                            p.ms,
                            desc,
                            best.ms
                        ),
                    )
                    .await;
            }
        } else {
            state
                .push_event(
                    "info",
                    format!(
                        "出口 {} 路径选定 {} {}ms",
                        &exit_id[..8.min(exit_id.len())],
                        desc,
                        best.ms
                    ),
                )
                .await;
        }
    }
    Ok(chosen)
}

/// 隧道类型别名（避免与 tunnel::Tunnel 名字混淆）
type Tunnel0 = tunnel::Tunnel;

/// 测一条路径：先直连，再逐个尝试经中转
async fn measure(
    state: &Arc<CoreState>,
    ns: &NetworkSecret,
    id_pub: &[u8; 32],
    self_id: &str,
    exit_id: &str,
    force_hop: Option<&str>,
) -> ExitChoice {
    // --- 直连（手动指定中转时跳过） ---
    let mut best: Option<ExitChoice> = None;
    if force_hop.is_none() {
        let t0 = Instant::now();
        if let Ok(Ok(t)) =
            tokio::time::timeout(PROBE_TIMEOUT, tunnel_for(state, ns, id_pub, exit_id)).await
        {
            best = Some(ExitChoice {
                via: None,
                ms: t0.elapsed().as_millis() as u64,
                at: Instant::now(),
                tunnel: Some(t),
            });
        }
    }

    // --- 中转候选：手动指定只测它；否则按 A→B 的 RTT 取前 N ---
    let hops: Vec<String> = match force_hop {
        Some(h) => vec![h.to_string()],
        None => {
            let mut v: Vec<(u32, String)> = {
                let dir = state.dir.read().await;
                let rtt = state.rtt.read().await;
                dir.values()
                    .filter(|n| n.node_id != exit_id && n.node_id != self_id)
                    .map(|n| {
                        (
                            rtt.get(&n.node_id).copied().unwrap_or(u32::MAX),
                            n.node_id.clone(),
                        )
                    })
                    .collect()
            };
            v.sort();
            v.truncate(MAX_HOPS);
            v.into_iter().map(|(_, id)| id).collect()
        }
    };

    for hop in hops {
        let hop_t = match tokio::time::timeout(PROBE_TIMEOUT, tunnel_for(state, ns, id_pub, &hop))
            .await
        {
            Ok(Ok(t)) => t,
            _ => continue,
        };
        let t0 = Instant::now();
        let relayed = tokio::time::timeout(
            PROBE_TIMEOUT,
            tunnel::connect_relayed(&hop_t, exit_id, ns, id_pub),
        )
        .await;
        let h = match relayed {
            Ok(Ok(h)) => h,
            _ => continue,
        };
        let ms = t0.elapsed().as_millis() as u64;
        // 收养嵌套隧道：起心跳（测 RTT + 判活），丢弃我们不用的收流通道
        spawn_ctrl_handler(
            h.tunnel.clone(),
            h.ctrl_rx,
            exit_id.to_string(),
            Some(self_id.to_string()),
            Some(state.clone()),
            None,
        );
        let cand = ExitChoice {
            via: Some(hop),
            ms,
            at: Instant::now(),
            tunnel: Some(h.tunnel.clone()),
        };
        if force_hop.is_some() {
            best = Some(cand);
            break;
        }
        let better = match &best {
            Some(b) => ms < b.ms,
            None => true,
        };
        if better {
            best = Some(cand);
        }
    }

    best.unwrap_or(ExitChoice {
        via: None,
        ms: u64::MAX,
        at: Instant::now(),
        tunnel: None,
    })
}

/// 出口语法解析：`A` 或 `B>A`（A=出口，B=中转）
pub fn parse_spec(spec: &str) -> (Option<String>, String) {
    match spec.split_once('>') {
        Some((hop, target)) => (
            Some(hop.trim().to_string()),
            target.trim().to_string(),
        ),
        None => (None, spec.trim().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parse() {
        assert_eq!(parse_spec("overseas-hk"), (None, "overseas-hk".into()));
        assert_eq!(
            parse_spec("laptop>overseas-hk"),
            (Some("laptop".into()), "overseas-hk".into())
        );
        assert_eq!(
            parse_spec(" laptop > hk "),
            (Some("laptop".into()), "hk".into())
        );
    }
}