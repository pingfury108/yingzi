//! yz-core: 组网引擎（可被桌面二进制与 Android 客户端复用）
//!
//! 这里只放**与 IO 框架无关**的共享逻辑：
//! - tunnel: 多路复用隧道（TCP/UDP/WSS 承载、流、中继、rekey、健康检测）
//! - policy: 分流规则与 ACL
//! - wss:    TLS + WebSocket 承载（模仿模式）
//!
//! 不含：CLI、Web 控制台、SOCKS5 入口、ingress、TUN 设备路径（用 PacketIo 抽象）。

pub mod policy;
pub mod tunnel;
pub mod wss;
