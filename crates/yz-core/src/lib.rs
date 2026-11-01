//! yz-core: 组网引擎（可被桌面二进制与 Android 客户端复用）
//!
//! 只放**与 IO 框架无关**的共享逻辑：隧道、规则、承载、状态、地址工具。
//! 不含：CLI、Web 控制台、SOCKS5 入口、ingress 发布、TUN 设备路径。

pub mod dns;
pub mod exit_dns;
pub mod exit_udp;
pub mod fakeip;
pub mod geo;
pub mod ingress;
pub mod mesh;
pub mod peer;
pub mod policy;
pub mod stack;
pub mod tcp_stack;
pub mod state;
pub mod tunnel;
pub mod util;
pub mod wss;
