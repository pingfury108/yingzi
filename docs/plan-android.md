# Android 客户端方案（路径 B · 流级分流）

> 状态：P1–P5 完成（Android 客户端已跑通） ｜ 目标设备：Xiaomi MIX 4 (odin) / Android 14 (SDK 34) / arm64-v8a
> 关联文档：[plan.md](plan.md)（协议与桌面端）｜ [deploy.md](deploy.md)（部署）

## 1. 定位

Android 客户端 = **代理客户端 + mesh 成员**，不是服务端。

| 做 | 不做 |
|---|---|
| 加入组网、访问其他设备 vIP | 当出口给别人用（`caps=0`） |
| 分流：**外网 → 出口节点**，**国内/私网 → 本机直发** | ingress 端口发布 |
| 域名/geoip 规则、广告拦截、多出口选择 | SOCKS5 入口 / Web 控制台 |
| 节点列表、规则命中追踪、流量统计 | — |

**桌面端（yz-node）功能与行为完全不变。**

## 2. 技术路线：流级（路径 B）

```
TUN(IP 包) → smoltcp 终结成"流" → 每条流决策
                                    ├─ Direct → protect() 过的 socket 从物理网卡发
                                    ├─ Exit(node) → 复用现有出口节点的流级转发
                                    └─ Block → RST / 丢弃
```

选择理由（对比"系统路由排除"路径 A）：

| 维度 | 路径 B（选定） | 路径 A |
|---|---|---|
| Android 版本 | 全版本 | 需 API 33+ (`excludeRoute`) |
| 出口节点改造 | **不需要** gateway，复用现有流级出口 | 需 IP 级网关 + NAT |
| 域名分流 / 广告拦截 | 天然支持 | 只能 IP 级 |
| 直连精度 | 精确到 IP/域名 | 受路由条数限制 |
| 代价 | 需接入 smoltcp | 实现简单 |

## 3. 代码组织

```
crates/
├── yz-proto/  yz-crypto/  yz-rudp/     # 不变
├── yz-core/        # 新：共享引擎（纯逻辑，无 CLI / 无 axum）
│   ├── tunnel.rs   # 多路复用隧道（TCP/UDP/WSS 承载、流、中继、rekey、健康检测）
│   ├── policy.rs   # 规则引擎（matcher/action/ACL）
│   ├── wss.rs      # TLS + WebSocket 承载（模仿模式）
│   ├── mesh.rs     # vIP + MESH 帧路由 + PacketIo trait
│   ├── geo.rs      # geoip.dat / geosite.dat 解析与索引
│   ├── dns.rs      # DNS 代理（拦截/决策/缓存）
│   ├── stack.rs    # smoltcp 集成（feature = "stack"）
│   ├── exit.rs     # 出口数据面（serve 侧）
│   └── stats.rs    # 流量/连接/规则命中统计
├── yz-node/        # 桌面二进制：CLI + web + socks5 + ingress + TUN(设备路径)
└── yz-android/     # 新：cdylib + JNI
android/            # 新：Kotlin App（Gradle）
```

**PacketIo 抽象**（桌面用设备路径，Android 用 VpnService fd）：

```rust
pub trait PacketIo: Send + Sync {
    async fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize>;
    async fn send(&self, pkt: &[u8]) -> anyhow::Result<()>;
}
```

**重构原则**：只搬移不改逻辑；每阶段跑单测 + 6 节点冒烟；打 tag 作回滚点。

## 4. 分流设计

### 4.1 规则模型

```rust
enum Action { Direct, Exit(Option<String>), Block }

enum Matcher {
    GeoIp(String),        // cn / private / telegram
    GeoSite(String),      // cn / google / netflix / category-ads-all
    Cidr(CidrV4),
    DomainSuffix(String),
    Port(u16),
    App(String),          // Android 包名
}
```

匹配顺序：`用户规则（有序） → geo 预设 → 默认动作`

### 4.2 判定链路

```
1) 按 App        VpnService.addDisallowedApplication → 完全绕过
2) 按域名        DNS 拦截（流级）→ 域名规则 → 缓存 domain→IP
3) 按 IP         geoip / CIDR（含 DNS 缓存映射）
```

### 4.3 DNS 代理

```
UDP:53 流 → yz-core DNS 代理
  ├─ Block   → 0.0.0.0 / NXDOMAIN（广告拦截）
  ├─ Direct  → 本地 DNS（protect socket）
  └─ Exit    → 经出口节点解析（防污染）
记录 domain → (决策, IP, TTL)
```

v2 增强：fake-IP 模式（立即返回假 IP，异步解析后按域名决策）。

## 5. geo 数据与广告拦截

| 项 | 方案 |
|---|---|
| 格式 | `geoip.dat` / `geosite.dat`（v2ray protobuf，`prost`） |
| 性能 | CIDR：前缀分桶 + 有序数组二分；域名：反向标签逐级查表 |
| 体积 | 按需加载类别；APK 内置精简子集，全量按需下载 |
| 更新 | 应用内检查更新 → 下载 → 校验 → 原子替换 |
| 广告拦截 | `geosite:category-ads-all` + 自定义列表 → DNS sinkhole；IP 兜底；白名单 |
| 许可 | 数据源许可需核对；优先运行时下载而非打包 |

## 6. Android 集成

| 项 | 要点 |
|---|---|
| VpnService | `addRoute("0.0.0.0/0")` + `::/0`；fd 交给 Rust（`AsyncFd`，无 AF 头） |
| **protect(fd)** | 所有出口 socket 必须 protect，否则被自己的 VPN 捕获 |
| 前台服务 | 常驻通知（出口/延迟/流量/拦截数） |
| 网络切换 | `ConnectivityManager` → 重建 UDP endpoint + 重打洞 |
| Keystore | NS/身份加密存储 |
| Always-on / Kill Switch | 系统原生能力 |
| 体积 | 仅 `arm64-v8a`，APK 约 10–15MB |

## 7. JNI 接口

```
nativeStart(configJson)
nativeStop()
nativeStatus()  -> json
nativeEvents()  -> json
nativeSetRules(json)
nativeProtectFd(fd)      // ★ VpnService.protect
nativeDnsQuery(...)
```

## 8. 可观测

- 规则命中追踪：`doubleclick.net → geosite:category-ads-all → Block`
- 流量：按出口 / 按 App / 上下行；拦截计数
- 事件流：隧道建立/失效/重建
- UI：开关、节点列表（vIP/路径/RTT）、规则编辑、命中日志、统计

## 9. 分期与验收

| 阶段 | 内容 | 验收 | 估时 |
|---|---|---|---|
| **P1** | 抽 `yz-core`（搬移 + PacketIo），yz-node 依赖它 | 单测全过 + 6 节点冒烟行为等价 | 3–4 天 |
| **P2** | 规则引擎 + geoip/geosite 解析（含命中追踪） | 真实 .dat 解析 + 规则单测 | 4–5 天 |
| **P3** | DNS 代理（Block/Direct/Exit + 缓存） | DNS 用例集；拦截率；污染域 | 3–4 天 |
| **P4** | smoltcp 栈（Linux 上用 TUN 验证） | 整机流量按规则分流 | 7–10 天 |
| **P5** ✔ | `yz-android` JNI + Kotlin 壳（VpnService 全隧道 + 前台服务 + 极简 UI） | 真机：curl 出口 IP = 149.129.41.181，google 204 | 已完成 |
| **P6** | 网络切换自愈、保活、Keystore、Always-on | 24h 稳定、WiFi↔4G | 4–6 天 |
| **P7a** ✔ | fake-IP（198.18.0.0/15，代理域名按域名分流） | 真机：google→198.18.0.1，baidu→真实 IP，日志显示域名决策 | 已完成 |
| **P7** | fake-IP、SNI 嗅探、多出口、统计图表、二维码 | 体验完善 | 4–6 天 |

## 10. 风险

| 风险 | 对策 |
|---|---|
| P1 重构影响现有 6 节点 | 只搬移；每阶段冒烟 + git tag 回滚点 |
| smoltcp 复杂度 | 参考 `tun2proxy`(MIT)；先 TCP 后 UDP；ICMP 丢弃 |
| 厂商 ROM 杀后台 | 前台服务 + 白名单 + Always-on |
| 对称 NAT 打洞失败 | 中继兜底 + 短打洞快速降级 |
| geo 数据许可 | 运行时下载；核对后决定是否内置 |
| 电耗 | 空闲保活 30s、灭屏降频 |

## 10.1 真机验证记录（P5）

设备: Xiaomi MIX 4 (odin) / Android 14 / arm64-v8a，adb 在 pcw 上

```
安装: adb install app-debug.apk (20MB, 含 geo 数据)
授权: adb shell cmd appops set io.yingzi.app ACTIVATE_VPN allow
启动: adb shell am start -n io.yingzi.app/.MainActivity --ez autostart true

验证:
  curl ifconfig.me → 149.129.41.181   (海外出口节点)  ✓
  curl google/generate_204 → 204                        ✓
  关闭 VPN 后 → 123.139.9.92 (家庭 IP)                  ✓
  分流统计: direct 36 / exit 3, DNS 0 失败               ✓
```

**踩坑记录**：
- `VpnService.Builder.setBlocking(false)` 会让 TUN fd 非阻塞 → 读线程 EAGAIN 立即退出（必须保持阻塞读）
- 服务 `exported=false` 时 adb 无法直接启动 → 用 Activity 的 `autostart` extra
- `addDisallowedApplication` + `protect(fd)` 两者都要（前者排除自身进程，后者逐 socket 兜底）

## 11. 构建与测试环境

| 用途 | 位置 |
|---|---|
| Rust 构建（x86_64 / aarch64 musl） | `rdev` → pcw (`/data/rdev/yingzi`) |
| Android 交叉编译（`aarch64-linux-android`） | 同上（cargo-ndk / NDK 工具链） |
| 真机 | `adb` 在 pcw 上，设备 `192.168.32.145:38363`（Xiaomi MIX 4 / Android 14 / arm64-v8a） |
| 现网验证 | 6 节点（VPS 协调器 + 海外出口 + pcw/树莓派/fury/Mac） |
