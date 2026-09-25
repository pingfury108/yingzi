# yingzi 总体设计方案

> 自研对等组网 + 流量隐匿 + 出口选择 + Web UI
> 状态: v1 草案 (P0 已开工)

## 1. 目标与场景

所有设备组成一个对等网络（mesh），每个节点：

- 知道整个网络的拓扑（节点列表、在线状态、延迟）
- 本地提供翻墙入口（SOCKS5/HTTP），可配置流量从**任意节点**（或 direct）出去
- 可被其他节点选为出口（受 ACL 约束）
- 节点间优先 P2P 直连，失败走中继，全程端到端加密

场景：

| 场景 | 路径 |
|---|---|
| 翻墙 | 本机入口 → mesh → 海外 VPS 节点 → 公网 |
| 内网穿透/访问家中网络 | 本机入口 → mesh → 家里 NAS → 家庭内网 |
| 设备互访 | 任意两节点 → 虚拟 IP 直连 |

## 2. 总体架构

```
┌──────────────────────── yz (唯一二进制, 角色由配置决定) ───────────────────────┐
│  web-ui    本地 Web 控制台: 拓扑/出口选择/规则/状态                             │
│  entry     入口: SOCKS5/HTTP (P3), TUN 全局接管 (P6)                            │
│  exit      出口: 替其他节点访问公网/内网目标, ACL 控制                         │
│  ingress   入口发布: 公网端口 → 组网内任意节点的服务 (内网穿透)                  │
│  policy    出口策略: 按域名/geoip/cidr 选 exit node / direct / auto            │
│  mesh      peer 管理, 节点目录同步, 打洞, 中继, 虚拟IP路由                      │
│  session   加密会话 + 多路复用 (YZP 协议, 见 §3)                                │
│  transport 可插拔传输: udp-reliable(主力) / tcp-raw / wss(CDN兜底)              │
│  coordinator (可选开启) 注册表/撮合/密钥分发, 不接触明文                         │
└───────────────────────────────────────────────────────────────────────────────┘
```

原则：

- **全自研协议**：不用 QUIC/WireGuard/Shadowsocks 任何现成协议，无已知指纹
- **密码学原语用 `ring`**（X25519/Ed25519/ChaCha20-Poly1305/HKDF），协议与握手自研
- **传输可插拔**：上层 session/mux 不感知底层载体
- **无 client/server 对立**：只有 node；coordinator 是兼任角色

## 3. YZP 协议（yingzi protocol）

### 3.1 身份与网络密钥

- **网络密钥 NS**：32 字节随机数，组网时生成，全网节点共享。握手的准入凭证
- **节点身份**：Ed25519 密钥对，`node_id = hex(SHA256(id_pub))[..16]`
- 节点目录条目由节点私钥签名，防止 coordinator 伪造节点（P1）

### 3.2 握手（TCP/可靠流上，双向认证）

```
I → R:  eph_pub_i(32) | hs_nonce_i(12) | AEAD(k_hs1, aad=eph_pub_i,
          plain = id_pub_i(32) | ts(8) | nonce_i(16))          共 116 B
R → I:  eph_pub_r(32) | hs_nonce_r(12) | AEAD(k_hs2, aad=msg1,
          plain = id_pub_r(32) | nonce_r(16) | nonce_i(16))     共 124 B

k_hs1 = HKDF(salt="yz-hs1-v1", ikm=NS)   # 证明知道 NS, 无 NS 无法解密
k_hs2 = HKDF(salt="yz-hs2-v1", ikm=NS)
会话密钥 = HKDF(salt=SHA256(msg1|msg2), ikm=X25519_shared)
  → k_c2s, k_s2c (ChaCha20-Poly1305) + len_mask(16B)
```

- 任何一步失败：**静默断开，不回任何字节**（抗主动探测）
- ts 时间窗 ±120s，防重放；nonce_i 回显校验防中间人
- 前向保密：每次会话临时 X25519 密钥对
- 对观察者：116/124 字节随机噪声，无任何结构（噪声模式）

### 3.3 加密包格式（会话建立后）

```
packet = masked_len(2) | AEAD_seal(k_dir, nonce=be96(counter), frame) + tag(16)
masked_len = ct_len XOR mask_word(counter)     # 长度不可见, 包边界不可枚举
nonce = 0x00000000 | be64(counter)             # 单调计数器, 抗重放
```

### 3.4 多路复用帧（一个包一个帧）

```
type(1) | stream_id(4, be) | payload...

0x01 SYN        payload = addr(atype + host + port)   开流并指定目标
0x02 SYN_ACK    payload = ok(1)
0x03 DATA       payload = raw bytes
0x04 FIN        半关闭
0x05 RST        重置
0x06 WIN_UPDATE payload = delta(4)                    流控(P2 起启用)
0x10 CONTROL    stream_id=0, 控制消息(见 3.5)
0x11 PING / 0x12 PONG   payload = ts(8)
```

### 3.5 控制消息（CONTROL 帧内，P1 起）

```
0x01 HELLO        版本/能力/节点名
0x02 DIR_SYNC     节点目录全量/增量 (coordinator → node)
0x03 DIR_GOSSIP   节点目录摘要 (node ↔ node, 去中心化兜底)
0x04 PUNCH_REQ    请求与某 peer 打洞 (→ coordinator)
0x05 PUNCH_START  撮合结果: peer candidates(公网/内网/端口猜测)
0x06 PUNCH_PING   打洞探测包 (UDP, 不经隧道)
0x07 EXIT_ADV     出口能力声明: {allow: all|list|none, subnets: [...]}
0x08 RELAY_OPEN   请求中继转发 (打洞失败兜底)
0x09 INGRESS_PUB  端口发布请求/应答 (node ↔ 公网入口节点)
0x10 INGRESS_DEL  撤销端口发布
```

## 4. 节点目录同步（全网可见的基础）

- **coordinator** 维护权威节点目录：node_id、id_pub、虚拟 IP、endpoints、出口能力、在线状态、last_seen
- 节点上线 → 连 coordinator → 拉全量 → 订阅增量推送
- 节点间定期交换目录摘要（DIR_GOSSIP），coordinator 挂了网络仍能自愈
- 延迟测量：节点间 PING/PONG，上报并广播，供 Web UI 展示和 `exit=auto` 选路

## 5. 出口策略（核心体验）

```toml
# node.toml 示意
[network]
secret_file = "network.key"
coordinators = ["vps1.example.com:9000"]

[exit]
allow = "all"            # 我是否允许别人用我当出口: all | [node_ids] | none

[[route]]
match = "geoip:cn"
exit = "direct"
[[route]]
match = "cidr:192.168.0.0/16"
exit = "nas-home"        # 内网穿透: 从家里 NAS 出
[[route]]
match = "domain-suffix:google.com"
exit = "vps-tokyo"
[route-default]
exit = "auto"            # 按延迟自动选
```

## 5A. 入口发布（公网反代组网服务，内网穿透）

exit 的镜像方向：有公网 IP 的节点把**自己的公网端口**映射到**组网内任意节点**的本地服务。

```
公网用户 → 入口节点公网IP:8080 → mesh 隧道 → nas-home:80
公网用户 → 入口节点公网IP:6022 → mesh 隧道 → laptop:22
```

- 数据面与 exit 完全复用：公网连接到达入口节点 → 入口节点向目标节点建立隧道流，SYN 指定目标节点的本地地址 → 双向转发。入口节点只做转发，服务内容由目标节点终结
- 发布方式：
  - **静态**：入口节点配置里写死映射
  - **动态**：节点经 INGRESS_PUB 控制消息申请（"把你在 8080 的端口指到我这台机器的 80"），入口节点按 ACL 审批
- ACL：入口节点配置 `ingress_allow = { node_ids: [...], port_range: "8000-9000" }`，防止组网内节点乱占公网端口
- 可选增强（P5+）：按 TLS SNI / HTTP Host 分流，一个 443 端口托管多个节点的多个站点；TCP/UDP 均支持

```toml
# 入口节点 (有公网IP) 配置示意
[[ingress]]
listen = "0.0.0.0:8080"
to = { node = "nas-home", addr = "127.0.0.1:80" }

[[ingress]]
listen = "0.0.0.0:6022"
to = { node = "laptop", addr = "127.0.0.1:22" }

[ingress-acl]
allow_nodes = ["nas-home", "laptop"]
port_range = "8000-9000"
```

## 6. Web UI（每节点本地控制台）

- 每节点 `--web 127.0.0.1:9800`，axum + 内嵌静态页，仅监听本地
- API：
  - `GET  /api/status`        本节点信息/在线 peers 数/当前出口
  - `GET  /api/nodes`         全网节点目录（在线状态/延迟/出口能力）
  - `POST /api/exit`          设置默认出口 {exit: node_id | "direct" | "auto"}
  - `GET/POST /api/routes`    分流规则增删改
  - `GET  /api/ingress`       本节点发布的/可用的公网入口映射
  - `POST /api/ingress`       申请/撤销端口发布
  - `GET  /api/events` (WS)   实时事件：节点上下线、打洞结果、延迟更新
- 页面：节点拓扑卡片（在线/延迟/角色）、出口下拉选择、入口发布管理、规则表、实时日志条

## 7. 隐匿层（P5）

| 模式 | 外观 | 用途 |
|---|---|---|
| 噪声模式（默认） | 全流随机噪声，无结构无指纹 | 一般环境 |
| 模仿模式 | 套 HTTP/2 / WSS 帧皮，挂真实域名，可过 CDN | 严格环境/UDP被QoS |

- 长度混淆：随机 padding，包长分布可配置（模仿视频流）
- 时序整形：burst 聚合 + 随机微延迟
- fallback：未通过握手的连接转发到本机真实站点，探测者看到正常网站

## 8. NAT 打洞（yz-nat，P2）

1. 节点经隧道向 coordinator 报备（自研 STUN-like 拿公网映射，判断 NAT 类型）
2. coordinator 撮合：交换双方 candidates（公网/内网/端口增量预测范围）
3. UDP simultaneous open 同步发包
4. 对称 NAT 兜底：端口预测 + birthday 多端口散射
5. 全失败 → RELAY_OPEN 走 coordinator 中继（仍是端到端加密）

打洞成功后，同一套握手+会话直接跑在 P2P UDP 上（传输层换成 udp-reliable）。

## 9. 目录结构

```
yingzi/
├── docs/plan.md           # 本文档
├── crates/
│   ├── yz-proto/          # 帧编解码 (§3.4)            [P0 ✔]
│   ├── yz-crypto/         # NS/身份/握手/会话 (§3.1-3.3) [P0 ✔]
│   ├── yz-node/           # 节点二进制 (dial/serve)      [P0 ✔]
│   ├── yz-transport/      # 传输抽象 + tcp/wss/udp       [P2]
│   ├── yz-nat/            # 打洞                          [P2]
│   ├── yz-mesh/           # 目录同步/路由/虚拟IP          [P1/P6]
│   ├── yz-policy/         # 出口策略 + 入口发布 + ACL           [P3]
│   └── yz-web/            # Web UI                      [P4]
└── (legacy) src/ yingzi+benti  旧玩具, 仅供对照, 不再演进
```

## 10. 路线图

| 阶段 | 内容 | 验收 |
|---|---|---|
| **P0** 协议地基 ✔ | yz-proto + yz-crypto + yz-node(dial/serve, TCP承载, 单流) | 两节点加密转发 TCP |
| **P1** 组网骨架 ✔ | node 统一角色 + coordinator + 目录同步(HELLO/DIR_SYNC) + 一隧道多流复用 | 多节点互相可见, 并发流复用 |
| **P2** UDP+打洞 | 传输抽象、udp-reliable(ARQ/SACK/FEC)、yz-nat | NAT 后两节点 P2P 直连 |
| **P3** 出口/入口体系 | exit 模块 + ingress 端口发布 + 策略路由 + ACL + SOCKS5 入口 | 任选节点出流量/公网反代组网服务 |
| **P4** Web UI | yz-web + 实时事件 + 出口切换 + 规则编辑 | 浏览器控制台可用 |
| **P5** 隐匿增强 | 噪声/模仿双模式、fallback、时序整形 | 抓包无结构可识别 |
| **P6** 全局组网 | TUN 接管 + 虚拟 IP + subnet 路由 | 设备互 ping 虚拟 IP |
| **P7** 强健化 | rekey、连接迁移、拥塞控制优化、管理 CLI | 长期真实环境运行 |

## 11. 安全假设

- NS 泄露 = 网络准入失效 → NS 不入库、仅文件保存、支持轮换（P7）
- Ed25519 身份签名节点目录，coordinator 被控也不能伪造节点
- 所有失败路径静默断开；日志默认不记录流量内容
