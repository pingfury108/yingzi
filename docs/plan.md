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
  - **静态**：入口节点配置里写死映射 ✔ (`--ingress "listen=node/addr"`)
  - **动态**：节点经 INGRESS_PUB 控制消息申请（"把你在 8080 的端口指到我这台机器的 80"），入口节点按 ACL 审批 ✔ (Web UI `/api/ingress`)
- ACL：入口节点配置 `--ingress-allow` + `--ingress-ports` 端口范围；**注意**：作为 ingress 目标的节点也需 `--exit-allow` 放行入口节点（反向流复用 exit 数据面）
- 动态映射随隧道生命周期：隧道断开自动回收监听端口，重连后需重新申请
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
- 现状：P4 已实现 status/nodes/exit/routes API + 单页控制台(2s 轮询); WS 实时推送、延迟展示、入口发布管理待后续

## 7. 隐匿层（P5，进行中）

| 模式 | 外观 | 用途 |
|---|---|---|
| 噪声模式（默认）✔ | 全流随机噪声，无结构无指纹 | 一般环境 |
| 模仿模式（待做） | 套 HTTP/2 / WSS 帧皮，挂真实域名，可过 CDN | 严格环境/UDP被QoS |

已实现（P5a）：
- **握手尺寸随机化**：`rand_pad || core`，TCP 侧加 NS 掩码长度——消除 116/124 固定长度指纹
- **UDP 尺寸桶填充**：加密层内填充到 {64,160,320,640,1024,1380}+抖动，ACK/小包无尺寸特征
- **fallback 站点**：TCP 握手失败的连接原样转发到真实站点（`--fallback host:port`），主动探测者看到正常 HTTP 服务
- 未认证连接静默丢弃；无任何错误回显

待做（P5b）：WSS 模仿模式（TLS+真实证书+CDN）、时序整形（burst 聚合+微延迟）、连接轮换

## 8. NAT 打洞（yz-rudp Endpoint，P2b ✔）

1. 节点 UDP 端点与 TCP 同端口绑定；经 coordinator 的 UDP P / P+1 双端口探测公网映射，判定 cone/对称 NAT
2. HELLO 携带 udp_addr 入目录；`tunnel_for` 优先 P2P：PunchReq → coordinator 互发 PunchStart(candidates)
3. 双方散射 NS 认证的 PUNCH 包（对称 NAT 绕观察端口 ±64 采样 32 端口）
4. 打通后同一 UDP 端点上跑 YZP 握手 → Rudp 可靠流隧道；失败回退 TCP 直连
5. 中继（TURN-like）未实现，列入 P7

## 9. 目录结构

```
yingzi/
├── docs/plan.md           # 本文档
├── crates/
│   ├── yz-proto/          # 帧编解码 (§3.4)            [P0 ✔]
│   ├── yz-crypto/         # NS/身份/握手/会话 (§3.1-3.3) [P0 ✔]
│   ├── yz-node/           # 节点二进制 (tunnel/coord/policy/socks5/ingress/web/mesh) │
│   └── yz-rudp/           # UDP 可靠传输 + 探测/打洞 (P2 ✔)               │
└── (legacy) src/ yingzi+benti  旧玩具, 仅供对照, 不再演进
```

## 10. 路线图

| 阶段 | 内容 | 验收 |
|---|---|---|
| **P0** 协议地基 ✔ | yz-proto + yz-crypto + yz-node(dial/serve, TCP承载, 单流) | 两节点加密转发 TCP |
| **P1** 组网骨架 ✔ | node 统一角色 + coordinator + 目录同步(HELLO/DIR_SYNC) + 一隧道多流复用 | 多节点互相可见, 并发流复用 |
| **P2a** UDP 可靠传输 ✔ | yz-rudp(加密元数据/SACK/快速重传/AIMD) + 隧道双承载(TCP/UDP) + serve/dial --udp | 20MB 经 UDP 隧道 MD5 一致 |
| **P2b** NAT 打洞 ✔ | probe(双端口判定 cone/对称) + PUNCH_REQ/START 撮合 + 散射 + P2P UDP 直连, TCP 兜底 | 节点间无 TCP 连接的纯 UDP 代理成功 |
| **P3** 出口/入口体系 ✔ | exit + 策略路由 + ACL + SOCKS5 入口 + ingress 静态/动态端口发布 | 任选节点出流量/公网反代组网服务 |
| **P4** Web UI ✔(轮询版) | yz-web: status/nodes/exit/routes API + 内嵌单页控制台 | 浏览器可看全网节点、切换出口、增删规则 |
| **P5a** 噪声强化 ✔ | 握手尺寸随机化 + UDP 尺寸桶填充 + fallback 伪装站点 | 探针看到真实 HTTP 服务 |
| **P5b** WSS 模仿 ✔ | 真实 TLS + RFC6455 承载 YZP, 可挂 CDN | TLS 观察者看到真实证书, 隧道 200 |
| **P6** 全局组网 ✔ | TUN + 确定性虚拟IP(100.64.0.0/10 | node_id低22位) + Mesh帧路由(自动P2P) | 设备互 ping 虚拟 IP (需root, 降级已验证) |
| **P7** 强健化(进行中) | 中继兜底 ✔(嵌套YZP隧道, coordinator零明文) | 对称NAT/直连失败仍可达 |
| P7 剩余 | rekey、RTT 测量驱动的 RTO/拥塞、ingress ack 关联、多 coordinator | 长期真实环境运行 |

## 11. 安全假设

- NS 泄露 = 网络准入失效 → NS 不入库、仅文件保存、支持轮换（P7）
- Ed25519 身份签名节点目录，coordinator 被控也不能伪造节点
- 所有失败路径静默断开；日志默认不记录流量内容
