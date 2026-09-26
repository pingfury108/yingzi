# yingzi (yz)

自研对等组网 + 流量隐匿 + 出口选择 + Web 控制台。一个二进制管全部：组网、翻墙出口、内网穿透、虚拟 IP。

- 协议自研（握手/加密包/多路复用/可靠 UDP/打洞），无 QUIC/TLS/WireGuard 等已知指纹
- 密码学原语用 `ring`（X25519 / Ed25519 / ChaCha20-Poly1305 / HKDF）
- 设计文档：**[docs/plan.md](docs/plan.md)** ｜ 部署手册：**[docs/deploy.md](docs/deploy.md)**

## 它能做什么

| 场景 | 怎么用 |
|---|---|
| 翻墙 | 本机 SOCKS5 入口 → 组网隧道 → 海外节点出口 → 公网 |
| 任选出口 | Web 控制台里挑一台节点当出口（`auto` 按实测 RTT 选最快） |
| 设备互访 | 每台设备有确定性虚拟 IP（`100.64.0.0/14`），直接 ping/ssh |
| 内网穿透 | 有公网 IP 的节点发布端口 → 转发到组网内任意设备的服务 |
| 分流 | 按域名/网段选出口，规则可在 Web 控制台增删（持久化） |

节点间优先 **P2P 打洞**（UDP），失败退 **TCP 直连**，再失败走 **协调器中继**（嵌套隧道，协调器看不到明文）。

## 快速开始

```bash
# 0) 构建（本机）
cargo build --release -p yz-node        # 产物 target/release/yz

# 1) 第一个节点生成网络密钥（全网共用，只做一次）
yz keygen --id-file /opt/yz/node.key
#   → network_secret = <64位hex>   ← 记下来，后面所有节点都用它

# 2) 有公网 IP 的机器当协调器
YZ_NETWORK_SECRET=<hex> yz --id-file /opt/yz/coord.key coord --bind 0.0.0.0:9000

# 3) 出口节点（海外 VPS）
YZ_NETWORK_SECRET=<hex> yz --id-file /opt/yz/node.key node \
  --bind 0.0.0.0:9100 --advertise <公网IP>:9100 --udp-advertise <公网IP>:9100 \
  --coordinator <协调器IP>:9000 --name overseas \
  --exit-allow all \
  --web 0.0.0.0:9800 --web-token <令牌> --config /opt/yz/node.json

# 4) 自己的电脑（入口，不需要公网 IP）
YZ_NETWORK_SECRET=<hex> yz --id-file ~/.yz/node.key node \
  --bind 0.0.0.0:9100 --coordinator <协调器IP>:9000 --name laptop \
  --socks5 127.0.0.1:1080 --default-exit overseas \
  --web 127.0.0.1:9800 --config ~/.yz/node.json

# 5) 用起来
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me   # 出口 IP 应为海外节点
```

Web 控制台：`http://127.0.0.1:9800`（拓扑/延迟/出口切换/分流规则/入口发布/流量统计）。
挂了公网就给 `--web-token`，并能用 SSH 隧道安全访问。

## 端口

| 角色 | 端口 | 协议 | 用途 |
|---|---|---|---|
| 协调器 | 9000 | TCP | 注册 / 目录同步 / 打洞撮合 / 中继 |
| 协调器 | 9000 + 9001 | UDP | NAT 探测（双端口判对称 NAT） |
| 想被直连或打洞的节点 | 9100 | TCP + UDP | 节点间直连隧道 / P2P 打洞 |
| 入口发布节点 | 自定义 | TCP | 对外发布的公网端口 |
| 本机 SOCKS5 / Web UI | 1080 / 9800 | TCP | **只监听本机，勿对外** |

NAT 后的普通节点**不需要开任何端口**（靠打洞/中继）。详细说明见 [docs/deploy.md](docs/deploy.md)。

## 命令行

```
yz keygen                生成网络密钥 + 节点身份
yz coord                 协调器（注册表/目录广播/撮合/中继）
yz node                  对等节点（组网 + 可选 SOCKS5 入口 + Web UI + TUN）
yz serve                 独立隧道出口（无 mesh；支持 --udp / --wss-cert）
yz dial                  本地入口 → 远端 serve（支持 --udp / --wss-sni）
```

`yz node` 常用参数：

```
--coordinator <addr>      协调器地址，可多次（多实例容错，按序轮换）
--name <名>               节点名（分流规则/出口可用名字引用）
--socks5 127.0.0.1:1080   本地 SOCKS5 入口（支持 CONNECT + UDP ASSOCIATE）
--exit-allow all|none|ids 谁可以用我当出口
--default-exit auto|<名>  默认出口；auto = 按实测 RTT 选最快
--route "domain-suffix:google.com=海外"   分流规则，可多次
--ingress "0.0.0.0:8080=nas/127.0.0.1:80" 静态端口发布
--ingress-allow all|none|ids --ingress-ports 8000-9999   动态发布 ACL
--web 0.0.0.0:9800 --web-token <令牌>      Web 控制台
--config node.json        Web 控制台改的出口/规则落盘，重启自动加载
--fallback 127.0.0.1:443  握手失败的连接转发到真实站点（抗主动探测，伪装成正常网站）
--tun utun5 / --no-tun    虚拟组网网卡（默认开；Linux yz0 / macOS utun5）
```

环境变量：`YZ_NETWORK_SECRET`（等价 `--network-secret`）、`YZ_NO_P2P=1`（强制关闭 P2P，调试用）、`YZ_REKEY_SECS`（密钥轮换，**实验性，默认关闭**，见 plan §13）。

## 工作区

```
crates/yz-proto/   帧 + 控制消息编解码
crates/yz-crypto/  网络密钥 / 身份 / 握手 / 会话 / rekey
crates/yz-rudp/    UDP 可靠传输 + NAT 探测 + 打洞
crates/yz-node/    唯一二进制 yz（tunnel/coord/node/policy/socks5/ingress/mesh/web/wss）
docs/plan.md       总体设计（协议字节级定义、路线图、决策记录）
docs/deploy.md     部署手册（三台真实机器为例）
scripts/           验证脚本（如 SOCKS5 UDP ASSOCIATE 端到端测试）
```

## 平台与构建

| 平台 | 产物 | 说明 |
|---|---|---|
| Linux x86_64 | `--target x86_64-unknown-linux-musl` | 静态、零依赖，任意发行版可跑 |
| Linux aarch64（树莓派） | `--target aarch64-unknown-linux-musl` | 需 C 交叉工具链（musl.cc 预编译包），见 deploy.md |
| macOS | 本机 `cargo build --release` | utun 需 root；无权限时 `--no-tun` 只当代理用 |

## 状态

已在真实环境跑通：3+ 节点组网（国内 VPS 协调器 + 海外出口 + 家庭机器 + macOS），P2P 打洞、任选出口翻墙、虚拟 IP 互 ping、SOCKS5（TCP+UDP）、Web 控制台、ingress 发布。

已知限制见 [docs/plan.md](docs/plan.md) §12/§13：不做子网路由（只做 agent 间互联）、单跳 mesh、rekey 默认关闭、Windows 待做。
