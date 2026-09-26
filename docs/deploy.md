# 部署手册

以真实环境为例：一台国内 VPS 当协调器，一台海外 VPS 当出口，家庭机器和 Mac 当入口/客户端。
**进程托管统一用 runpulse**（单二进制进程守护，支持 systemd/launchd，崩溃自动拉起 + 开机自启）。

## 0. 拓扑与端口

```
              ┌──────────────────────────┐
   海外 VPS    │ yz node (exit)           │  TCP/UDP 9100 对外开放
   (出口)      └──────────┬───────────────┘
                          │  P2P 打洞 / 直连 / 中继
   国内 VPS    ┌──────────┴───────────────┐
   (协调器)    │ yz coord  :9000 TCP      │  9000 TCP 对外
               │           :9000/9001 UDP │  9000+9001 UDP 对外
               └──────────┬───────────────┘
                          │
   家庭机器     ┌──────────┴───────────────┐
   (入口)      │ yz node + SOCKS5 :1080    │  不需要开任何端口
               └──────────────────────────┘
```

| 角色 | 必开端口 | 说明 |
|---|---|---|
| 协调器 | `9000/TCP` + `9000/UDP` + `9001/UDP` | UDP 两个口用于 NAT 探测（判断 cone/对称） |
| 出口 / ingress 入口节点 | `9100/TCP` + `9100/UDP` | 不开也能用（走中继），开了才 P2P/直连 |
| 普通客户端 | 无 | 靠打洞或中继 |

> 主机防火墙（iptables/nftables/ufw）通常无需改：只需要**云安全组**放行。Linux 上 `yz` 只监听上面这些端口。

## 1. 构建

```bash
# Linux（源码在远程构建机上构建，本手册用 rdev）
rdev sh <<'EOF'
export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
cargo build --release --target x86_64-unknown-linux-musl -p yz-node
EOF
cp target/x86_64-unknown-linux-musl/release/yz /tmp/yz-musl   # 静态, 零依赖

# macOS（本机直接编译）
cargo build --release -p yz-node     # → target/release/yz
```

**为什么要 musl**：静态链接、零 glibc 依赖，同一个二进制能在任意 x86_64 Linux（含 CentOS 7 老内核）上跑。
Linux↔macOS 不要交叉编译（macOS 目标需要 macOS SDK），各平台本机编即可。

## 2. runpulse（进程守护）

### Linux
```bash
scp runpulse-musl root@<host>:/usr/local/bin/runpulse
ssh root@<host> 'chmod +x /usr/local/bin/runpulse && runpulse service install'
```
写入 systemd 系统服务（`/etc/systemd/system/runpulse.service`），daemon 开机自启。

### macOS
```bash
# 在 Mac 上从源码编译 runpulse
cd ~/codes/runpulse && cargo build --release
cp target/release/runpulse ~/.local/bin/
runpulse service install        # 写入 ~/Library/LaunchAgents/cloud.runpulse.plist
```

### 开 Web 面板（可选）
`service install` 生成的单元**不带 `--api`**，面板默认不监听 8477。

- 临时：`runpulse daemon --api`（前台）
- 长期：把 `--api` 加进单元文件参数，再重载

```bash
# macOS: 编辑 ~/Library/LaunchAgents/cloud.runpulse.plist, 在 daemon 后加 <string>--api</string>
launchctl bootout gui/$(id -u)/cloud.runpulse; launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/cloud.runpulse.plist

# Linux: systemctl edit runpulse → ExecStart 末尾加 --api, 然后 daemon-reload + restart
```

访问：`http://127.0.0.1:8477/`，右上角填 `runpulse status` 里的 token。**只监听 127.0.0.1，不要放公网**（明文 HTTP + token）。远程看就开 SSH 隧道：`ssh -L 8477:127.0.0.1:8477 root@<host>`。

## 3. 部署各角色

```bash
# 通用准备
mkdir -p /opt/yz && chmod 700 /opt/yz
scp yz root@<host>:/opt/yz/yz && ssh root@<host> 'chmod +x /opt/yz/yz'
```

### 3.1 网络密钥（只做一次）

任一节点上：
```bash
ssh root@<vps> '/opt/yz/yz keygen --id-file /opt/yz/node.key'
# 输出 network_secret = <64位hex>  ← 全网共用
```
把密钥存成环境变量放入 runpulse 的 `--env`（不要写进命令行，会进 `ps`）。
`gen.out` 里也有一份，建议 `chmod 600`。

### 3.2 协调器

```bash
runpulse start /opt/yz/yz --name yz-coord --cwd /opt/yz \
  --env RUST_LOG=info --env YZ_NETWORK_SECRET=<hex> \
  -- --id-file /opt/yz/coord.key coord --bind 0.0.0.0:9000
```
可选 `--fallback 127.0.0.1:443`：握手失败的连接转给本机真实站点，探测者看到正常网站。

### 3.3 出口节点（海外 VPS）

```bash
runpulse start /opt/yz/yz --name yz-exit --cwd /opt/yz \
  --env RUST_LOG=info --env YZ_NETWORK_SECRET=<hex> \
  -- --id-file /opt/yz/node.key node \
     --bind 0.0.0.0:9100 \
     --advertise <本机公网IP>:9100 --udp-advertise <本机公网IP>:9100 \
     --coordinator <协调器IP>:9000 --name overseas \
     --exit-allow all \
     --web 0.0.0.0:9800 --web-token <令牌> --config /opt/yz/node.json
```
- `--advertise` / `--udp-advertise`：云主机上探测是被 NAT 回环误导的（探测到的是内网地址），**必须手填公网 IP**，否则别的节点连不上/打洞不通
- `--exit-allow all`：允许其他节点用我当出口；也可写 `node_id` 列表（支持前缀）

### 3.4 客户端 / 入口节点（家庭机器、Mac）

```bash
# Linux
runpulse start ~/.local/yz/yz --name yz-laptop --cwd ~/.local/yz \
  --env RUST_LOG=info --env YZ_NETWORK_SECRET=<hex> \
  -- --id-file ~/.local/yz/node.key node \
     --bind 0.0.0.0:9100 --advertise <局域网IP>:9100 \
     --coordinator <协调器IP>:9000 --name laptop \
     --socks5 127.0.0.1:1080 --default-exit overseas \
     --web 0.0.0.0:9800 --config ~/.local/yz/node.json

# macOS 同上; 若要虚拟 IP 组网需 root(见 §5), 否则加 --no-tun
```

### 3.5 把服务发布到公网（内网穿透）

在有公网 IP 的节点上：
```bash
# 静态: 公网 8080 → 组网内 nas 的 127.0.0.1:80
--ingress "0.0.0.0:8080=nas/127.0.0.1:80"
# 动态: 允许别人申请发布, 限端口范围
--ingress-allow all --ingress-ports 8000-8999
```
然后在 Web 控制台「入口发布」里选目标节点 + 端口 + 服务地址申请即可。
注意：**被访问的那台节点也要放行**（`--exit-allow` 里包含入口节点）——反向流复用的是同一套隧道。

## 4. 验证

```bash
# 1) 节点是否入网
ssh <host> 'runpulse logs yz-node -n 5 | grep directory'
#   → directory: N nodes: ...

# 2) 翻墙出口
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me        # 应为出口节点公网 IP
curl -x socks5h://127.0.0.1:1080 -o /dev/null -w '%{http_code}\n' https://www.google.com/generate_204

# 3) UDP（HTTP/3、DNS 等）— 走 SOCKS5 UDP ASSOCIATE
python3 scripts/udp_associate_test.py 8.8.8.8 53             # 期望 PASS

# 4) 虚拟 IP 互通
ping -c3 <对端 vIP>      # 100.64.x.x，Web 控制台的节点卡片上有

# 5) 走的哪条路（P2P / 直连 / 中继）
ssh <host> 'runpulse logs yz-node | grep -E "p2p punched|relayed|tcp direct"'
```

## 5. TUN 虚拟组网（虚拟 IP）

默认开启（Linux `yz0` / macOS `utun5`），需要权限：

- **Linux root 部署**：直接可用
- **Linux 非 root**（runpulse 用户模式）：一次性授权
  ```bash
  sudo setcap cap_net_admin,cap_net_raw+ep ~/.local/yz/yz
  ```
  ⚠️ **每次用 mv/scp 替换二进制后 capability 会丢，必须重跑**（所以部署脚本里要带上这步）
- **macOS**：utun 只能 root 创建 → 需要 root 运行节点（或先 `--no-tun`，只当代理用）
  ```bash
  sudo runpulse service install     # root 模式: /var/lib/runpulse + launchd 守护
  ```

无权限时优雅降级：只打一条 warn，SOCKS5/出口/ingress 功能不受影响。

## 6. 运维速查

```bash
runpulse list                     # 各进程状态
runpulse logs yz-node -n 50       # 看日志
runpulse restart yz-node          # 重启
runpulse info yz-node             # 完整启动参数
runpulse list --json              # AI/脚本友好
```

配置持久化：Web 控制台改的「默认出口 / 分流规则」会写进 `--config` 指定的 JSON，重启自动加载（**文件优先于命令行初值**）。改完想回退就删掉该文件。

## 7. 排障

| 症状 | 原因 / 处理 |
|---|---|
| 日志反复 `bind … Address in use` 后退出 | 有**游离的旧进程**占着端口（通常是 `remove`+`start` 快速交替导致）。判断：`ps -eo pid,ppid,args \| grep yz`，**PPID=1 且不在 `runpulse list` 里**的就是游离进程，杀掉后重启。新版本自带绑定重试，一般能自愈 |
| `nat probe failed, p2p disabled` | 协调器的 UDP 9000/9001 没通（安全组）。仍是中继可用 |
| 打洞一直失败 | 一边是对称 NAT，或对方 `9100/UDP` 被封。看日志 `nat: symmetric/cone`；可先接受走中继 |
| 云主机上 `udp_addr` 是内网地址 | 探测被云 NAT 回环误导 → 加 `--udp-advertise <公网IP>:9100` |
| 出口选了但没流量 / 全 timeout | 确认出口节点 `--exit-allow` 放行了你；节点目录里能看到对方（`directory: N nodes`） |
| 换了二进制后 TUN 失效 | Linux 上 capability 被清 → 重跑 `setcap`（见 §5） |
| 节点崩了会不会掉 | runpulse 自动拉起；daemon 自己也重启也无损（会 adopt 存活子进程） |

排障小抄（我踩过的坑）：
- `pkill -f '<pattern>'` 会**匹配到自己的 ssh 命令行**从而杀掉会话；用 `pkill -x yz` 或按 `/proc/<pid>/exe` 精确匹配
- 二进制被 `mv` 替换后，`/proc/<pid>/exe` 会带 `" (deleted)"` 后缀，脚本比对路径要 `replace(' (deleted)','')`
- 改完协议/二进制后**协调器和所有节点都要重启**（协议版本不一致会导致注册失败、目录为空、静默退化成 direct）
