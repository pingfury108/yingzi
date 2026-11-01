// 演示数据 —— 取自真实部署（6 节点 / 5 条规则）
const NODES = [
  { id: 'overseas-hk', name: 'overseas-hk', region: '香港', ip: '149.129.41.181', rtt: 42, load: 0.22, tag: '出口', current: true },
  { id: 'vps-tokyo', name: 'vps-tokyo', region: '东京', ip: '47.109.61.89', rtt: 68, load: 0.35, tag: '协调器' },
  { id: 'laptop', name: 'laptop', region: '局域网', ip: '192.168.31.251', rtt: 3, load: 0.61, tag: '入口' },
  { id: 'rpi4ff', name: 'rpi4ff', region: '局域网', ip: '192.168.31.93', rtt: 5, load: 0.18, tag: '入口' },
  { id: 'fury', name: 'fury', region: '局域网', ip: '192.168.31.95', rtt: 7, load: 0.44, tag: '入口' },
];

const RULES = [
  { group: '拦截', match: 'geosite:category-ads-all', action: 'block', hits: 1284, on: true },
  { group: '直连', match: 'geosite:cn', action: 'direct', hits: 8642, on: true },
  { group: '直连', match: 'geoip:cn', action: 'direct', hits: 3120, on: true },
  { group: '直连', match: 'geoip:private', action: 'direct', hits: 96, on: true },
  { group: '代理', match: 'geosite:google', action: 'exit', hits: 512, on: true },
  { group: '代理', match: 'geosite:telegram', action: 'exit', hits: 208, on: false },
];

// 45 秒速率序列（KB/s）
const SERIES_DOWN = [820, 760, 910, 1180, 1020, 880, 1240, 1420, 1180, 960, 1120, 1380, 1520, 1340, 1180, 1240, 1460, 1680, 1520, 1380, 1280, 1420, 1620, 1780, 1540, 1380, 1260, 1420, 1580, 1720, 1480, 1320, 1240, 1380, 1520, 1680, 1540, 1420, 1280, 1180, 1320, 1460, 1580, 1420, 1240];
const SERIES_UP = [210, 180, 240, 320, 280, 220, 300, 360, 300, 240, 280, 340, 380, 330, 290, 300, 360, 420, 380, 340, 310, 350, 400, 440, 380, 340, 310, 350, 390, 420, 370, 330, 310, 340, 380, 420, 390, 350, 320, 300, 330, 370, 400, 360, 310];

const LOGS = [
  { t: '21:04:12', lvl: 'TCP', text: 'TCP 172.217.119.4:443 → exit overseas-hk' },
  { t: '21:04:12', lvl: 'OK', text: 'pipe 结束 up=21.2KB down=87.3KB' },
  { t: '21:04:11', lvl: 'DNS', text: 'www.google.com → 172.217.119.4 (exit, 38ms)' },
  { t: '21:04:10', lvl: 'TCP', text: 'TCP 110.43.0.168:80 → direct 命中 geoip:cn' },
  { t: '21:04:09', lvl: 'BLK', text: 'doubleclick.net → 0.0.0.0 命中 category-ads-all' },
  { t: '21:04:07', lvl: 'NET', text: '对端 overseas-hk 保活 42ms rtt=42 var=3' },
  { t: '21:04:05', lvl: 'DNS', text: 'api.telegram.org → 91.108.56.130 (exit, 61ms)' },
  { t: '21:04:03', lvl: 'TCP', text: 'TCP 91.108.56.130:443 → exit overseas-hk' },
  { t: '21:04:01', lvl: 'WARN', text: 'UDP 上游 223.5.5.5:53 重试 1/3' },
  { t: '21:03:58', lvl: 'OK', text: 'UDP 上游恢复 223.5.5.5:53' },
];

const EVENTS = [
  { t: '21:04', text: '出口已切换到 overseas-hk', tone: 'exit' },
  { t: '21:03', text: '网络从 Wi-Fi 切换到 5G，已自动重连', tone: 'warn' },
  { t: '21:01', text: '规则热更新 5 条', tone: 'ok' },
];

Object.assign(window, { NODES, RULES, SERIES_DOWN, SERIES_UP, LOGS, EVENTS });
