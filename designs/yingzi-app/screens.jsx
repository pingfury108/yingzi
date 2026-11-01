// ---------- 共用部件 ----------
function TopBar({ title, right, onBack }) {
  return (
    <div className="topbar">
      <div className="row" style={{ gap: 10 }}>
        {onBack
          ? <button className="iconbtn" onClick={onBack}><Icon name="back" size={18} /></button>
          : <Mark size={20} />}
        <span className="title">{title}</span>
      </div>
      <div className="actions">{right}</div>
    </div>
  );
}

function NavBar({ tab, onTab }) {
  const items = [
    { id: 'main', label: '状态', icon: 'bolt' },
    { id: 'exit', label: '节点', icon: 'globe' },
    { id: 'rules', label: '规则', icon: 'rules' },
    { id: 'log', label: '日志', icon: 'log' },
  ];
  return (
    <div className="navbar">
      {items.map(it => (
        <button key={it.id} className="navitem" data-on={tab === it.id ? 1 : 0} onClick={() => onTab(it.id)}>
          <Icon name={it.icon} size={20} sw={tab === it.id ? 1.9 : 1.6} />
          <span>{it.label}</span>
        </button>
      ))}
    </div>
  );
}

function StatePill({ connected }) {
  return (
    <span className="pill" style={{
      color: connected ? 'var(--accent)' : 'var(--text-3)',
      borderColor: connected ? 'var(--accent-line)' : 'var(--line)',
      background: connected ? 'var(--accent-soft)' : 'transparent',
    }}>
      <span className="dot" style={{
        background: connected ? 'var(--accent)' : 'var(--text-3)',
        boxShadow: connected ? '0 0 8px var(--accent)' : 'none',
      }} />
      {connected ? '已连接' : '未连接'}
    </span>
  );
}

function PowerButton({ connected, onClick, size = 62 }) {
  return (
    <button onClick={onClick} style={{
      width: size, height: size, borderRadius: 99, border: 0, cursor: 'pointer',
      display: 'grid', placeItems: 'center', flex: 'none',
      background: connected ? 'var(--accent)' : 'rgba(255,255,255,.06)',
      color: connected ? '#04120F' : 'var(--text-2)',
      boxShadow: connected
        ? '0 0 0 1px rgba(56,240,198,.6), 0 0 30px -4px rgba(56,240,198,.6)'
        : 'inset 0 0 0 1px var(--line-2)',
      transition: '.2s',
    }}>
      <Icon name="power" size={size * 0.4} sw={2} />
    </button>
  );
}

function StatCell({ label, value, unit, color }) {
  return (
    <div style={{ flex: 1, textAlign: 'left' }}>
      <div className="micro">{label}</div>
      <div className="row" style={{ gap: 3, marginTop: 7, alignItems: 'baseline' }}>
        <span className="num" style={{ font: '500 17px/1 var(--mono)', color: color || 'var(--text)' }}>{value}</span>
        {unit && <span className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)' }}>{unit}</span>}
      </div>
    </div>
  );
}

// ---------- 主界面 V1 · 单卡片 ----------
function MainV1({ connected, onToggle, onTab, onExit }) {
  return (
    <>
      <TopBar title="yingzi" right={
        <>
          <StatePill connected={connected} />
          <button className="iconbtn" onClick={() => onTab('settings')}><Icon name="settings" size={18} /></button>
        </>
      } />
      <div className="scroll">
        <div className="pad" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

          <div className="card" style={{ padding: 18 }}>
            <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div className="micro">{connected ? '隧道已建立' : '隧道未建立'}</div>
                <div style={{ font: '500 26px/1.2 var(--sans)', marginTop: 8, letterSpacing: '.01em' }}>
                  {connected ? '运行中' : '已停止'}
                </div>
                <div className="num" style={{ font: '400 11px/1 var(--mono)', color: 'var(--text-3)', marginTop: 8 }}>
                  overseas-hk · 149.129.41.181
                </div>
              </div>
              <PowerButton connected={connected} onClick={onToggle} />
            </div>

            <div className="divider" style={{ margin: '18px 0 14px' }} />

            <div className="row" style={{ gap: 8 }}>
              <StatCell label="延迟" value="42" unit="ms" color="var(--accent)" />
              <StatCell label="运行" value="02:14:33" />
              <StatCell label="对端" value="5" unit="节点" />
            </div>

            <div style={{ margin: '16px -4px 0' }}>
              <Spark series={SERIES_DOWN} h={58} id="v1" />
            </div>

            <div className="row" style={{ justifyContent: 'space-between', marginTop: 6 }}>
              <div className="row" style={{ gap: 7 }}>
                <Icon name="down" size={14} color="var(--accent)" />
                <span className="num" style={{ font: '500 13px/1 var(--mono)' }}>1.24</span>
                <span className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)' }}>MB/s</span>
              </div>
              <div className="row" style={{ gap: 7 }}>
                <Icon name="up" size={14} color="var(--exit)" />
                <span className="num" style={{ font: '500 13px/1 var(--mono)' }}>236</span>
                <span className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)' }}>KB/s</span>
              </div>
            </div>
          </div>

          {/* 分流计数 */}
          <div className="row" style={{ gap: 8 }}>
            {[
              { k: '直连', v: 36, c: 'var(--direct)' },
              { k: '代理', v: 3, c: 'var(--exit)' },
              { k: '拦截', v: 12, c: 'var(--block)' },
            ].map(x => (
              <div key={x.k} className="card inset" style={{ flex: 1, padding: '11px 12px' }}>
                <div className="row" style={{ gap: 6 }}>
                  <span className="dot" style={{ background: x.c }} />
                  <span className="micro" style={{ letterSpacing: '.1em' }}>{x.k}</span>
                </div>
                <div className="num" style={{ font: '500 19px/1 var(--mono)', marginTop: 8 }}>{x.v}</div>
              </div>
            ))}
          </div>

          <div className="section-label">
            <span className="micro">当前出口</span>
            <span className="line" />
          </div>

          <div className="card" style={{ cursor: 'pointer' }} onClick={() => onTab('exit')}>
            <div className="listrow">
              <div style={{
                width: 38, height: 38, borderRadius: 12, display: 'grid', placeItems: 'center',
                background: 'rgba(95,168,255,.10)', border: '1px solid rgba(95,168,255,.25)',
              }}>
                <Icon name="globe" size={19} color="var(--exit)" />
              </div>
              <div className="grow">
                <div className="label">overseas-hk</div>
                <div className="sub">香港 · 149.129.41.181</div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div className="num" style={{ font: '500 13px/1 var(--mono)', color: 'var(--accent)' }}>42ms</div>
                <div className="micro" style={{ marginTop: 4 }}>切换</div>
              </div>
              <Icon name="chevron" size={16} color="var(--text-3)" />
            </div>
          </div>

          <div className="section-label">
            <span className="micro">最近事件</span>
            <span className="line" />
          </div>

          <div className="card" style={{ padding: '4px 16px' }}>
            {EVENTS.map((e, i) => (
              <div key={i} className="row" style={{
                gap: 12, padding: '11px 0',
                borderTop: i ? '1px solid rgba(255,255,255,.05)' : 'none',
              }}>
                <span className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)' }}>{e.t}</span>
                <span style={{ font: '400 12px/1.4 var(--sans)', color: 'var(--text-2)' }}>{e.text}</span>
              </div>
            ))}
          </div>

          <div style={{ height: 14 }} />
        </div>
      </div>
      <NavBar tab="main" onTab={onTab} />
    </>
  );
}

// ---------- 主界面 V2 · 环形仪表 ----------
function MainV2({ connected, onToggle, onTab }) {
  const down = 1240;
  return (
    <>
      <TopBar title="yingzi" right={
        <>
          <StatePill connected={connected} />
          <button className="iconbtn" onClick={() => onTab('settings')}><Icon name="settings" size={18} /></button>
        </>
      } />
      <div className="scroll">
        <div className="pad" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          <div style={{ display: 'grid', placeItems: 'center', paddingTop: 6 }}>
            <Ring value={connected ? 0.62 : 0} label="下行速率" sub={connected ? '1.24' : '0.00'} />
            <div className="row" style={{ gap: 8, marginTop: -6 }}>
              <span className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)' }}>MB/s</span>
              <span className="dot" style={{ background: connected ? 'var(--accent)' : 'var(--text-3)' }} />
              <span style={{ font: '400 11px/1 var(--sans)', color: 'var(--text-2)' }}>
                {connected ? 'overseas-hk · 42ms' : '未连接'}
              </span>
            </div>
          </div>

          <div className="row" style={{ gap: 8 }}>
            <StatCell label="上行" value="236" unit="KB/s" color="var(--exit)" />
            <StatCell label="对端" value="5" unit="节点" />
            <StatCell label="运行" value="02:14:33" />
          </div>

          <button className="cta" data-off={connected ? 0 : 1} onClick={onToggle}>
            {connected ? '断开连接' : '建立连接'}
          </button>

          <div>
            <div className="section-label" style={{ marginTop: 6 }}>
              <span className="micro">出口</span>
              <span className="line" />
            </div>
            <div className="row" style={{ gap: 8, overflowX: 'auto', paddingBottom: 2 }}>
              {NODES.slice(0, 3).map((n, i) => (
                <div key={n.id} className="card" style={{
                  padding: '10px 13px', flex: 'none', cursor: 'pointer',
                  borderColor: i === 0 ? 'var(--accent-line)' : 'var(--line)',
                  background: i === 0 ? 'var(--accent-soft)' : undefined,
                }}>
                  <div className="row" style={{ gap: 7 }}>
                    <span className="dot" style={{ background: i === 0 ? 'var(--accent)' : 'var(--text-3)' }} />
                    <span style={{ font: '500 12px/1 var(--mono)', color: i === 0 ? 'var(--accent)' : 'var(--text-2)' }}>{n.name}</span>
                  </div>
                  <div className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)', marginTop: 6 }}>{n.rtt}ms · {n.region}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card" style={{ padding: 16 }}>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span className="micro">实时吞吐</span>
              <span className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)' }}>45s</span>
            </div>
            <div style={{ margin: '12px -4px 0' }}><Spark series={SERIES_DOWN} h={70} id="v2" /></div>
            <div className="divider" style={{ margin: '14px 0 12px' }} />
            <div className="row" style={{ gap: 8 }}>
              {[
                { k: '直连', v: 36, c: 'var(--direct)' },
                { k: '代理', v: 3, c: 'var(--exit)' },
                { k: '拦截', v: 12, c: 'var(--block)' },
              ].map(x => (
                <div key={x.k} className="row grow" style={{ gap: 7 }}>
                  <span className="dot" style={{ background: x.c }} />
                  <span className="num" style={{ font: '500 13px/1 var(--mono)' }}>{x.v}</span>
                  <span className="micro" style={{ letterSpacing: '.1em' }}>{x.k}</span>
                </div>
              ))}
            </div>
          </div>

          <div style={{ height: 10 }} />
        </div>
      </div>
      <NavBar tab="main" onTab={onTab} />
    </>
  );
}

// ---------- 主界面 V3 · 数据面板 ----------
function MainV3({ connected, onToggle, onTab }) {
  return (
    <>
      <TopBar title="面板" right={
        <>
          <StatePill connected={connected} />
          <button className="iconbtn" onClick={onToggle}>
            <Icon name={connected ? 'pause' : 'play'} size={16} />
          </button>
        </>
      } />
      <div className="scroll">
        <div className="pad" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

          <div className="card" style={{ padding: 16 }}>
            <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline' }}>
              <div>
                <div className="micro">下行 / 上行</div>
                <div className="row" style={{ gap: 10, marginTop: 8, alignItems: 'baseline' }}>
                  <span className="num" style={{ font: '500 22px/1 var(--mono)', color: 'var(--accent)' }}>1.24</span>
                  <span className="num" style={{ font: '400 12px/1 var(--mono)', color: 'var(--text-3)' }}>MB/s</span>
                  <span className="num" style={{ font: '500 13px/1 var(--mono)', color: 'var(--exit)' }}>↑236K</span>
                </div>
              </div>
              <span className="pill" style={{ color: 'var(--text-3)' }}>峰值 1.78</span>
            </div>
            <div style={{ margin: '14px -4px 0' }}><Spark series={SERIES_DOWN} h={86} id="v3" /></div>
            <div className="row" style={{ justifyContent: 'space-between', marginTop: 6 }}>
              <span className="num" style={{ font: '400 9px/1 var(--mono)', color: 'var(--text-3)' }}>-45s</span>
              <span className="num" style={{ font: '400 9px/1 var(--mono)', color: 'var(--text-3)' }}>-30s</span>
              <span className="num" style={{ font: '400 9px/1 var(--mono)', color: 'var(--text-3)' }}>-15s</span>
              <span className="num" style={{ font: '400 9px/1 var(--mono)', color: 'var(--text-3)' }}>now</span>
            </div>
          </div>

          <div className="card">
            <div className="row" style={{ padding: '12px 16px', justifyContent: 'space-between' }}>
              <span className="micro">对端节点</span>
              <span className="micro">{NODES.length}</span>
            </div>
            <div className="divider" />
            {NODES.slice(0, 4).map(n => (
              <div key={n.id} className="row" style={{ padding: '10px 16px', gap: 10, borderTop: '1px solid rgba(255,255,255,.04)' }}>
                <span className="dot" style={{ background: n.rtt < 20 ? 'var(--direct)' : n.current ? 'var(--accent)' : 'var(--text-3)' }} />
                <span style={{ font: '400 12px/1 var(--mono)', color: 'var(--text)', width: 96 }}>{n.name}</span>
                <span className="num" style={{ font: '400 11px/1 var(--mono)', color: 'var(--text-3)', flex: 1 }}>{n.ip}</span>
                <span className="num" style={{ font: '500 11px/1 var(--mono)', color: n.rtt < 20 ? 'var(--direct)' : 'var(--text-2)' }}>{n.rtt}ms</span>
              </div>
            ))}
          </div>

          <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span className="micro">规则命中</span>
              <span className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)' }}>24h</span>
            </div>
            <HitBar label="geosite:cn" pct={72} color="var(--direct)" />
            <HitBar label="geoip:cn" pct={18} color="var(--direct)" />
            <HitBar label="category-ads" pct={7} color="var(--block)" />
            <HitBar label="geosite:google" pct={3} color="var(--exit)" />
          </div>

          <div className="card" style={{ padding: '6px 16px 10px' }}>
            <div className="row" style={{ justifyContent: 'space-between', padding: '10px 0 4px' }}>
              <span className="micro">实时日志</span>
              <span className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--accent)' }}>LIVE</span>
            </div>
            {LOGS.slice(0, 3).map((l, i) => (
              <div key={i} className="logline" style={{ borderBottom: 'none' }}>
                <span className="t">{l.t}</span>
                <span className="lvl" style={{ color: lvlColor(l.lvl) }}>{l.lvl}</span>
                <span className="msg">{l.text}</span>
              </div>
            ))}
          </div>

          <div style={{ height: 10 }} />
        </div>
      </div>
      <NavBar tab="main" onTab={onTab} />
    </>
  );
}

function lvlColor(l) {
  return { TCP: 'var(--text-2)', DNS: 'var(--exit)', OK: 'var(--direct)', BLK: 'var(--block)', WARN: 'var(--warn)', NET: 'var(--accent)' }[l] || 'var(--text-3)';
}

// ---------- 出口节点 ----------
function ExitScreen({ onTab, exit, setExit }) {
  return (
    <>
      <TopBar title="出口节点" onBack={() => onTab('main')} right={
        <button className="iconbtn"><Icon name="search" size={17} /></button>
      } />
      <div className="scroll">
        <div className="pad" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div className="card" style={{
            padding: 14, display: 'flex', alignItems: 'center', gap: 12,
            borderColor: exit === 'auto' ? 'var(--accent-line)' : 'var(--line)',
            background: exit === 'auto' ? 'var(--accent-soft)' : undefined, cursor: 'pointer',
          }} onClick={() => setExit('auto')}>
            <div style={{ width: 36, height: 36, borderRadius: 11, display: 'grid', placeItems: 'center', background: 'rgba(255,255,255,.05)' }}>
              <Icon name="bolt" size={18} color={exit === 'auto' ? 'var(--accent)' : 'var(--text-2)'} />
            </div>
            <div className="grow">
              <div style={{ font: '500 13px/1 var(--sans)' }}>自动选择</div>
              <div className="sub" style={{ marginTop: 5 }}>按延迟与负载择优</div>
            </div>
            {exit === 'auto' && <Icon name="check" size={17} color="var(--accent)" />}
          </div>

          <div className="section-label">
            <span className="micro">可用节点</span>
            <span className="line" />
            <span className="micro">{NODES.length}</span>
          </div>

          <div className="card">
            {NODES.map((n, i) => {
              const on = exit === n.id;
              return (
                <div key={n.id} onClick={() => setExit(n.id)} style={{
                  display: 'flex', alignItems: 'center', gap: 12, padding: '13px 15px', cursor: 'pointer',
                  borderTop: i ? '1px solid rgba(255,255,255,.05)' : 'none',
                  background: on ? 'rgba(56,240,198,.045)' : undefined,
                }}>
                  <div style={{ width: 3, height: 30, borderRadius: 3, background: on ? 'var(--accent)' : 'transparent' }} />
                  <div className="grow">
                    <div className="row" style={{ gap: 7 }}>
                      <span style={{ font: '500 13px/1 var(--mono)' }}>{n.name}</span>
                      <span style={{
                        font: '500 9px/1 var(--mono)', letterSpacing: '.08em', color: 'var(--text-3)',
                        padding: '3px 5px', borderRadius: 4, background: 'rgba(255,255,255,.05)',
                      }}>{n.tag}</span>
                    </div>
                    <div className="sub" style={{ marginTop: 5 }}>{n.region} · {n.ip}</div>
                  </div>
                  <div style={{ textAlign: 'right', width: 62 }}>
                    <div className="num" style={{ font: '500 12px/1 var(--mono)', color: n.rtt < 20 ? 'var(--direct)' : 'var(--text-2)' }}>{n.rtt}ms</div>
                    <div style={{ height: 3, borderRadius: 3, background: 'rgba(255,255,255,.07)', marginTop: 7 }}>
                      <div style={{ width: `${n.load * 100}%`, height: '100%', borderRadius: 3, background: n.load > .5 ? 'var(--warn)' : 'var(--accent)' }} />
                    </div>
                  </div>
                  {on ? <Icon name="check" size={16} color="var(--accent)" /> : <span style={{ width: 16 }} />}
                </div>
              );
            })}
          </div>

          <div className="card inset" style={{ padding: 14, marginTop: 4 }}>
            <div className="micro">说明</div>
            <div style={{ font: '400 11px/1.7 var(--sans)', color: 'var(--text-3)', marginTop: 8 }}>
              出口决定被代理流量的落地 IP。国内域名与内网地址始终直连，不受此处影响。
            </div>
          </div>
          <div style={{ height: 12 }} />
        </div>
      </div>
      <NavBar tab="exit" onTab={onTab} />
    </>
  );
}

// ---------- 分流规则 ----------
function RulesScreen({ onTab, rules, toggleRule }) {
  const groups = ['拦截', '直连', '代理'];
  return (
    <>
      <TopBar title="分流规则" onBack={() => onTab('main')} right={
        <button className="iconbtn"><Icon name="plus" size={18} /></button>
      } />
      <div className="scroll" style={{ paddingBottom: 70 }}>
        <div className="pad">
          <div className="seg" style={{ marginBottom: 4 }}>
            <button data-on="1">全部</button>
            <button>直连</button>
            <button>代理</button>
            <button>拦截</button>
          </div>

          {groups.map(g => {
            const list = rules.filter(r => r.group === g);
            if (!list.length) return null;
            return (
              <div key={g}>
                <div className="section-label">
                  <span className="micro">{g}</span>
                  <span className="line" />
                  <span className="micro">{list.length}</span>
                </div>
                <div className="card">
                  {list.map((r, i) => (
                    <div key={r.match} style={{
                      display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px',
                      borderTop: i ? '1px solid rgba(255,255,255,.05)' : 'none',
                      opacity: r.on ? 1 : .45,
                    }}>
                      <Icon name="drag" size={16} color="var(--text-3)" />
                      <div className="grow">
                        <div style={{ font: '400 12px/1.3 var(--mono)', color: 'var(--text)' }}>{r.match}</div>
                        <div className="num" style={{ font: '400 10px/1 var(--mono)', color: 'var(--text-3)', marginTop: 5 }}>
                          命中 {r.hits.toLocaleString()} 次
                        </div>
                      </div>
                      <span className="actionpill" data-a={r.action}>
                        {r.action === 'direct' ? 'DIRECT' : r.action === 'exit' ? 'EXIT' : 'BLOCK'}
                      </span>
                      <div className="switch" data-on={r.on ? 1 : 0} onClick={() => toggleRule(r.match)} />
                    </div>
                  ))}
                </div>
              </div>
            );
          })}

          <div style={{ font: '400 11px/1.6 var(--sans)', color: 'var(--text-3)', textAlign: 'center', marginTop: 18 }}>
            自上而下匹配 · 先命中先生效
          </div>
        </div>
      </div>
      <button className="fab"><Icon name="plus" size={22} sw={2} /></button>
      <NavBar tab="rules" onTab={onTab} />
    </>
  );
}

// ---------- 日志 ----------
function LogScreen({ onTab }) {
  const [filter, setFilter] = React.useState('ALL');
  const shown = LOGS.filter(l => filter === 'ALL' || l.lvl === filter);
  return (
    <>
      <TopBar title="日志" onBack={() => onTab('main')} right={
        <>
          <button className="iconbtn"><Icon name="pause" size={15} /></button>
          <button className="iconbtn"><Icon name="trash" size={16} /></button>
        </>
      } />
      <div className="row" style={{ gap: 6, padding: '0 18px 10px', overflowX: 'auto' }}>
        {['ALL', 'TCP', 'DNS', 'BLK', 'WARN'].map(f => (
          <button key={f} onClick={() => setFilter(f)} className="pill" style={{
            cursor: 'pointer', flex: 'none',
            color: filter === f ? 'var(--accent)' : 'var(--text-3)',
            borderColor: filter === f ? 'var(--accent-line)' : 'var(--line)',
            background: filter === f ? 'var(--accent-soft)' : 'transparent',
          }}>{f}</button>
        ))}
      </div>
      <div className="scroll">
        <div className="pad">
          {shown.map((l, i) => (
            <div key={i} className="logline">
              <span className="t">{l.t}</span>
              <span className="lvl" style={{ color: lvlColor(l.lvl) }}>{l.lvl}</span>
              <span className="msg">{l.text}</span>
            </div>
          ))}
        </div>
      </div>
      <NavBar tab="log" onTab={onTab} />
    </>
  );
}

// ---------- 设置 ----------
function SettingsScreen({ onTab }) {
  const [bypassLan, setBypassLan] = React.useState(true);
  const [autoStart, setAutoStart] = React.useState(false);
  const sections = [
    {
      title: '连接',
      rows: [
        { label: '协调器', value: '47.109.61.89:9000', chevron: true },
        { label: '节点名', value: 'android', chevron: true },
        { label: '网络密钥', value: '•••••••• 已加密', chevron: true },
      ],
    },
    {
      title: 'DNS',
      rows: [
        { label: '代理域名', value: 'exit://overseas-hk', chevron: true },
        { label: '直连域名', value: 'udp://223.5.5.5', chevron: true },
        { label: '缓存条目', value: '412', chevron: false },
      ],
    },
  ];
  return (
    <>
      <TopBar title="设置" onBack={() => onTab('main')} />
      <div className="scroll">
        <div className="pad">
          {sections.map(s => (
            <div key={s.title}>
              <div className="section-label"><span className="micro">{s.title}</span><span className="line" /></div>
              <div className="card">
                {s.rows.map((r, i) => (
                  <div key={r.label} className="listrow" style={{
                    borderTop: i ? '1px solid rgba(255,255,255,.05)' : 'none', cursor: r.chevron ? 'pointer' : 'default',
                  }}>
                    <span className="label grow">{r.label}</span>
                    <span className="value">{r.value}</span>
                    {r.chevron && <Icon name="chevron" size={15} color="var(--text-3)" />}
                  </div>
                ))}
              </div>
            </div>
          ))}

          <div className="section-label"><span className="micro">网络</span><span className="line" /></div>
          <div className="card">
            <div className="listrow">
              <div className="grow">
                <div className="label">绕过局域网</div>
                <div className="sub">内网地址不进入隧道</div>
              </div>
              <div className="switch" data-on={bypassLan ? 1 : 0} onClick={() => setBypassLan(!bypassLan)} />
            </div>
            <div className="listrow">
              <div className="grow">
                <div className="label">开机自启</div>
                <div className="sub">随系统启动并连接</div>
              </div>
              <div className="switch" data-on={autoStart ? 1 : 0} onClick={() => setAutoStart(!autoStart)} />
            </div>
            <div className="listrow">
              <span className="label grow">MTU</span>
              <span className="value">1400</span>
            </div>
          </div>

          <div className="section-label"><span className="micro">关于</span><span className="line" /></div>
          <div className="card">
            <div className="listrow"><span className="label grow">版本</span><span className="value">0.1.0 (p6b)</span></div>
            <div className="listrow"><span className="label grow">协议</span><span className="value">YZP · ChaCha20-Poly1305</span></div>
            <div className="listrow"><span className="label grow">本机 vIP</span><span className="value">100.67.243.69</span></div>
          </div>

          <button className="cta" data-off="1" style={{ marginTop: 22 }}>断开并停止服务</button>
          <div style={{ height: 16 }} />
        </div>
      </div>
    </>
  );
}

Object.assign(window, { TopBar, NavBar, StatePill, PowerButton, StatCell, MainV1, MainV2, MainV3, ExitScreen, RulesScreen, LogScreen, SettingsScreen });
