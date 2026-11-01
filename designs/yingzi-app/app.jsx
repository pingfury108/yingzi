const { useState } = React;

const HASH = new URLSearchParams(location.hash.slice(1));

function App() {
  const [tab, setTab] = useState(HASH.get('screen') || 'main');   // main | exit | rules | log | settings
  const [variant, setVariant] = useState(HASH.get('v') || 'v1');  // 主界面变体
  const [connected, setConnected] = useState(true);
  const [exit, setExit] = useState('overseas-hk');
  const [rules, setRules] = useState(RULES);

  const toggleRule = (match) =>
    setRules(rs => rs.map(r => r.match === match ? { ...r, on: !r.on } : r));

  const go = (t) => setTab(t);

  let screen;
  if (tab === 'main') {
    const props = { connected, onToggle: () => setConnected(c => !c), onTab: go, onExit: exit };
    screen = variant === 'v1' ? <MainV1 {...props} />
      : variant === 'v2' ? <MainV2 {...props} />
      : <MainV3 {...props} />;
  } else if (tab === 'exit') {
    screen = <ExitScreen onTab={go} exit={exit} setExit={setExit} />;
  } else if (tab === 'rules') {
    screen = <RulesScreen onTab={go} rules={rules} toggleRule={toggleRule} />;
  } else if (tab === 'log') {
    screen = <LogScreen onTab={go} />;
  } else {
    screen = <SettingsScreen onTab={go} />;
  }

  return (
    <div className="stage">
      <div className="stage-head">
        <div className="wordmark">
          <Mark size={18} />
          <b>YINGZI</b>
          <span>android client</span>
        </div>
        <div className="switcher">
          {[
            ['v1', '主界面 A · 单卡'],
            ['v2', '主界面 B · 仪表'],
            ['v3', '主界面 C · 面板'],
          ].map(([id, label]) => (
            <button key={id} data-on={variant === id && tab === 'main' ? 1 : 0}
              onClick={() => { setVariant(id); setTab('main'); }}>{label}</button>
          ))}
        </div>
        <div className="switcher">
          {[['exit', '节点'], ['rules', '规则'], ['log', '日志'], ['settings', '设置']].map(([id, label]) => (
            <button key={id} data-on={tab === id ? 1 : 0} onClick={() => setTab(id)}>{label}</button>
          ))}
        </div>
      </div>

      <div style={{ filter: 'drop-shadow(0 40px 90px rgba(0,0,0,.65))' }}>
        <AndroidDevice width={390} height={812} dark bg="#07090B">
          <div className="app">{screen}</div>
        </AndroidDevice>
      </div>

      <div style={{ font: '400 11px/1 var(--mono)', color: 'var(--text-3)', letterSpacing: '.1em' }}>
        点击底部导航可切换 · 电源键切换连接状态 · 规则开关实时生效
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
