// 图表组件：迷你面积图 / 环形仪表 / 命中率条
function toPath(series, w, h, pad = 2) {
  const max = Math.max(...series) * 1.12 || 1;
  const step = (w - pad * 2) / (series.length - 1);
  return series.map((v, i) => {
    const x = pad + i * step;
    const y = h - pad - (v / max) * (h - pad * 2);
    return [x, y];
  });
}

function linePath(pts) {
  // Catmull-Rom → 贝塞尔，让曲线不呆板
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] || p2;
    const c1x = p1[0] + (p2[0] - p0[0]) / 6;
    const c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6;
    const c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C${c1x},${c1y} ${c2x},${c2y} ${p2[0]},${p2[1]}`;
  }
  return d;
}

function Spark({ series, w = 300, h = 64, color = 'var(--accent)', fill = true, id = 'sp' }) {
  const pts = toPath(series, w, h);
  const line = linePath(pts);
  const area = `${line} L${w - 2},${h} L2,${h} Z`;
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: 'block' }}>
      <defs>
        <linearGradient id={`${id}-g`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity=".28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <path d={area} fill={`url(#${id}-g)`} />}
      <path d={line} fill="none" stroke={color} strokeWidth="1.6" strokeLinejoin="round" />
      <circle cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r="2.6" fill={color} />
    </svg>
  );
}

function Ring({ value = 0.62, size = 210, label, sub, color = 'var(--accent)' }) {
  const r = size / 2 - 14;
  const c = 2 * Math.PI * r;
  const arc = c * 0.75; // 270° 仪表弧
  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(135deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke="rgba(255,255,255,.06)" strokeWidth="10"
          strokeDasharray={`${arc} ${c}`} strokeLinecap="round" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${arc * value} ${c}`}
          style={{ filter: 'drop-shadow(0 0 10px rgba(56,240,198,.45))', transition: 'stroke-dasharray .6s ease' }} />
        {/* 刻度 */}
        {Array.from({ length: 33 }).map((_, i) => {
          const a = (135 + (270 / 32) * i) * Math.PI / 180;
          const inner = r - 12;
          const x1 = size / 2 + Math.cos(a) * inner;
          const y1 = size / 2 + Math.sin(a) * inner;
          const x2 = size / 2 + Math.cos(a) * (inner - (i % 4 === 0 ? 7 : 3));
          const y2 = size / 2 + Math.sin(a) * (inner - (i % 4 === 0 ? 7 : 3));
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
            stroke="rgba(255,255,255,.18)" strokeWidth="1" />;
        })}
      </svg>
      <div style={{
        position: 'absolute', inset: 0, display: 'grid', placeItems: 'center',
        textAlign: 'center', gap: 2,
      }}>
        <div>
          <div style={{ font: '500 11px/1 var(--mono)', letterSpacing: '.16em', color: 'var(--text-3)' }}>{label}</div>
          <div style={{ font: '500 34px/1.1 var(--mono)', color: 'var(--text)', marginTop: 8 }}>{sub}</div>
        </div>
      </div>
    </div>
  );
}

function HitBar({ label, pct, color }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <span style={{ font: '400 11px/1 var(--mono)', color: 'var(--text-2)' }}>{label}</span>
        <span className="num" style={{ font: '500 11px/1 var(--mono)', color: 'var(--text-3)' }}>{pct}%</span>
      </div>
      <div style={{ height: 4, borderRadius: 4, background: 'rgba(255,255,255,.07)', overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 4 }} />
      </div>
    </div>
  );
}

Object.assign(window, { Spark, Ring, HitBar });
