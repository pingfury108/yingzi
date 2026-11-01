// 线性图标集（24 网格，1.6 描边）
const ICONS = {
  power: 'M12 3v9M6.4 6.4a8 8 0 1 0 11.2 0',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM3 12h18M12 3c2.6 3 2.6 15 0 18M12 3c-2.6 3-2.6 15 0 18',
  rules: 'M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0M14 3v6M8 9v6M16 15v6',
  log: 'M4 5h16M4 10h10M4 15h13M4 20h7',
  settings: 'M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2 2 2 0 1 1-4 0 1.7 1.7 0 0 0-2.9-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.7 1.7 0 0 0 4.6 15a2 2 0 1 1 0-4 1.7 1.7 0 0 0 1.2-2.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.7 1.7 0 0 0 11.5 4a2 2 0 1 1 4 0 1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1A1.7 1.7 0 0 0 19.4 11a2 2 0 1 1 0 4Z',
  chevron: 'M9 6l6 6-6 6',
  back: 'M15 6l-6 6 6 6',
  check: 'M4 12.5l5 5L20 6.5',
  plus: 'M12 5v14M5 12h14',
  trash: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13',
  drag: 'M9 6h.01M9 12h.01M9 18h.01M15 6h.01M15 12h.01M15 18h.01',
  shield: 'M12 3l7 3v6c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3Z',
  bolt: 'M13 3L5 14h6l-1 7 8-11h-6l1-7Z',
  down: 'M12 4v13m0 0l-5-5m5 5l5-5',
  up: 'M12 20V7m0 0L7 12m5-5l5 5',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 4v5l4 2',
  wifi: 'M2 8.8a16 16 0 0 1 20 0M5.5 12.4a11 11 0 0 1 13 0M9 16a6 6 0 0 1 6 0M12 19.5h.01',
  search: 'M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15Zm0 15L21 21',
  pause: 'M9 5v14M15 5v14',
  play: 'M7 4l13 8-13 8V4Z',
  more: 'M6 12h.01M12 12h.01M18 12h.01',
  bell: 'M6 9a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6ZM10 20a2 2 0 0 0 4 0',
};

function Icon({ name, size = 20, color = 'currentColor', sw = 1.6, style }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
      style={{ display: 'block', flex: 'none', ...style }}>
      <path d={ICONS[name] || ''} />
    </svg>
  );
}

// 品牌标记：三层同心弧 + 中心点（网状互联的抽象）
function Mark({ size = 22, color = 'var(--accent)' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" style={{ display: 'block' }}>
      <circle cx="12" cy="12" r="2.2" fill={color} />
      <circle cx="12" cy="12" r="5.6" stroke={color} strokeOpacity=".55" strokeWidth="1.3" />
      <circle cx="12" cy="12" r="9.2" stroke={color} strokeOpacity=".22" strokeWidth="1.3" />
      <circle cx="12" cy="3.2" r="1.5" fill={color} fillOpacity=".9" />
      <circle cx="19.1" cy="16.4" r="1.5" fill={color} fillOpacity=".55" />
      <circle cx="4.9" cy="16.4" r="1.5" fill={color} fillOpacity=".55" />
    </svg>
  );
}

Object.assign(window, { Icon, Mark, ICONS });
