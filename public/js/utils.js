const ICON_PATHS = {
  activity: '<path d="M22 12h-4l-3 8-6-16-3 8H2"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  arrowLeft: '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
  barChart: '<path d="M3 3v18h18"/><path d="M7 16v-5"/><path d="M12 16V7"/><path d="M17 16v-8"/>',
  bolt: '<path d="M13 2 4 14h7l-1 8 10-12h-7l1-8Z"/>',
  calendar: '<path d="M8 2v4"/><path d="M16 2v4"/><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M3 10h18"/>',
  check: '<path d="m20 6-11 11-5-5"/>',
  clipboard: '<rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><rect x="2" y="2" width="13" height="13" rx="2"/>',
  diamond: '<path d="M6 3h12l4 6-10 12L2 9l4-6Z"/><path d="m2 9 10 12L22 9"/><path d="M6 3 2 9h20l-4-6"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="m3 3 18 18"/><path d="M10.6 10.6A3 3 0 0 0 13.4 13.4"/><path d="M9.9 4.2A10.3 10.3 0 0 1 12 4c6.5 0 10 8 10 8a15.6 15.6 0 0 1-4.1 5.1"/><path d="M6.1 6.1A15.6 15.6 0 0 0 2 12s3.5 8 10 8c.8 0 1.5-.1 2.2-.3"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 0 20"/><path d="M12 2a15.3 15.3 0 0 0 0 20"/>',
  id: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="M15 9h3"/><path d="M15 13h3"/><path d="M7 16h4"/>',
  key: '<circle cx="7.5" cy="14.5" r="3.5"/><path d="M10 12 21 1"/><path d="m15 6 3 3"/><path d="m18 3 3 3"/>',
  list: '<path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/>',
  loader: '<path d="M12 2v4"/><path d="M12 18v4"/><path d="m4.93 4.93 2.83 2.83"/><path d="m16.24 16.24 2.83 2.83"/><path d="M2 12h4"/><path d="M18 12h4"/><path d="m4.93 19.07 2.83-2.83"/><path d="m16.24 7.76 2.83-2.83"/>',
  logOut: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  package: '<path d="m16.5 9.4-9-5.2"/><path d="M21 16V8a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.7l7 4a2 2 0 0 0 2 0l7-4a2 2 0 0 0 1-1.7Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
  radio: '<path d="M4.9 19.1a10 10 0 0 1 0-14.2"/><path d="M7.8 16.2a6 6 0 0 1 0-8.5"/><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.5"/><path d="M19.1 4.9a10 10 0 0 1 0 14.2"/>',
  send: '<path d="m22 2-7 20-4-9-9-4 20-7Z"/><path d="M22 2 11 13"/>',
  server: '<rect x="3" y="4" width="18" height="8" rx="2"/><rect x="3" y="12" width="18" height="8" rx="2"/><path d="M7 8h.01"/><path d="M7 16h.01"/>',
  settings: '<path d="M12 15.5A3.5 3.5 0 1 0 12 8a3.5 3.5 0 0 0 0 7.5Z"/><path d="M19.4 15a1.8 1.8 0 0 0 .4 2l.1.1a2.1 2.1 0 1 1-3 3l-.1-.1a1.8 1.8 0 0 0-2-.4 1.8 1.8 0 0 0-1 1.6V22a2.1 2.1 0 1 1-4.2 0v-.2a1.8 1.8 0 0 0-1-1.6 1.8 1.8 0 0 0-2 .4l-.1.1a2.1 2.1 0 1 1-3-3l.1-.1a1.8 1.8 0 0 0 .4-2 1.8 1.8 0 0 0-1.6-1H2a2.1 2.1 0 1 1 0-4.2h.2a1.8 1.8 0 0 0 1.6-1 1.8 1.8 0 0 0-.4-2l-.1-.1a2.1 2.1 0 1 1 3-3l.1.1a1.8 1.8 0 0 0 2 .4 1.8 1.8 0 0 0 1-1.6V2a2.1 2.1 0 1 1 4.2 0v.2a1.8 1.8 0 0 0 1 1.6 1.8 1.8 0 0 0 2-.4l.1-.1a2.1 2.1 0 1 1 3 3l-.1.1a1.8 1.8 0 0 0-.4 2 1.8 1.8 0 0 0 1.6 1H22a2.1 2.1 0 1 1 0 4.2h-.2a1.8 1.8 0 0 0-1.6 1Z"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>',
  spark: '<path d="M12 2v5"/><path d="M12 17v5"/><path d="M2 12h5"/><path d="M17 12h5"/><path d="m4.9 4.9 3.5 3.5"/><path d="m15.6 15.6 3.5 3.5"/><path d="m19.1 4.9-3.5 3.5"/><path d="m8.4 15.6-3.5 3.5"/>',
  user: '<path d="M20 21a8 8 0 0 0-16 0"/><circle cx="12" cy="7" r="4"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9"/><path d="M16 3.1a4 4 0 0 1 0 7.8"/>',
  wrench: '<path d="M14.7 6.3a4 4 0 0 0-5.5 5.5L3 18v3h3l6.2-6.2a4 4 0 0 0 5.5-5.5l-2.4 2.4-3-3 2.4-2.4Z"/>'
};

function $(id) {
  return document.getElementById(id);
}

function iconSvg(name, className = '') {
  const path = ICON_PATHS[name] || ICON_PATHS.spark;
  const classAttr = ['app-icon', className].filter(Boolean).join(' ');
  return `<svg class="${classAttr}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${path}</svg>`;
}

function renderStaticIcons(root = document) {
  root.querySelectorAll('[data-icon]').forEach((el) => {
    el.innerHTML = iconSvg(el.dataset.icon, el.dataset.iconClass || '');
  });
}

function formatUptime(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h ${m % 60}m ${s % 60}s`;
}

function formatNum(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

function maskKey(key) {
  if (!key || key.length <= 8) return '••••••••';
  return key.slice(0, 6) + '•'.repeat(Math.max(6, key.length - 10)) + key.slice(-4);
}

function copyToClipboard(text, btn, copiedLabel = 'Kopyalandı') {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = `${iconSvg('check')} ${copiedLabel}`;
    setTimeout(() => { btn.innerHTML = orig; }, 1800);
  });
}

function getDaysLeft(expires) {
  const diff = Math.ceil((new Date(expires) - Date.now()) / 86_400_000);
  return Math.max(0, diff);
}

function getSubProgress(started, expires) {
  const s = new Date(started).getTime();
  const e = new Date(expires).getTime();
  const elapsed = Date.now() - s;
  return Math.min(100, Math.max(0, (elapsed / (e - s)) * 100));
}

function saveSession(user) {
  sessionStorage.setItem('cx_user', JSON.stringify(user));
}

function loadSession() {
  const raw = sessionStorage.getItem('cx_user');
  return raw ? JSON.parse(raw) : null;
}

function clearSession() {
  sessionStorage.removeItem('cx_user');
}

async function apiFetch(url, options) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'İstek başarısız.');
  return data;
}

document.addEventListener('DOMContentLoaded', () => {
  renderStaticIcons();
});
