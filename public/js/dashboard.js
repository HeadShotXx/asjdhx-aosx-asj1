let currentUser = null;
let systemData = null;
let systemConfig = { global_slots: 0 };
let methods = [];
let uptimeInterval = null;
let attackTicker = null;
let systemStartTime = null;
let activeRequest = null;
let activeAttacks = [];
let globalAttacks = [];
let attackRefreshInFlight = false;
let attackFilter = 'all';
let attackCooldownUntil = 0;
const attackTargetHistory = new Set();

const PAGE_TITLES = {
  overview: { title: 'Dashboard Overview', sub: 'Sistem metrikleri ve genel durum' },
  menu: { title: 'API Menüsü', sub: 'Kullanılabilir metodlar ve endpointler' },
  sendapi: { title: 'Send API', sub: 'API isteği gönder ve sonuçları gör' },
  profile: { title: 'Profil', sub: 'Hesap bilgileri ve abonelik detayları' },
  settings: { title: 'Ayarlar', sub: 'Uygulama tercihleri' }
};

async function loadAppData() {
  const [system, methodList, config] = await Promise.all([
    apiFetch('/api/system'),
    apiFetch('/api/methods'),
    apiFetch('/api/config')
  ]);
  systemData = system;
  methods = methodList;
  systemConfig = config || { global_slots: 0 };
  systemStartTime = new Date(system.startedAt);
}

async function refreshSessionUser(savedUser) {
  if (!savedUser?.key) return savedUser;
  const data = await apiFetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key: savedUser.key })
  });
  saveSession(data.user);
  return data.user;
}

function showDashboard(user) {
  renderDashboard(user);
  navigateTo('overview');
  startUptime();
  startAttackTicker();
}

function renderDashboard(user) {
  $('sidebar-username').textContent = user.username;
  $('sidebar-plan').textContent = user.plan;
  $('sidebar-avatar').textContent = user.username[0].toUpperCase();
  $('topbar-user').textContent = user.username;

  const badges = [];
  if (user.admin) badges.push('<span class="mini-badge danger">Admin</span>');
  if (user.star) badges.push('<span class="mini-badge">Star</span>');
  if (user.vip) badges.push('<span class="mini-badge gold">VIP</span>');

  const badgeEl = $('user-badges');
  if (badgeEl) badgeEl.innerHTML = badges.join('');
}

function navigateTo(page) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });

  document.querySelectorAll('.page').forEach(el => {
    el.classList.toggle('active', el.id === `page-${page}`);
  });

  if (page === 'overview') {
    // Overview'a her geçişte sistem verilerini ve kullanıcıyı tazele
    Promise.all([
      apiFetch('/api/system').catch(() => systemData),
      apiFetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: currentUser?.key })
      }).catch(() => null)
    ]).then(([sys, authData]) => {
      if (sys) systemData = sys;
      if (authData?.user) {
        currentUser = authData.user;
        saveSession(currentUser);
      }
      renderOverview();
    });
  }
  if (page === 'menu') renderMenu();
  if (page === 'sendapi') renderSendApi();
  if (page === 'profile') renderProfile();
  if (page === 'settings') renderSettings();

  const t = PAGE_TITLES[page] || { title: 'Cortex', sub: '' };
  if ($('topbar-title')) $('topbar-title').textContent = t.title;
  if ($('topbar-sub')) $('topbar-sub').textContent = t.sub;
}

function renderOverview() {
  if (!currentUser || !systemData) return;

  const totalAttacks = systemData.totalApiSends || 0;
  const userTotal = currentUser.stats?.totalApiSends || 0;

  const metrics = [
    { icon: 'activity', color: 'green', value: '--', label: 'Uptime Süresi', id: 'metric-uptime', change: 'Stabil', changeClass: 'stable' },
    { icon: 'users', color: 'violet', value: formatNum(systemData.totalCustomers), label: 'Toplam Müşteri', change: '+12% bu ay', changeClass: 'up' },
    { icon: 'radio', color: 'cyan', value: formatNum(totalAttacks), label: 'Toplam Gönderilen Atak', change: `Benim: ${formatNum(userTotal)}`, changeClass: 'up' },
    { icon: 'wrench', color: 'gold', value: systemData.totalMethods, label: 'Toplam Method', change: 'Stabil', changeClass: 'stable' }
  ];

  $('overview-grid').innerHTML = metrics.map(m => `
    <div class="metric-card fade-in">
      <div class="metric-icon ${m.color}">${iconSvg(m.icon)}</div>
      <div class="metric-value" id="${m.id || ''}">${m.value}</div>
      <div class="metric-label">${m.label}</div>
      <div class="metric-change ${m.changeClass}">${m.changeClass === 'up' ? '+ ' : ''}${m.change}</div>
    </div>
  `).join('');

  updateUptimeMetric();

  const activities = [
    { color: 'green', text: 'API isteği başarıyla gönderildi - <span style="color:var(--lavender)">HTTP Flood</span>', time: '2 dk önce' },
    { color: 'violet', text: 'Yeni kullanıcı oturum açtı - <span style="color:var(--lavender)">CX-001-ALPHA</span>', time: '15 dk önce' },
    { color: 'cyan', text: 'Method güncellemesi yayınlandı - <span style="color:var(--lavender)">v2.4.1</span>', time: '1 sa önce' },
    { color: 'green', text: 'Sistem sağlık kontrolü geçti - <span style="color:var(--success)">%100 healthy</span>', time: '2 sa önce' },
    { color: 'violet', text: 'UDP Bypass method eklendi', time: '1 gün önce' }
  ];

  $('activity-feed').innerHTML = activities.map(a => `
    <div class="activity-item">
      <div class="activity-dot ${a.color}"></div>
      <div>
        <div class="activity-text">${a.text}</div>
        <div class="activity-time">${a.time}</div>
      </div>
    </div>
  `).join('');

  $('user-stat-box').innerHTML = `
    <div class="info-row"><span class="info-key">Hesap</span><span class="info-val">${currentUser.username}</span></div>
    <div class="info-row"><span class="info-key">Plan</span><span class="info-val">${currentUser.plan}</span></div>
    <div class="info-row"><span class="info-key">UID</span><span class="info-val">${currentUser.uid}</span></div>
    <div class="info-row"><span class="info-key">Toplam Atak</span><span class="info-val" style="color:var(--success);font-weight:600;">${formatNum(userTotal)}</span></div>
    <div class="info-row"><span class="info-key">Abonelik Bitiş</span><span class="info-val">${currentUser.subscription.expires}</span></div>
  `;
}

function updateUptimeMetric() {
  if (!systemStartTime) return;
  const elapsed = Date.now() - systemStartTime.getTime();
  const text = formatUptime(elapsed);
  if ($('metric-uptime')) $('metric-uptime').textContent = text;
  if ($('topbar-uptime')) $('topbar-uptime').textContent = text;
}

function startUptime() {
  if (uptimeInterval) clearInterval(uptimeInterval);
  updateUptimeMetric();
  uptimeInterval = setInterval(updateUptimeMetric, 1000);
}

function startAttackTicker() {
  if (attackTicker) clearInterval(attackTicker);
  attackTicker = setInterval(async () => {
    try {
      await refreshActiveAttacks();
    } catch {
      return;
    }
    pruneFinishedAttacks();
    renderActiveAttacks();
  }, 1000);
}

function hydrateAttack(attack) {
  return {
    ...attack,
    startedAt: Number(attack.startedAt),
    duration: Number(attack.duration),
    port: Number(attack.port) || 80,
    mine: attack.ownerUid === currentUser?.uid
  };
}

function setSharedAttacks(attacks) {
  globalAttacks = (Array.isArray(attacks) ? attacks : []).map(hydrateAttack);
  activeAttacks = globalAttacks.filter(attack => attack.mine);
  activeRequest = activeAttacks[0] || null;
}

async function refreshActiveAttacks() {
  if (attackRefreshInFlight) return;
  attackRefreshInFlight = true;
  try {
    const data = await apiFetch('/api/active-attacks');
    setSharedAttacks(data.attacks);
  } finally {
    attackRefreshInFlight = false;
  }
}

function typeBadgeStyle(type) {
  if (type === 'L4') return 'background:rgba(239,68,68,.1);color:#FCA5A5;border-color:rgba(239,68,68,.2)';
  if (type === 'L7') return 'background:rgba(124,58,237,.12);color:var(--lavender);border-color:rgba(124,58,237,.2)';
  return '';
}

function renderMenu() {
  $('method-grid').innerHTML = methods.map(m => {
    const tags = Array.isArray(m.tags) ? m.tags : [];
    const tagBadges = tags.map(tag => `<span class="method-badge badge-get">${escapeHtml(tag)}</span>`).join('');

    // Target type indicators
    const targets = [];
    if (m.ip) targets.push('<span class="method-badge badge-target-on">IP</span>');
    else targets.push('<span class="method-badge badge-target-off">IP</span>');
    if (m.http) targets.push('<span class="method-badge badge-target-on">HTTP</span>');
    else targets.push('<span class="method-badge badge-target-off">HTTP</span>');
    if (m.https) targets.push('<span class="method-badge badge-target-on">HTTPS</span>');
    else targets.push('<span class="method-badge badge-target-off">HTTPS</span>');

    return `
    <div class="method-card fade-in">
      <div class="method-header">
        <span class="method-name">${escapeHtml(m.name)}</span>
        <div class="method-badges">
          <span class="method-badge badge-get" style="${typeBadgeStyle(m.type)}">${escapeHtml(m.type)}</span>
          ${tagBadges}
          ${m.vip ? '<span class="method-badge badge-vip">VIP</span>' : ''}
          ${m.star ? '<span class="method-badge badge-star">Star</span>' : ''}
          ${m.admin ? '<span class="method-badge badge-admin">Admin</span>' : ''}
        </div>
      </div>
      <div class="method-desc">${escapeHtml(m.desc)}</div>
      <div class="method-target-types">${targets.join('')}</div>
      <div class="method-endpoint">/api/attack?method=${encodeURIComponent(m.name)}</div>
    </div>
  `;
  }).join('');
}

function canUseMethod(m) {
  if (!currentUser) return false;
  if (m.vip && !currentUser.vip) return false;
  if (m.star && !currentUser.star) return false;
  if (m.admin && !currentUser.admin) return false;
  return true;
}

function detectTargetType(target) {
  const t = String(target).trim().toLowerCase();
  if (t.startsWith('https://')) return 'https';
  if (t.startsWith('http://')) return 'http';
  return 'ip';
}

function isTargetAllowed(method, targetType) {
  const hasAny = method.ip || method.http || method.https;
  if (!hasAny) return true;
  if (targetType === 'ip') return !!method.ip;
  if (targetType === 'http') return !!method.http;
  if (targetType === 'https') return !!method.https;
  return true;
}

function renderSendApi() {
  const usable = methods.filter(m => canUseMethod(m));
  const permBadge = (m) => {
    let b = '';
    if (m.vip) b += ' VIP';
    if (m.star) b += ' Star';
    if (m.admin) b += ' Admin';
    return b;
  };
  $('method-select').innerHTML = usable.map(m =>
    `<option value="${m.name}">${m.name} [${m.type}]${permBadge(m)}</option>`
  ).join('');
  if (!usable.length) {
    $('method-select').innerHTML = '<option disabled>Kullanilabilir method yok</option>';
  }
  if ($('time-input') && currentUser?.attack_time) {
    $('time-input').max = currentUser.attack_time;
    $('time-input').value = Math.min(parseInt($('time-input').value || currentUser.attack_time, 10), currentUser.attack_time);
  }
  ensureGlobalAttackFeed();
  updateOngoingPanel(activeRequest ? 'running' : 'idle');
  pruneFinishedAttacks();
  renderActiveAttacks();
}

function getSelectedMethod() {
  const name = $('method-select')?.value;
  return methods.find(m => m.name === name) || methods[0];
}

function getAttackTiming(attack) {
  const elapsedMs = Date.now() - attack.startedAt;
  const totalMs = attack.duration * 1000;
  const remainingMs = Math.max(0, totalMs - elapsedMs);
  const progress = Math.min(100, Math.max(0, (elapsedMs / totalMs) * 100));
  return {
    remainingSeconds: Math.ceil(remainingMs / 1000),
    progress
  };
}

function pruneFinishedAttacks() {
  activeAttacks = activeAttacks.filter(attack => getAttackTiming(attack).remainingSeconds > 0);
  globalAttacks = globalAttacks.filter(attack => getAttackTiming(attack).remainingSeconds > 0);
}

function ensureGlobalAttackFeed() {
  globalAttacks = globalAttacks.slice(0, getGlobalSlotLimit());
}

function getGlobalSlotLimit() {
  return Math.max(0, parseInt(systemConfig?.global_slots ?? 0, 10) || 0);
}

function getUserConcurrentLimit() {
  return Math.max(0, parseInt(currentUser?.concurrent ?? 0, 10) || 0);
}

function updateAttackCounters() {
  const globalLimit = getGlobalSlotLimit();
  const myLimit = getUserConcurrentLimit();
  const globalCount = globalAttacks.length;
  const myCount = globalAttacks.filter(attack => attack.mine).length;
  const userTotal = currentUser?.stats?.totalApiSends || 0;
  if ($('global-slots-count')) $('global-slots-count').textContent = `${globalCount}/${globalLimit}`;
  if ($('my-concurrents-count')) $('my-concurrents-count').textContent = `${myCount}/${myLimit}`;
  if ($('user-total-attacks')) $('user-total-attacks').textContent = formatNum(userTotal);
}

function getVisibleAttacks() {
  return attackFilter === 'all'
    ? globalAttacks
    : globalAttacks.filter(attack => attack.mine);
}

function setAttackFilter(filter) {
  attackFilter = filter === 'all' ? 'all' : 'mine';
  document.querySelectorAll('[data-attack-filter]').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.attackFilter === attackFilter);
  });
  renderActiveAttacks();
}

function renderActiveAttacks() {
  const panel = $('active-attacks-panel');
  const count = $('active-attack-count');
  if (!panel) return;

  pruneFinishedAttacks();
  const visibleAttacks = getVisibleAttacks();
  if (count) count.textContent = visibleAttacks.length;
  updateAttackCounters();

  if (!visibleAttacks.length) {
    panel.innerHTML = `
      <div class="empty-attacks">
        <div class="empty-attacks-icon">${iconSvg('radio')}</div>
        <div>
          <strong>Aktif atak yok</strong>
          <span>Yeni bir istek başlatıldığında burada listelenecek.</span>
        </div>
      </div>
    `;
    return;
  }

  panel.innerHTML = visibleAttacks.map(attack => {
    const timing = getAttackTiming(attack);
    return `
      <div class="attack-row">
        <div class="attack-row-head">
          <div>
            <div class="attack-name">${escapeHtml(attack.method)}</div>
            <div class="attack-target">${escapeHtml(attack.target)}</div>
            <div class="attack-owner">${attack.mine ? 'Bizim atagimiz' : escapeHtml(attack.owner)}</div>
          </div>
          <span class="attack-live ${attack.mine ? '' : 'is-global'}">${attack.mine ? 'Mine' : 'Global'}</span>
        </div>
        <div class="attack-meta">
          <span>Port ${attack.port}</span>
          <span>${timing.remainingSeconds}s kaldı</span>
          <span>${escapeHtml(attack.node)}</span>
        </div>
        <div class="attack-progress"><span style="width:${timing.progress}%"></span></div>
      </div>
    `;
  }).join('');
}

function updateOngoingPanel(state = 'idle') {
  const panel = $('ongoing-panel');
  const method = getSelectedMethod();
  if (!panel || !method) return;

  const target = $('target-input')?.value || 'https://example.com';
  const port = $('port-input')?.value || '80';
  const time = $('time-input')?.value || '60';
  const isRunning = state === 'running';
  const isDone = state === 'done';
  const title = isRunning ? 'Atak devam ediyor' : isDone ? 'Son atak tamamlandı' : 'Beklemede';
  const note = isRunning
    ? 'Aktif atak izleniyor. Tamamlandığında aktif atak listesinden otomatik silinecek.'
    : isDone
      ? 'Son atak tamamlandı ve aktif listeden kaldırıldı. Yeni istek için parametreleri güncelleyebilirsiniz.'
      : 'Henüz aktif bir atak yok. Parametreleri kontrol edip isteği başlatabilirsiniz.';

  panel.innerHTML = `
    <div class="ongoing-state ${isRunning ? 'running' : isDone ? 'done' : ''}">
      <div class="ongoing-icon">${iconSvg(isRunning ? 'loader' : isDone ? 'check' : 'activity', isRunning ? 'spin-icon' : '')}</div>
      <div>
        <div class="ongoing-title">${title}</div>
        <div class="ongoing-note">${note}</div>
      </div>
      <span class="ongoing-badge">${isRunning ? 'Running' : isDone ? 'Completed' : 'Ongoing'}</span>
    </div>
    <div class="ongoing-meta">
      <div><span>Method</span><strong>${escapeHtml(method.name)}</strong></div>
      <div><span>Hedef</span><strong>${escapeHtml(target)}</strong></div>
      <div><span>Port</span><strong>${port}</strong></div>
      <div><span>Süre</span><strong>${time} sn</strong></div>
    </div>
    <div class="ongoing-progress ${isRunning ? 'is-active' : ''}">
      <span></span>
    </div>
  `;
}

function normalizeTarget(target) {
  return target.trim().toLowerCase();
}

function stopAttackRequest(message) {
  updateOngoingPanel(activeRequest ? 'running' : 'idle');
  alert(message);
}

async function sendApiRequest() {
  const btn = $('send-api-btn');
  const method = getSelectedMethod();
  const target = $('target-input')?.value || 'https://example.com';
  const port = $('port-input')?.value || '80';
  const requestedDuration = Math.max(1, parseInt($('time-input')?.value || '60', 10));
  const maxAttackTime = Math.max(1, parseInt(currentUser?.attack_time ?? requestedDuration, 10) || requestedDuration);
  const duration = Math.min(requestedDuration, maxAttackTime);
  const globalLimit = getGlobalSlotLimit();
  const myLimit = getUserConcurrentLimit();
  const myActiveCount = globalAttacks.filter(attack => attack.mine).length;
  const normalizedTarget = normalizeTarget(target);

  if (!target.trim()) {
    updateOngoingPanel('idle');
    return;
  }

  // Permission kontrolü (client-side)
  if (!canUseMethod(method)) {
    const needed = [];
    if (method.vip && !currentUser.vip) needed.push('VIP');
    if (method.star && !currentUser.star) needed.push('Star');
    if (method.admin && !currentUser.admin) needed.push('Admin');
    stopAttackRequest(`Bu method icin ${needed.join(', ')} yetkisi gerekli.`);
    return;
  }

  // Target type kontrolü (client-side)
  const targetType = detectTargetType(target);
  if (!isTargetAllowed(method, targetType)) {
    const allowed = [];
    if (method.ip) allowed.push('IP');
    if (method.http) allowed.push('HTTP');
    if (method.https) allowed.push('HTTPS');
    stopAttackRequest(`Bu method sadece ${allowed.join(', ')} hedeflerini destekler. Siz ${targetType.toUpperCase()} gonderdiniz.`);
    return;
  }

  if (globalAttacks.length >= globalLimit) {
    stopAttackRequest('Global slot limiti dolu.');
    return;
  }

  if (myActiveCount >= myLimit) {
    stopAttackRequest('My Concurrents limiti dolu.');
    return;
  }

  if (Date.now() < attackCooldownUntil) {
    const waitSeconds = Math.ceil((attackCooldownUntil - Date.now()) / 1000);
    stopAttackRequest(`Cooldown aktif. ${waitSeconds}s sonra tekrar deneyin.`);
    return;
  }

  if (currentUser?.spambypass === false && attackTargetHistory.has(normalizedTarget)) {
    stopAttackRequest('Spam bypass kapali. Ayni targeta tekrar attack baslatamazsiniz.');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Baslatiliyor...';

  try {
    const data = await apiFetch('/api/active-attacks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key: currentUser?.key,
        method: method.name,
        target,
        port,
        duration
      })
    });

    setSharedAttacks(data.attacks);

    // Yerel kullanıcı stats'unu güncelle (sunucudan dönen güncel veri varsa kullan)
    if (data.user) {
      currentUser = data.user;
      saveSession(currentUser);
    } else if (currentUser?.stats) {
      currentUser.stats.totalApiSends = (currentUser.stats.totalApiSends || 0) + 1;
      currentUser.stats.totalRequests = (currentUser.stats.totalRequests || 0) + 1;
      saveSession(currentUser);
    }

    attackTargetHistory.add(normalizedTarget);
    attackCooldownUntil = Date.now() + (Math.max(0, parseInt(currentUser?.cooldown ?? 0, 10) || 0) * 1000);
    renderActiveAttacks();
    updateOngoingPanel('running');
    // Toplam atak sayıcısını anında güncelle
    if ($('user-total-attacks')) $('user-total-attacks').textContent = formatNum(currentUser?.stats?.totalApiSends || 0);
  } catch (error) {
    stopAttackRequest(error.message || 'Istek baslatilamadi.');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `${iconSvg('send')} Send Request`;
  }
  return;
}

function renderProfile() {
  if (!currentUser) return;
  const u = currentUser;
  const daysLeft = getDaysLeft(u.subscription.expires);

  $('profile-avatar').textContent = u.username[0].toUpperCase();
  $('profile-name').textContent = u.username;
  $('profile-uid').textContent = u.uid;

  const badges = [];
  if (u.admin) badges.push(`<span class="badge-tag admin">${iconSvg('shield')} Admin</span>`);
  if (u.star) badges.push(`<span class="badge-tag star">${iconSvg('spark')} Star</span>`);
  if (u.vip) badges.push(`<span class="badge-tag vip">${iconSvg('diamond')} VIP</span>`);
  badges.push(`<span class="badge-tag plan">${iconSvg('package')} ${u.plan}</span>`);
  $('profile-badges').innerHTML = badges.join('');

  $('profile-info').innerHTML = `
    <div class="info-row"><span class="info-key">${iconSvg('user')} KullanÄ±cÄ± AdÄ±</span><span class="info-val">${u.username}</span></div>
    <div class="info-row"><span class="info-key">${iconSvg('id')} KullanÄ±cÄ± ID</span><span class="info-val">${u.uid}</span></div>
    <div class="info-row"><span class="info-key">${iconSvg('calendar')} KayÄ±t Tarihi</span><span class="info-val">${u.createdAt.slice(0, 10)}</span></div>
    <div class="info-row"><span class="info-key">${iconSvg('activity')} Kalan GÃ¼n</span><span class="info-val" style="color:${daysLeft < 14 ? 'var(--warning)' : 'var(--success)'}">${daysLeft} gÃ¼n</span></div>
    <div class="info-row"><span class="info-key">${iconSvg('check')} Durum</span><span class="info-val" style="color:var(--success)">Aktif</span></div>
    <div class="info-row"><span class="info-key">${iconSvg('shield')} Spam Bypass</span><span class="info-val" style="color:${u.spambypass ? 'var(--success)' : 'var(--danger)'}">${u.spambypass ? 'Aktif' : 'Kapali'}</span></div>
    <div class="info-row"><span class="info-key">${iconSvg('key')} API Access</span><span class="info-val" style="color:${u.api_access ? 'var(--success)' : 'var(--danger)'}">${u.api_access ? 'Aktif' : 'Kapali'}</span></div>
    <div class="info-row"><span class="info-key">${iconSvg('activity')} Cooldown</span><span class="info-val">${u.cooldown ?? 0} sn</span></div>
    <div class="info-row"><span class="info-key">${iconSvg('users')} Concurrent</span><span class="info-val">${u.concurrent ?? 0}</span></div>
  `;

  if ($('profile-key')) $('profile-key').textContent = maskKey(u.key);

  let revealed = false;
  if ($('key-reveal-btn')) $('key-reveal-btn').onclick = () => {
    revealed = !revealed;
    if ($('profile-key')) $('profile-key').textContent = revealed ? u.key : maskKey(u.key);
    $('key-reveal-btn').innerHTML = `${iconSvg(revealed ? 'eyeOff' : 'eye')} ${revealed ? 'Gizle' : 'GÃ¶ster'}`;
  };

  if ($('key-copy-btn')) $('key-copy-btn').onclick = () => copyToClipboard(u.key, $('key-copy-btn'));

  $('sub-plan').textContent = u.plan;
  $('sub-expires').textContent = u.subscription.expires;
  $('sub-started').textContent = u.subscription.started;
  $('sub-days-left').textContent = daysLeft + ' gÃ¼n';
  $('sub-status').textContent = u.subscription.active ? 'Aktif' : 'Sona Erdi';
  $('sub-status').style.color = u.subscription.active ? 'var(--success)' : 'var(--danger)';
  $('sub-progress').style.width = getSubProgress(u.subscription.started, u.subscription.expires) + '%';
  $('stat-api-sends').textContent = formatNum(u.stats.totalApiSends);
  $('stat-requests').textContent = formatNum(u.stats.totalRequests);
}

function renderSettings() {
  if (!currentUser) return;

  const baseEndpoint = `/api/attack?key=${encodeURIComponent(currentUser.key)}&host=&port=&time=&method=`;
  const fullEndpoint = `${window.location.origin}${baseEndpoint}`;

  if ($('settings-api-key')) $('settings-api-key').textContent = maskKey(currentUser.key);
  if ($('settings-api-endpoint')) $('settings-api-endpoint').textContent = fullEndpoint;

  let revealed = false;
  if ($('settings-key-reveal-btn')) {
    $('settings-key-reveal-btn').onclick = () => {
      revealed = !revealed;
      $('settings-api-key').textContent = revealed ? currentUser.key : maskKey(currentUser.key);
      $('settings-key-reveal-btn').innerHTML = `${iconSvg(revealed ? 'eyeOff' : 'eye')} ${revealed ? 'Gizle' : 'Goster'}`;
    };
  }

  if ($('settings-key-copy-btn')) {
    $('settings-key-copy-btn').onclick = () => copyToClipboard(currentUser.key, $('settings-key-copy-btn'));
  }

  if ($('settings-endpoint-copy-btn')) {
    $('settings-endpoint-copy-btn').onclick = () => copyToClipboard(fullEndpoint, $('settings-endpoint-copy-btn'));
  }

  // Mevcut methodları ayarlar sayfasında listele
  const methodsList = $('settings-methods-list');
  if (methodsList && methods.length) {
    methodsList.innerHTML = methods.map(m => {
      const permBadges = [
        m.vip ? '<span class="method-badge badge-vip" style="font-size:10px;padding:2px 6px;">VIP</span>' : '',
        m.star ? '<span class="method-badge badge-star" style="font-size:10px;padding:2px 6px;">Star</span>' : '',
        m.admin ? '<span class="method-badge badge-admin" style="font-size:10px;padding:2px 6px;">Admin</span>' : ''
      ].filter(Boolean).join(' ');
      const targetFlags = [
        m.ip ? '<span style="color:var(--success);font-size:10px;">IP</span>' : '<span style="color:var(--text-muted);font-size:10px;text-decoration:line-through;">IP</span>',
        m.http ? '<span style="color:var(--success);font-size:10px;">HTTP</span>' : '<span style="color:var(--text-muted);font-size:10px;text-decoration:line-through;">HTTP</span>',
        m.https ? '<span style="color:var(--success);font-size:10px;">HTTPS</span>' : '<span style="color:var(--text-muted);font-size:10px;text-decoration:line-through;">HTTPS</span>'
      ].join(' ');
      const usable = canUseMethod(m);
      return `
      <div class="info-row" style="${usable ? '' : 'opacity:0.45;'}">
        <span class="info-key" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
          <span class="method-badge badge-get" style="${typeBadgeStyle(m.type)};font-size:10px;padding:2px 6px;">${escapeHtml(m.type)}</span>
          ${escapeHtml(m.name)} ${permBadges}
        </span>
        <span class="info-val" style="display:flex;align-items:center;gap:6px;">${targetFlags}</span>
      </div>
    `;
    }).join('');
  }
}

function logout() {
  clearSession();
  clearInterval(uptimeInterval);
  clearInterval(attackTicker);
  window.location.href = '/';
}

document.addEventListener('DOMContentLoaded', async () => {
  const saved = loadSession();
  if (!saved) {
    window.location.href = '/';
    return;
  }

  document.querySelectorAll('.nav-item[data-page]').forEach(el => {
    el.addEventListener('click', () => navigateTo(el.dataset.page));
  });

  $('logout-btn')?.addEventListener('click', logout);
  ['method-select', 'target-input', 'port-input', 'time-input'].forEach(id => {
    $(id)?.addEventListener('input', () => updateOngoingPanel(activeRequest ? 'running' : 'idle'));
    $(id)?.addEventListener('change', () => updateOngoingPanel(activeRequest ? 'running' : 'idle'));
  });
  $('send-api-btn')?.addEventListener('click', sendApiRequest);
  document.querySelectorAll('[data-attack-filter]').forEach(btn => {
    btn.addEventListener('click', () => setAttackFilter(btn.dataset.attackFilter));
  });

  try {
    await loadAppData();
    currentUser = await refreshSessionUser(saved);
    await refreshActiveAttacks();
    showDashboard(currentUser);
  } catch {
    logout();
  }
});
