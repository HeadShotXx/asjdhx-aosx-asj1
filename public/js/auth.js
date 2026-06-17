function showView(id) {
  ['view-landing', 'view-login'].forEach(v => {
    const el = $(v);
    if (el) el.style.display = 'none';
  });
  const target = $(id);
  if (target) target.style.display = '';
}

async function authenticate(key) {
  try {
    const data = await apiFetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: key.trim() })
    });
    return { user: data.user };
  } catch (err) {
    return { error: err.message };
  }
}

function initLogin() {
  const form = $('login-form');
  const input = $('key-input');
  const errorEl = $('login-error');
  const btn = $('login-btn');
  if (!form) return;

  const showError = (msg) => {
    errorEl.innerHTML = `${iconSvg('alert')} ${msg}`;
    errorEl.className = 'alert alert-error show';
  };

  const clearError = () => { errorEl.className = 'alert alert-error'; };

  input.addEventListener('input', clearError);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const key = input.value.trim();
    if (!key) { showError('Lütfen bir key girin.'); return; }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Doğrulanıyor...';

    const result = await authenticate(key);

    if (result.error) {
      showError(result.error);
      btn.disabled = false;
      btn.innerHTML = `<span class="btn-shimmer"></span>${iconSvg('bolt')} Giriş Yap`;
      return;
    }

    saveSession(result.user);
    window.location.href = '/dashboard';
  });
}

document.addEventListener('DOMContentLoaded', () => {
  if (loadSession()) {
    window.location.href = '/dashboard';
    return;
  }

  $('go-login')?.addEventListener('click', (e) => {
    e.preventDefault();
    showView('view-login');
    initLogin();
  });

  $('back-home')?.addEventListener('click', (e) => {
    e.preventDefault();
    showView('view-landing');
  });

  if (window.location.hash === '#login') {
    showView('view-login');
    initLogin();
  }
});
