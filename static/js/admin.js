function toast(msg, type = 'success') {
  const c  = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className   = `toast toast-${type}`;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Map a component status to a CSS modifier class.
function statusClass(s) {
  if (s === 'UP')       return 'up';
  if (s === 'DEGRADED') return 'degraded';
  return 'down';
}

// Human-friendly component names and a line of supporting detail.
const LABELS = {
  api_server: 'API Server',
  tls:        'TLS Layer'
};

function detailLine(key, c) {
  const bits = [];
  if (key === 'tls') {
    if (c.version) bits.push(`TLS ${c.version}`);
    if (typeof c.days_until_expiry === 'number') bits.push(`cert expires in ${c.days_until_expiry}d`);
  }
  if (c.detail) bits.push(c.detail);
  return bits.join(' · ');
}

let timer = null;

async function loadHealth() {
  const { ok, status, data } = await Api.adminHealth();

  // Session expired — bounce to login.
  if (status === 401) { Auth.clearSession(); window.location.href = '/index.html'; return; }
  // Lost admin rights mid-session — back to the dashboard.
  if (status === 403) { window.location.href = '/dashboard.html'; return; }

  if (!data || !data.components) {
    toast('Failed to load system health', 'error');
    return;
  }

  renderOverall(data.status);
  renderMeta(data.timestamp);
  renderComponents(data.components);
}

function renderOverall(status) {
  const el = document.getElementById('overall');
  el.className = `health-overall health-${statusClass(status)}`;
  const icon = status === 'UP'
    ? '<img src="/assets/icons/checkmark.png" class="icon-img" alt="UP">'
    : (status === 'DEGRADED'
        ? '<img src="/assets/icons/warning.png" class="icon-img" alt="DEGRADED">'
        : '<img src="/assets/icons/null.png" class="icon-img" alt="DOWN">');
  el.innerHTML = `<span class="health-dot"></span>
    <span class="health-overall-icon">${icon}</span>
    <span class="health-overall-text">${escHtml(status)}</span>`;
}

function renderMeta(serverTs) {
  const now = new Date().toLocaleTimeString(undefined, { timeStyle: 'medium' });
  const parts = [`Last checked ${now}`];
  if (serverTs) parts.push(`server time ${escHtml(serverTs)}`);
  document.getElementById('health-meta').textContent = parts.join(' · ');
}

function renderComponents(components) {
  const grid = document.getElementById('health-grid');
  grid.innerHTML = Object.keys(LABELS).map(key => {
    const c = components[key];
    if (!c) return '';
    const cls    = statusClass(c.status);
    const label  = LABELS[key];
    const detail = detailLine(key, c);
    return `
      <div class="health-card health-${cls}">
        <div class="health-card-head">
          <span class="health-name">${escHtml(label)}</span>
          <span class="health-pill health-pill-${cls}">${escHtml(c.status)}</span>
        </div>
        <div class="health-detail">${escHtml(detail) || '&nbsp;'}</div>
      </div>`;
  }).join('');
}

document.addEventListener('DOMContentLoaded', async () => {
  // Gate: verifies auth and refreshes role from the server; non-admins are
  // redirected to the dashboard. The server still enforces the real 403.
  if (!(await Auth.requireAdmin())) return;

  document.getElementById('nav-user').textContent = Auth.getUsername() || 'User';

  document.getElementById('logout-btn').addEventListener('click', async () => {
    await Api.logout();
    Auth.clearSession();
    window.location.href = '/index.html';
  });

  document.getElementById('refresh-btn').addEventListener('click', loadHealth);

  await loadHealth();

  // Auto-refresh every 10s while the tab is visible.
  timer = setInterval(() => {
    if (!document.hidden) loadHealth();
  }, 10000);
});

window.addEventListener('beforeunload', () => { if (timer) clearInterval(timer); });
