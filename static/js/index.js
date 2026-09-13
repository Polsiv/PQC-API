Auth.redirectIfAuth();

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

function showAlert(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.add('show');
}
function hideAlert(id) { document.getElementById(id).classList.remove('show'); }

// Login
async function doLogin() {
  hideAlert('login-alert');
  const u = document.getElementById('login-user').value.trim();
  const p = document.getElementById('login-pass').value;
  if (!u || !p) { showAlert('login-alert', 'Username and password are required'); return; }

  const btn = document.getElementById('login-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Signing in…';

  const { ok, data } = await Api.login(u, p);

  btn.disabled = false;
  btn.textContent = 'Login';

  if (!ok) { showAlert('login-alert', data.error || 'Login failed'); return; }

  Auth.setSession(data.token, data.user_id, u);

  // Fetch the role so the dashboard can reveal admin-only UI.
  const me = await Api.me();
  Auth.setRole(me.ok ? me.data.role : 0);

  window.location.href = '/dashboard.html';
}

document.getElementById('login-btn').addEventListener('click', doLogin);
['login-user', 'login-pass'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  });
});

// Register
async function doRegister() {
  hideAlert('reg-alert');
  hideAlert('reg-success');
  const u = document.getElementById('reg-user').value.trim();
  const p = document.getElementById('reg-pass').value;
  if (!u || !p) { showAlert('reg-alert', 'Username and password are required'); return; }

  const btn = document.getElementById('reg-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Creating account…';

  const { ok, data } = await Api.register(u, p);

  btn.disabled = false;
  btn.textContent = 'Create Account';

  if (!ok) { showAlert('reg-alert', data.error || 'Registration failed'); return; }

  showAlert('reg-success', 'Account created! Redirecting to login…');
  document.getElementById('reg-user').value = '';
  document.getElementById('reg-pass').value = '';
  setTimeout(() => document.querySelector('[data-tab="login"]').click(), 1500);
}

document.getElementById('reg-btn').addEventListener('click', doRegister);
['reg-user', 'reg-pass'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', e => {
    if (e.key === 'Enter') doRegister();
  });
});
