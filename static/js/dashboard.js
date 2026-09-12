function toast(msg, type = 'success') {
  const c  = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className   = `toast toast-${type}`;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function fmtDate(s) {
  return new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function trunc(s, n = 16) {
  return s && s.length > n ? s.slice(0, n) + '…' : s;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Document list ─────────────────────────────────────────────────

let docs = [];

async function loadDocuments() {
  const { ok, data } = await Api.listDocuments();
  if (!ok) { toast('Failed to load documents', 'error'); return; }

  docs = data.documents || [];
  document.getElementById('doc-count').textContent = docs.length;
  renderTable();
}

function renderTable() {
  const tbody = document.getElementById('doc-tbody');

  if (docs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5">
      <div class="empty-state">
        <div class="icon"><img src="/assets/icons/file.png" class="icon-img" alt=""></div>
        <p>No documents yet — upload a PDF above to get started</p>
      </div>
    </td></tr>`;
    return;
  }

  tbody.innerHTML = docs.map(d => `
    <tr>
      <td>${d.id}</td>
      <td>${escHtml(d.filename)}</td>
      <td>${fmtDate(d.signed_at)}</td>
      <td class="mono" title="${escHtml(d.sha256)}">${trunc(d.sha256)}</td>
      <td>
        <button class="btn btn-sm btn-primary"
          onclick="downloadDoc(${d.id}, '${escHtml(d.filename)}')">Download</button>
        <button class="btn btn-sm btn-ghost"
          onclick="openVerify(${d.id}, '${escHtml(d.filename)}')">Verify</button>
        <button class="btn btn-sm btn-ghost"
          onclick="deleteDoc(${d.id}, '${escHtml(d.filename)}')">Delete</button>
      </td>
    </tr>
  `).join('');
}

async function downloadDoc(id, filename) {
  await Api.downloadDocument(id, filename);
}

async function deleteDoc(id, filename) {
  if (!confirm(`Delete "${filename}"? This cannot be undone.`)) return;

  const { ok, data } = await Api.deleteDocument(id);
  if (!ok) {
    toast(data.error || 'Delete failed', 'error');
    return;
  }
  toast(`Deleted: ${filename}`, 'success');
  await loadDocuments();
}

async function openVerify(id, filename) {
  const modal  = document.getElementById('verify-modal');
  const title  = document.getElementById('verify-modal-filename');
  const result = document.getElementById('verify-result');

  title.textContent = filename;
  result.className  = 'verify-result';
  result.innerHTML  = '<div style="text-align:center;padding:1rem;color:var(--muted)"><span class="spinner" style="border-color:rgba(0,0,0,.15);border-top-color:var(--primary)"></span> Verifying…</div>';
  modal.classList.add('open');

  const { ok, data } = await Api.verifyDocument(id);

  if (!ok) {
    result.className = 'verify-result invalid';
    result.innerHTML = `<div class="verify-icon"><img src="/assets/icons/warning.png" class="icon-img" alt="Error"></div>
      <div class="verify-label" style="color:var(--error)">Error</div>
      <div class="verify-algo">${escHtml(data.error || 'Unknown error')}</div>`;
    return;
  }

  if (data.valid) {
    result.className = 'verify-result valid';
    result.innerHTML = `
      <div class="verify-icon"><img src="/assets/icons/checkmark.png" class="icon-img" alt="Valid"></div>
      <div class="verify-label" style="color:var(--success)">Signature Valid</div>
      <div class="verify-algo">${escHtml(data.algorithm)} · ${trunc(data.sha256, 20)}</div>`;
  } else {
    result.className = 'verify-result invalid';
    result.innerHTML = `
      <div class="verify-icon"><img src="/assets/icons/cross.png" class="icon-img" alt="Invalid"></div>
      <div class="verify-label" style="color:var(--error)">Invalid Signature</div>
      <div class="verify-algo">${escHtml(data.algorithm)}</div>`;
  }
}

// ── Upload / sign ─────────────────────────────────────────────────

let selectedFile = null;

function setupDropZone() {
  const zone  = document.getElementById('drop-zone');
  const input = document.getElementById('file-input');

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('over');
    if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', () => {
    if (input.files[0]) setFile(input.files[0]);
  });
}

function setFile(f) {
  selectedFile = f;
  document.getElementById('file-name').textContent = f.name;
  document.getElementById('sign-btn').disabled = false;
}

async function signDocument() {
  if (!selectedFile) return;

  const btn = document.getElementById('sign-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Signing…';

  const { ok, data } = await Api.signDocument(selectedFile);

  btn.disabled = false;
  btn.textContent = 'Sign Document';

  if (!ok) {
    toast(data.error || 'Signing failed', 'error');
    return;
  }

  toast(`Signed: ${data.filename} (doc #${data.doc_id})`, 'success');
  selectedFile = null;
  document.getElementById('file-name').textContent = '';
  document.getElementById('file-input').value = '';
  btn.disabled = true;
  await loadDocuments();
  openSigModal(data.signature, data.filename);
}

function openSigModal(signature, filename) {
  document.getElementById('sig-modal-filename').textContent = filename;
  document.getElementById('sig-box').value = signature;
  document.getElementById('sig-modal').classList.add('open');
}

// ── Init ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  if (!Auth.requireAuth()) return;

  document.getElementById('nav-user').textContent = Auth.getUsername() || 'User';

  // Reveal the admin link only for admins. Refresh role from the server so a
  // change of role reflects without requiring a fresh login.
  Api.me().then(({ ok, data }) => {
    if (ok && data.role !== undefined) Auth.setRole(data.role);
    if (Auth.isAdmin()) document.getElementById('admin-link').style.display = '';
  });

  document.getElementById('logout-btn').addEventListener('click', async () => {
    // Revoke server-side, but log out locally regardless of the result so a
    // failed/slow request never leaves the user stuck on the dashboard.
    try { await Api.logout(); } catch (_) { /* ignore */ }
    Auth.clearSession();
    window.location.href = '/index.html';
  });

  document.getElementById('sign-btn').addEventListener('click', signDocument);

  document.getElementById('sig-modal-close').addEventListener('click', () => {
    document.getElementById('sig-modal').classList.remove('open');
  });
  document.getElementById('sig-modal').addEventListener('click', e => {
    if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
  });
  document.getElementById('sig-copy-btn').addEventListener('click', () => {
    const btn = document.getElementById('sig-copy-btn');
    navigator.clipboard.writeText(document.getElementById('sig-box').value).then(() => {
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy Signature'; }, 2000);
    });
  });

  document.getElementById('modal-close').addEventListener('click', () => {
    document.getElementById('verify-modal').classList.remove('open');
  });
  document.getElementById('verify-modal').addEventListener('click', e => {
    if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
  });

  setupDropZone();
  await loadDocuments();
});
