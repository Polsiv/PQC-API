function toast(msg, type = 'success') {
  const c  = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className   = `toast toast-${type}`;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

let selectedFile = null;

function setFile(f) {
  selectedFile = f;
  document.getElementById('file-name').textContent = f.name;
}

document.addEventListener('DOMContentLoaded', () => {
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

  document.getElementById('fetch-key-btn').addEventListener('click', async () => {
    const btn = document.getElementById('fetch-key-btn');
    btn.disabled = true;
    btn.textContent = 'Fetching…';
    const { ok, data } = await Api.getPublicKey();
    btn.disabled = false;
    btn.textContent = 'Fetch Server Key';
    if (!ok) { toast('Failed to fetch public key', 'error'); return; }
    document.getElementById('public-key').value = data.public_key_pem;
    toast('Server public key loaded', 'success');
  });

  document.getElementById('verify-form').addEventListener('submit', async e => {
    e.preventDefault();

    if (!selectedFile) { toast('Please select a PDF', 'error'); return; }
    const sig = document.getElementById('signature').value.trim();
    const key = document.getElementById('public-key').value.trim();
    if (!sig) { toast('Please paste the signature', 'error'); return; }
    if (!key) { toast('Please enter the public key', 'error'); return; }

    const btn    = document.getElementById('verify-btn');
    const result = document.getElementById('verify-result');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Verifying…';
    result.style.display = 'none';

    const { ok, data } = await Api.verifyExternal(selectedFile, sig, key);

    btn.disabled = false;
    btn.textContent = 'Verify Signature';
    result.style.display = 'block';

    if (!ok) {
      result.className = 'verify-result invalid';
      result.innerHTML = `<div class="verify-icon">⚠️</div>
        <div class="verify-label" style="color:var(--error)">Error</div>
        <div class="verify-algo">${data.error || 'Verification failed'}</div>`;
      return;
    }

    if (data.valid) {
      result.className = 'verify-result valid';
      result.innerHTML = `
        <div class="verify-icon"><img src="/assets/icons/checkmark.png" class="icon-img" alt="Valid"></div>
        <div class="verify-label" style="color:var(--success)">Signature Valid</div>
        <div class="verify-algo">${data.algorithm || 'ML-DSA-65'}</div>`;
    } else {
      result.className = 'verify-result invalid';
      result.innerHTML = `
        <div class="verify-icon"><img src="/assets/icons/cross.png" class="icon-img" alt="Invalid"></div>
        <div class="verify-label" style="color:var(--error)">Invalid Signature</div>
        <div class="verify-algo">${data.algorithm || 'ML-DSA-65'}</div>`;
    }
  });
});
