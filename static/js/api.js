const Api = {
  _h() {
    const t = Auth.getToken();
    return t ? { Authorization: `Bearer ${t}` } : {};
  },

  async register(username, password) {
    const r = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    return { ok: r.ok, data: await r.json() };
  },

  async login(username, password) {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    return { ok: r.ok, data: await r.json() };
  },

  async logout() {
    await fetch('/api/users/logout', { method: 'POST', headers: this._h() });
  },

  async listDocuments() {
    const r = await fetch('/api/documents', { headers: this._h() });
    return { ok: r.ok, data: await r.json() };
  },

  async signDocument(file) {
    const fd = new FormData();
    fd.append('file', file);
    const r = await fetch('/api/documents/sign', {
      method: 'POST',
      headers: this._h(),
      body: fd
    });
    return { ok: r.ok, data: await r.json() };
  },

  async downloadDocument(id, filename) {
    const r = await fetch(`/api/documents/${id}/download`, { headers: this._h() });
    if (!r.ok) return;
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  },

  async verifyDocument(id) {
    const r = await fetch(`/api/documents/${id}/verify`, {
      method: 'POST',
      headers: this._h()
    });
    return { ok: r.ok, data: await r.json() };
  },

  async getPublicKey() {
    const r = await fetch('/api/documents/public-key');
    return { ok: r.ok, data: await r.json() };
  },

  async verifyExternal(file, signature, publicKey) {
    const fd = new FormData();
    fd.append('pdf',        file);
    fd.append('signature',  signature.trim());
    fd.append('public_key', publicKey.trim());
    const r = await fetch('/api/documents/verify', { method: 'POST', body: fd });
    return { ok: r.ok, data: await r.json() };
  }
};
