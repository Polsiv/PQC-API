const Auth = {
  getToken()   { return sessionStorage.getItem('pqc_token'); },
  getUserId()  { return sessionStorage.getItem('pqc_uid'); },
  getUsername(){ return sessionStorage.getItem('pqc_user'); },
  getRole()    { return sessionStorage.getItem('pqc_role') || '0'; },
  isAdmin()    { return Number(this.getRole()) === 1; },

  setSession(token, userId, username) {
    sessionStorage.setItem('pqc_token', token);
    sessionStorage.setItem('pqc_uid',   String(userId));
    sessionStorage.setItem('pqc_user',  username);
  },

  setRole(role) {
    // role is an integer: 0 = user, 1 = admin
    sessionStorage.setItem('pqc_role', String(role ?? 0));
  },

  clearSession() {
    sessionStorage.removeItem('pqc_token');
    sessionStorage.removeItem('pqc_uid');
    sessionStorage.removeItem('pqc_user');
    sessionStorage.removeItem('pqc_role');
  },

  requireAuth() {
    if (!this.getToken()) {
      window.location.href = '/index.html';
      return false;
    }
    return true;
  },

  // Client-side convenience gate only — the server's /api/admin/* endpoints
  // enforce the real 403. Refreshes the cached role from the server so a
  // promotion/demotion takes effect without needing to log in again.
  async requireAdmin() {
    if (!this.requireAuth()) return false;
    const { ok, data } = await Api.me();
    if (ok && data.role !== undefined) this.setRole(data.role);
    if (!this.isAdmin()) {
      window.location.href = '/dashboard.html';
      return false;
    }
    return true;
  },

  redirectIfAuth() {
    if (this.getToken()) window.location.href = '/dashboard.html';
  }
};
