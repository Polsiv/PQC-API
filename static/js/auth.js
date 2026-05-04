const Auth = {
  getToken()   { return sessionStorage.getItem('pqc_token'); },
  getUserId()  { return sessionStorage.getItem('pqc_uid'); },
  getUsername(){ return sessionStorage.getItem('pqc_user'); },

  setSession(token, userId, username) {
    sessionStorage.setItem('pqc_token', token);
    sessionStorage.setItem('pqc_uid',   String(userId));
    sessionStorage.setItem('pqc_user',  username);
  },

  clearSession() {
    sessionStorage.removeItem('pqc_token');
    sessionStorage.removeItem('pqc_uid');
    sessionStorage.removeItem('pqc_user');
  },

  requireAuth() {
    if (!this.getToken()) {
      window.location.href = '/index.html';
      return false;
    }
    return true;
  },

  redirectIfAuth() {
    if (this.getToken()) window.location.href = '/dashboard.html';
  }
};
