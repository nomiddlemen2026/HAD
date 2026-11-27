'use strict';
(async () => {
  const me = await HAD.appShell('/account.html');
  const dl = document.getElementById('me');
  for (const [k, v] of [['Display name', me.displayName], ['Email', me.email], ['Role', me.role === 'user' ? 'Registered victim' : me.role]]) { const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = v; dl.append(dt, dd); }
  document.getElementById('logout').onclick = async () => { await HAD.api('POST', '/api/auth/logout', {}).catch(() => { }); location.href = '/'; };
  document.getElementById('delete-form').addEventListener('submit', async e => {
    e.preventDefault();
    if (!e.target.password.value) return HAD.alertBox('#msg', 'error', 'Password required', 'Enter your password to confirm.');
    if (!confirm('Permanently delete your account and all non-retained data?')) return;
    try {
      const r = await HAD.api('POST', '/api/account/delete', { password: e.target.password.value }, { redirectOn401: false });
      document.querySelector('main').innerHTML = '';
      const d = document.createElement('div'); d.className = 'card';
      d.innerHTML = '<h1>Account deleted</h1><p class="muted"></p><a class="btn" href="/">Back to home</a>';
      d.querySelector('p').textContent = `${r.casesPurged} case(s) deleted.` + (r.casesRetainedUnderLegalHold ? ` ${r.casesRetainedUnderLegalHold} case(s) kept under legal hold, without your personal details.` : '');
      document.querySelector('main').appendChild(d);
    } catch (err) { HAD.alertBox('#msg', 'error', 'Could not delete', err.message); }
  });
})();
