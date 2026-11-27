'use strict';
HAD.publicNav('');
document.querySelector('.footer')?.remove();
const msg = document.getElementById('msg');
const safeNext = () => { const n = HAD.qs('next'); return n && n.startsWith('/') && !n.startsWith('//') ? n : '/dashboard.html'; };
if (HAD.qs('expired')) HAD.alertBox(msg, 'warn', 'Your session expired', 'Please log in again. Anything you were typing is still saved in this browser.');

function bind(id, fn) {
  const form = document.getElementById(id);
  if (!form) return;
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = form.querySelector('button[type=submit]');
    for (const el of form.querySelectorAll('[required]')) {
      if ((el.type === 'checkbox' && !el.checked) || (el.type !== 'checkbox' && !el.value.trim())) {
        el.setAttribute('aria-invalid', 'true'); el.focus();
        return HAD.alertBox(msg, 'error', 'Missing information', el.type === 'checkbox' ? 'Please accept the terms to continue.' : 'Please fill in every field.');
      }
      el.removeAttribute('aria-invalid');
    }
    btn.disabled = true;
    try { await fn(HAD.formObject(form), form); }
    catch (err) { HAD.alertBox(msg, 'error', null, err.message); HAD.markInvalid(form, err); }
    finally { btn.disabled = false; }
  });
}
bind('login-form', async d => { await HAD.api('POST', '/api/auth/login', d, { redirectOn401: false }); location.href = safeNext(); });
bind('register-form', async d => { await HAD.api('POST', '/api/auth/register', d); location.href = '/dashboard.html?welcome=1'; });
bind('forgot-form', async d => { const r = await HAD.api('POST', '/api/auth/forgot', d); HAD.alertBox(msg, 'success', 'Check your email', r.message); });
bind('reset-form', async d => {
  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  if (!token) throw new Error('This page needs the link from your reset email.');
  const r = await HAD.api('POST', '/api/auth/reset', { token, password: d.password });
  HAD.alertBox(msg, 'success', 'Password updated', r.message + ' ');
  const a = document.createElement('a'); a.href = '/login.html'; a.textContent = 'Go to log in'; msg.firstChild.appendChild(a);
  document.getElementById('reset-form').remove();
});
