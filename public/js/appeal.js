'use strict';
HAD.publicNav('/appeal.html');
const form = document.getElementById('appeal-form');
const pre = HAD.qs('phone'); if (pre) form.phone.value = pre;
form.addEventListener('submit', async e => {
  e.preventDefault();
  for (const el of form.querySelectorAll('[required]')) {
    if (!el.value.trim() || (el.name === 'reason' && el.value.trim().length < 20)) { el.setAttribute('aria-invalid', 'true'); el.focus(); return HAD.alertBox('#msg', 'error', 'Missing information', el.name === 'reason' ? 'Please explain your reason in at least 20 characters.' : 'Please fill in every field.'); }
    el.removeAttribute('aria-invalid');
  }
  try { const r = await HAD.api('POST', '/api/appeals', HAD.formObject(form)); form.remove(); HAD.alertBox('#msg', 'success', 'Request received', r.message + ' Reference: ' + r.id.slice(0, 8)); }
  catch (err) { HAD.alertBox('#msg', 'error', 'Could not send', err.message); }
});
