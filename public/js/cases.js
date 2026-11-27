'use strict';
(async () => {
  await HAD.appShell('/cases.html');
  const ul = document.getElementById('cases');
  async function load() {
    const { cases } = await HAD.api('GET', '/api/cases');
    ul.innerHTML = '';
    if (!cases.length) ul.innerHTML = '<li class="empty">No cases yet. <a href="/report.html">Report a threat</a> to start one.</li>';
    for (const c of cases) {
      const li = document.createElement('li');
      const a = document.createElement('a'); a.className = 'item-link'; a.href = '/case.html?id=' + encodeURIComponent(c.id);
      a.innerHTML = '<div class="row between"><span class="t"></span><span class="row" data-b></span></div><div class="small muted"></div>';
      a.querySelector('.t').textContent = c.title;
      const b = a.querySelector('[data-b]');
      b.appendChild(HAD.badge(c.status === 'open' ? 'Open' : 'Closed', c.status === 'open' ? 'info' : 'plain'));
      if (c.legalHold) b.appendChild(HAD.badge('Legal hold', 'warn'));
      a.querySelector('.small').textContent = `${c.reportCount} report(s) · ${c.evidenceCount} evidence file(s) · updated ${HAD.fmtDate(c.updatedAt)}`;
      li.appendChild(a); ul.appendChild(li);
    }
  }
  await load();
  const form = document.getElementById('case-form');
  form.addEventListener('submit', async e => {
    e.preventDefault();
    try { const r = await HAD.api('POST', '/api/cases', HAD.formObject(form)); location.href = '/case.html?id=' + r.case.id; }
    catch (err) { HAD.alertBox('#msg', 'error', 'Could not create case', err.message); }
  });
})().catch(e => HAD.alertBox('#msg', 'error', 'Could not load cases', e.message));
