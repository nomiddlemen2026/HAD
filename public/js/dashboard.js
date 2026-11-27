'use strict';
(async () => {
  const me = await HAD.appShell('/dashboard.html');
  if (HAD.qs('welcome')) HAD.alertBox('#msg', 'success', `Welcome, ${me.displayName}`, 'Your account is private. Start by reporting the number that is threatening you.');
  const s = await HAD.api('GET', '/api/me/summary');
  const st = s.reportsByStatus;
  const stats = [
    ['Open cases', s.openCases], ['Numbers you reported', s.numbersReported],
    ['Awaiting review', st.pending_review || 0], ['Evidence files', s.evidence],
  ];
  const box = document.getElementById('stats');
  for (const [k, v] of stats) { const d = document.createElement('div'); d.className = 'stat'; d.innerHTML = '<div class="v"></div><div class="k"></div>'; d.querySelector('.v').textContent = v; d.querySelector('.k').textContent = k; box.appendChild(d); }
  if (s.staff) {
    const el = document.getElementById('staff'); el.classList.remove('hidden');
    el.innerHTML = '<div class="card"><h2>Moderation <a class="small" href="/mod.html">Open queue</a></h2><div class="grid cols-3" data-g></div></div>';
    for (const [k, v] of [['Reports awaiting review', s.staff.pendingReview], ['Open correction requests', s.staff.openAppeals], ['Published reports', s.staff.published]]) {
      const d = document.createElement('div'); d.className = 'stat'; d.innerHTML = '<div class="v"></div><div class="k"></div>'; d.querySelector('.v').textContent = v; d.querySelector('.k').textContent = k; el.querySelector('[data-g]').appendChild(d);
    }
  }
  const ul = document.getElementById('recent');
  if (!s.recentReports.length) ul.innerHTML = '<li class="empty">No reports yet. <a href="/report.html">Report a threat</a>.</li>';
  for (const r of s.recentReports) {
    const li = document.createElement('li');
    const a = document.createElement('a'); a.className = 'item-link'; a.href = '/case.html?id=' + encodeURIComponent(r.caseId);
    a.innerHTML = '<div class="row between"><span class="t mono"></span><span data-b></span></div><div class="small muted"></div>';
    a.querySelector('.t').textContent = r.phone;
    a.querySelector('[data-b]').appendChild(HAD.statusBadge('reportStatus', r.status));
    a.querySelector('.small').textContent = `${HAD.LABELS.category[r.category]} · ${HAD.LABELS.channel[r.channel]} · ${HAD.fmtDate(r.createdAt)}`;
    li.appendChild(a); ul.appendChild(li);
  }
  renderSearch(document.getElementById('search-root'));
})().catch(e => HAD.alertBox('#msg', 'error', 'Could not load dashboard', e.message));
