'use strict';
(async () => {
  const me = await HAD.appShell('/mod.html');
  const msg = document.getElementById('msg');
  if (me.role === 'user') { HAD.alertBox(msg, 'error', 'Staff only', 'You do not have access to moderation.'); return; }
  document.querySelectorAll('.tabs button').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach(x => x.setAttribute('aria-selected', x === b));
    document.querySelectorAll('[data-panel]').forEach(p => p.classList.toggle('hidden', p.dataset.panel !== b.dataset.tab));
  }));
  const CHECKS = ['The evidence supports what the report says', 'The summary contains no names, addresses, IC numbers, phone numbers or links', 'The summary describes conduct reported, not guilt'];

  async function loadQueue() {
    const { reports } = await HAD.api('GET', '/api/mod/queue');
    const box = document.getElementById('queue'); box.innerHTML = '';
    if (!reports.length) box.innerHTML = '<div class="card empty">The review queue is empty.</div>';
    for (const r of reports) {
      const card = document.createElement('div'); card.className = 'card';
      card.innerHTML = `<div class="row between"><span class="t mono"></span><span class="row" data-b></span></div>
        <div class="small muted" data-meta style="margin:4px 0 10px"></div>
        <div class="small faint">Private victim statement (never published):</div><p data-desc style="white-space:pre-wrap"></p>
        <div class="row small" style="margin-bottom:12px"><a data-case class="btn sm">Open case &amp; evidence</a></div>
        <form novalidate>
          <div class="field"><label>Public summary (written by you)</label><textarea name="publicSummary" maxlength="500" rows="3" placeholder="e.g. Reported for repeated loan collection intimidation over WhatsApp, including threats to visit the victim's home."></textarea><div class="hint">20 to 500 characters. Automatically blocked if it contains personal data.</div></div>
          <div class="field" data-checks></div>
          <div class="field"><label>Internal note <span class="opt">(optional)</span></label><input name="note" type="text" maxlength="2000"></div>
          <div class="row"><button class="btn primary" value="publish">Publish (masked)</button><button class="btn danger" value="reject">Reject</button></div>
        </form>`;
      card.querySelector('.t').textContent = r.phone;
      const b = card.querySelector('[data-b]');
      b.append(HAD.badge(HAD.LABELS.category[r.category], 'purple'), HAD.badge(r.evidenceCount + ' evidence', r.evidenceCount ? 'ok' : 'danger'));
      card.querySelector('[data-meta]').textContent = `${HAD.LABELS.channel[r.channel]} · submitted ${HAD.fmtDate(r.createdAt)} · reporter has ${r.reporterTotalReports} report(s), account since ${HAD.fmtDate(r.reporterSince)}`;
      card.querySelector('[data-desc]').textContent = r.description;
      card.querySelector('[data-case]').href = '/case.html?id=' + encodeURIComponent(r.caseId);
      const checks = card.querySelector('[data-checks]');
      for (const c of CHECKS) { const l = document.createElement('label'); l.className = 'check small'; l.innerHTML = '<input type="checkbox" data-check> <span></span>'; l.querySelector('span').textContent = c; checks.appendChild(l); }
      const form = card.querySelector('form');
      form.addEventListener('submit', e => e.preventDefault());
      form.querySelectorAll('button').forEach(btn => btn.addEventListener('click', async ev => {
        ev.preventDefault();
        const decision = btn.value;
        if (decision === 'publish' && [...form.querySelectorAll('[data-check]')].some(x => !x.checked)) return HAD.alertBox(msg, 'error', 'Checklist incomplete', 'Confirm every check before publishing.');
        try {
          await HAD.api('POST', `/api/mod/reports/${r.id}/decision`, { decision, publicSummary: form.publicSummary.value, note: form.note.value });
          HAD.alertBox(msg, 'success', decision === 'publish' ? 'Published' : 'Rejected', ''); await loadQueue();
        } catch (err) { HAD.alertBox(msg, 'error', 'Could not save decision', err.message); window.scrollTo(0, 0); }
      }));
      box.appendChild(card);
    }
  }

  async function loadAppeals() {
    const { appeals } = await HAD.api('GET', '/api/mod/appeals');
    const box = document.getElementById('appeals'); box.innerHTML = '';
    if (!appeals.length) box.innerHTML = '<div class="card empty">No correction or takedown requests.</div>';
    for (const a of appeals) {
      const card = document.createElement('div'); card.className = 'card';
      card.innerHTML = `<div class="row between"><span class="t"></span><span class="row" data-b></span></div>
        <div class="small muted" data-meta style="margin:4px 0 8px"></div><p data-reason style="white-space:pre-wrap"></p>
        <div class="small faint" data-pub></div>
        <form class="row" style="margin-top:10px" novalidate><input name="note" type="text" maxlength="2000" placeholder="Resolution note (required)" style="flex:1;min-width:200px"><button class="btn sm primary" value="upheld">Uphold</button><button class="btn sm danger" value="rejected">Reject</button></form>`;
      card.querySelector('.t').textContent = `${a.type[0].toUpperCase() + a.type.slice(1)} · ${a.phone}`;
      card.querySelector('[data-b]').appendChild(HAD.badge(a.status, a.status === 'open' ? 'warn' : a.status === 'upheld' ? 'ok' : 'plain'));
      card.querySelector('[data-meta]').textContent = `From ${a.requester_name} (${a.requester_contact}) · ${HAD.fmtDate(a.created_at)}${a.resolution_note ? ' · resolved: ' + a.resolution_note : ''}`;
      card.querySelector('[data-reason]').textContent = a.reason;
      card.querySelector('[data-pub]').textContent = a.published.length ? `${a.published.length} published report(s) on this number. Upholding an appeal or takedown removes them from public search.` : 'No published reports on this number.';
      const form = card.querySelector('form');
      if (a.status !== 'open') form.remove();
      else form.querySelectorAll('button').forEach(btn => btn.addEventListener('click', async ev => {
        ev.preventDefault();
        try { const r = await HAD.api('POST', `/api/mod/appeals/${a.id}/decision`, { decision: btn.value, note: form.note.value }); HAD.alertBox(msg, 'success', 'Saved', r.takenDown ? `${r.takenDown} report(s) taken down.` : ''); await loadAppeals(); }
        catch (err) { HAD.alertBox(msg, 'error', 'Could not save', err.message); }
      }));
      box.appendChild(card);
    }
  }
  async function loadLocations() {
    const { locations } = await HAD.api('GET', '/api/mod/locations');
    const box = document.getElementById('mod-locations'); box.innerHTML = '';
    if (!locations.length) box.innerHTML = '<div class="card empty">No location records yet.</div>';
    for (const l of locations) {
      const card = document.createElement('div'); card.className = 'card';
      card.innerHTML = `<div class="row between"><span class="t"></span><span class="row" data-b></span></div>
        <div class="small muted" data-a style="margin:4px 0"></div><div class="small faint" data-s></div>
        <div class="row small" style="margin:8px 0"><a data-case class="btn sm">Open case</a><a data-ev class="btn sm hidden">Open evidence</a></div>
        <form class="row" novalidate>
          <select name="verificationStatus" style="max-width:220px"></select>
          <label class="check small" data-cv><input type="checkbox" name="communityVisible"> <span>Show on community map</span></label>
          <button class="btn sm primary">Save</button>
        </form><div class="hint" data-why></div>`;
      card.querySelector('.t').textContent = l.label;
      const b = card.querySelector('[data-b]');
      b.append(HAD.statusBadge('verification', l.verificationStatus), HAD.badge(HAD.LABELS.location[l.category], 'plain'));
      if (l.isPrivateResidence) b.appendChild(HAD.badge('Private home', 'warn'));
      if (l.isVictimLocation) b.appendChild(HAD.badge('Victim location', 'info'));
      if (l.communityVisible) b.appendChild(HAD.badge('On community map', 'ok'));
      card.querySelector('[data-a]').textContent = [l.addressText, l.lat != null ? `${l.lat}, ${l.lng} (${l.precision})` : 'no coordinates', l.country, 'case: ' + l.caseTitle].filter(Boolean).join(' · ');
      card.querySelector('[data-s]').textContent = `Source: ${l.sourceReference} · reliability ${l.sourceReliability} · collected ${HAD.fmtDate(l.collectedAt)}${l.lastVerifiedAt ? ' · last verified ' + HAD.fmtDate(l.lastVerifiedAt) : ''}`;
      card.querySelector('[data-case]').href = '/case.html?id=' + encodeURIComponent(l.caseId);
      if (l.evidenceId) { const a = card.querySelector('[data-ev]'); a.href = '/evidence.html?id=' + encodeURIComponent(l.evidenceId); a.classList.remove('hidden'); }
      const form = card.querySelector('form');
      HAD.fillSelect(form.verificationStatus, HAD.LABELS.verification);
      form.verificationStatus.value = l.verificationStatus;
      form.communityVisible.checked = l.communityVisible;
      if (!l.communityEligible) { card.querySelector('[data-cv]').classList.add('hidden'); card.querySelector('[data-why]').textContent = 'Not eligible for the community map.'; }
      form.addEventListener('submit', async e => {
        e.preventDefault();
        try { await HAD.api('POST', `/api/mod/locations/${l.id}/verify`, { verificationStatus: form.verificationStatus.value, communityVisible: form.communityVisible.checked }); HAD.alertBox(msg, 'success', 'Location updated', ''); await loadLocations(); }
        catch (err) { HAD.alertBox(msg, 'error', 'Could not update location', err.message); window.scrollTo(0, 0); }
      });
      box.appendChild(card);
    }
  }
  await Promise.all([loadQueue(), loadAppeals(), loadLocations()]);
})().catch(e => HAD.alertBox('#msg', 'error', 'Could not load moderation', e.message));
