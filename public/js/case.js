'use strict';
(async () => {
  const me = await HAD.appShell('/cases.html');
  const id = HAD.qs('id');
  const msg = document.getElementById('msg');
  if (HAD.qs('submitted')) HAD.alertBox(msg, 'success', 'Report saved privately', 'A moderator will review it before anything is published. You can keep adding evidence here.' + (HAD.qs('warn') ? ' Note: ' + HAD.qs('warn') : ''));
  document.querySelectorAll('.tabs button').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach(x => x.setAttribute('aria-selected', x === b));
    document.querySelectorAll('[data-panel]').forEach(p => p.classList.toggle('hidden', p.dataset.panel !== b.dataset.tab));
  }));
  const lcat = document.getElementById('lcat');
  const locLabels = { ...HAD.LABELS.location };
  if (me.role === 'user') delete locLabels.officially_confirmed_suspect_location;
  HAD.fillSelect(lcat, locLabels);
  const HINTS = {
    incident_location: 'Where the incident took place, e.g. where paint was splashed.',
    location_mentioned_in_threat: 'A place named in a threat. Often the victim\'s place, not the sender\'s.',
    voluntarily_shared_location: 'A location someone chose to share, e.g. a WhatsApp live location.',
    public_business_address: 'A published business address, e.g. from an advertisement or company registry.',
    approximate_network_location: 'IP-based estimates are often wrong. Saved as a rough area with low reliability only.',
    officially_confirmed_suspect_location: 'Staff only. Requires an official source such as a police statement.',
  };
  const setHint = () => { document.getElementById('lcat-hint').textContent = HINTS[lcat.value] || ''; };
  lcat.addEventListener('change', setHint); setHint();

  let data;
  async function load() {
    data = await HAD.api('GET', '/api/cases/' + encodeURIComponent(id));
    const c = data.case;
    document.title = c.title + ' · H.A.D';
    document.getElementById('title').textContent = c.title;
    document.getElementById('sub').textContent = `${c.status === 'open' ? 'Open' : 'Closed'} · opened ${HAD.fmtDate(c.createdAt)}${c.legalHold ? ' · under legal hold' : ''}`;
    document.getElementById('add-report').href = '/report.html?case=' + encodeURIComponent(c.id);
    const f = document.getElementById('case-edit'); f.title.value = c.title; f.description.value = c.description; f.status.value = c.status;
    // reports
    const ul = document.getElementById('reports'); ul.innerHTML = '';
    if (!data.reports.length) ul.innerHTML = '<li class="empty">No reports in this case yet.</li>';
    for (const r of data.reports) {
      const li = document.createElement('li');
      li.innerHTML = `<div class="row between"><span class="t mono"></span><span data-b></span></div>
        <div class="row small muted" style="margin:4px 0 8px" data-meta></div><p class="desc" style="white-space:pre-wrap;margin:0 0 8px"></p>
        <dl class="kv small" data-extra></dl><div class="row" style="margin-top:8px" data-actions></div>`;
      li.querySelector('.t').textContent = r.phone;
      li.querySelector('[data-b]').appendChild(HAD.statusBadge('reportStatus', r.status));
      li.querySelector('[data-meta]').textContent = `${HAD.LABELS.category[r.category]} · ${HAD.LABELS.channel[r.channel]} · ${r.incidentAt ? 'incident ' + r.incidentAt.replace('T', ' ') : 'no incident date'} · issued in ${r.numberingRegion || '?'}`;
      li.querySelector('.desc').textContent = r.description;
      const dl = li.querySelector('[data-extra]');
      const kv = (k, v) => { if (!v) return; const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = v; dl.append(dt, dd); };
      kv('Other numbers (unverified)', r.relatedPhones.join(', '));
      kv('Bank accounts (unverified)', r.relatedBankAccounts.join(', '));
      kv('Police report', r.policeReportRef);
      kv('Public summary', r.publicSummary);
      if (r.status === 'pending_review' || r.status === 'published') {
        const b = document.createElement('button'); b.className = 'btn sm danger'; b.textContent = 'Withdraw report';
        b.onclick = async () => { if (!confirm('Withdraw this report? It will no longer be reviewed or shown.')) return; try { await HAD.api('POST', `/api/reports/${r.id}/withdraw`, {}); load(); } catch (e) { HAD.alertBox(msg, 'error', null, e.message); } };
        li.querySelector('[data-actions]').appendChild(b);
      }
      ul.appendChild(li);
    }
    // evidence
    const tb = document.getElementById('evidence'); tb.innerHTML = '';
    const evSel = document.getElementById('lev'); const evOpts = { '': 'None' };
    if (!data.evidence.length) tb.innerHTML = '<tr><td colspan="4" class="empty">No evidence yet.</td></tr>';
    data.evidence.forEach((e, i) => {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td><div class="t"></div><div class="small faint"></div></td><td class="mono small"></td><td class="small"></td><td><a class="btn sm">Open</a></td>';
      tr.querySelector('.t').textContent = `E${i + 1}. ${e.originalFilename}`;
      tr.querySelector('.faint').textContent = `${HAD.fmtSize(e.sizeBytes)}${e.derivedFrom ? ' · redacted copy' : ''}${e.status === 'purged' ? ' · deleted' : ''}`;
      tr.children[1].textContent = e.sha256.slice(0, 16) + '…'; tr.children[1].title = e.sha256;
      tr.children[2].textContent = HAD.fmtDate(e.uploadedAt);
      tr.querySelector('a').href = '/evidence.html?id=' + encodeURIComponent(e.id);
      tb.appendChild(tr);
      if (e.status === 'active') evOpts[e.id] = `E${i + 1}. ${e.originalFilename}`;
    });
    HAD.fillSelect(evSel, evOpts);
    // locations, grouped by category, never merged
    const lb = document.getElementById('locations'); lb.innerHTML = '';
    if (!data.locations.length) lb.innerHTML = '<p class="empty">No locations recorded.</p>';
    for (const [cat, label] of Object.entries(HAD.LABELS.location)) {
      const ls = data.locations.filter(l => l.category === cat); if (!ls.length) continue;
      const h = document.createElement('h3'); h.textContent = label; h.style.marginTop = '12px'; lb.appendChild(h);
      const ul2 = document.createElement('ul'); ul2.className = 'list';
      for (const l of ls) {
        const li = document.createElement('li');
        li.innerHTML = '<div class="row between"><span class="t"></span><span class="row" data-b></span></div><div class="small muted" data-a></div><div class="small faint" data-s></div>';
        li.querySelector('.t').textContent = l.label;
        const b = li.querySelector('[data-b]');
        b.appendChild(HAD.statusBadge('verification', l.verificationStatus));
        b.appendChild(HAD.badge('Precision: ' + l.precision, 'plain'));
        if (l.isPrivateResidence) b.appendChild(HAD.badge('Private home', 'warn'));
        if (l.isVictimLocation) b.appendChild(HAD.badge('Victim location', 'info'));
        li.querySelector('[data-a]').textContent = [l.addressText, l.lat != null ? `${l.lat}, ${l.lng}` : null, l.country].filter(Boolean).join(' · ');
        li.querySelector('[data-s]').textContent = `Source: ${l.sourceReference} · reliability ${l.sourceReliability} · collected ${HAD.fmtDate(l.collectedAt)}${l.lastVerifiedAt ? ' · last verified ' + HAD.fmtDate(l.lastVerifiedAt) : ''}`;
        ul2.appendChild(li);
      }
      lb.appendChild(ul2);
    }
    // timeline
    const tl = [];
    data.reports.forEach(r => { if (r.incidentAt) tl.push([r.incidentAt, `Incident: ${HAD.LABELS.category[r.category]} via ${HAD.LABELS.channel[r.channel]} from ${r.phone}`]); tl.push([r.createdAt, `Report submitted (${r.phone})`]); if (r.reviewedAt) tl.push([r.reviewedAt, `Report reviewed: ${HAD.LABELS.reportStatus[r.status][0]}`]); });
    data.evidence.forEach(e => tl.push([e.uploadedAt, `Evidence uploaded: ${e.originalFilename}`]));
    tl.sort((a, b) => a[0] < b[0] ? -1 : 1);
    const tlu = document.getElementById('timeline'); tlu.innerHTML = '';
    for (const [t, d] of tl) { const li = document.createElement('li'); li.innerHTML = '<div class="small faint"></div><div></div>'; li.firstChild.textContent = HAD.fmtDate(t); li.lastChild.textContent = d; tlu.appendChild(li); }
    if (!tl.length) tlu.innerHTML = '<li class="muted">Nothing yet.</li>';
  }
  await load();
  const uploader = createUploader(document.getElementById('uploader'), { onUploaded: () => load() });
  uploader.setCase(id);
  document.getElementById('pdf').addEventListener('click', async e => {
    e.preventDefault();
    const btn = e.currentTarget; btn.textContent = 'Generating…';
    try {
      const res = await fetch(`/api/cases/${encodeURIComponent(id)}/export.pdf`, { credentials: 'same-origin' });
      if (res.status === 401) return location.href = '/login.html?expired=1&next=' + encodeURIComponent(location.pathname + location.search);
      if (!res.ok) { const j = await res.json().catch(() => ({})); throw new Error((j.error && j.error.message) || 'PDF export failed.'); }
      const blob = await res.blob();
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `HAD-case-${id.slice(0, 8)}.pdf`; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    } catch (err) { HAD.alertBox(msg, 'error', 'Could not export', err.message); }
    finally { btn.textContent = 'Export police summary PDF'; }
  });
  document.getElementById('loc-form').addEventListener('submit', async e => {
    e.preventDefault();
    const f = e.target; const d = HAD.formObject(f);
    try {
      const r = await HAD.api('POST', `/api/cases/${encodeURIComponent(id)}/locations`, d);
      HAD.alertBox(msg, 'success', 'Location saved', (r.notes || []).join(' '));
      f.reset(); setHint(); await load();
    } catch (err) { HAD.alertBox(msg, 'error', 'Could not save location', err.message); HAD.markInvalid(f, err); }
  });
  document.getElementById('case-edit').addEventListener('submit', async e => {
    e.preventDefault();
    try { await HAD.api('PATCH', `/api/cases/${encodeURIComponent(id)}`, HAD.formObject(e.target)); HAD.alertBox(msg, 'success', 'Saved'); await load(); }
    catch (err) { HAD.alertBox(msg, 'error', 'Could not save', err.message); }
  });
})().catch(e => HAD.alertBox('#msg', 'error', 'Could not load this case', e.message));
