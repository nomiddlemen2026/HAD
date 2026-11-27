'use strict';
(async () => {
  const me = await HAD.appShell('/cases.html');
  const id = HAD.qs('id');
  const msg = document.getElementById('msg');
  async function load() {
    const d = await HAD.api('GET', '/api/evidence/' + encodeURIComponent(id));
    const e = d.evidence;
    document.title = e.originalFilename + ' · H.A.D';
    document.getElementById('title').textContent = e.originalFilename;
    document.getElementById('sub').textContent = `${HAD.fmtSize(e.sizeBytes)} · ${e.mimeType}${e.derivedFrom ? ' · redacted copy' : ' · original'}`;
    document.getElementById('case-link').href = '/case.html?id=' + encodeURIComponent(e.caseId);
    const meta = document.getElementById('meta'); meta.innerHTML = '';
    const kv = (k, v, mono) => { const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = v; if (mono) dd.className = 'mono break'; meta.append(dt, dd); };
    kv('Evidence ID', e.id, true); kv('Original filename', e.originalFilename); kv('SHA-256', e.sha256, true);
    kv('Uploaded', HAD.fmtDate(e.uploadedAt) + ' (' + e.uploadedAt + ')'); kv('Uploader ID', e.uploaderId, true); kv('Case ID', e.caseId, true);
    kv('Stored original', 'Read-only, never modified');
    if (e.derivedFrom) kv('Redacted from', e.derivedFrom, true);
    const ch = document.getElementById('chain'); ch.innerHTML = '';
    ch.appendChild(d.chainIntegrity.ok ? HAD.badge('Log intact', 'ok') : HAD.badge('Log integrity problem', 'danger'));
    const tb = document.getElementById('custody'); tb.innerHTML = '';
    for (const ev of d.custody) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td class="small faint"></td><td></td><td class="small"></td><td class="small mono"></td><td class="small"></td>';
      tr.children[0].textContent = ev.id;
      tr.children[1].appendChild(HAD.badge(ev.event_type.replace(/_/g, ' '), { upload: 'ok', redaction: 'purple', processing: 'info', download: 'warn', purge: 'danger', legal_hold: 'warn' }[ev.event_type] || 'plain'));
      tr.children[2].textContent = ev.at.replace('T', ' ').slice(0, 19);
      tr.children[3].textContent = ev.actor_id === me.id ? 'You' : (ev.actor_id || '').slice(0, 8);
      tr.children[4].textContent = Object.entries(ev.details).filter(([k]) => k !== 'sha256').map(([k, v]) => `${k.replace(/_/g, ' ')}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · ');
      tb.appendChild(tr);
    }
    const der = document.getElementById('derived'); der.innerHTML = '';
    for (const c of d.derivedCopies) { const p = document.createElement('p'); p.className = 'small'; const a = document.createElement('a'); a.href = '/evidence.html?id=' + c.id; a.textContent = c.originalFilename; p.append('Redacted copy: ', a, ' · ' + HAD.fmtDate(c.uploadedAt)); der.appendChild(p); }
    if (e.derivedFrom) document.getElementById('redact-form').classList.add('hidden');
    document.getElementById('wa-card').classList.toggle('hidden', !/\.txt$/i.test(e.originalFilename));
    return d;
  }
  await load();

  document.getElementById('download').addEventListener('click', ev => { ev.preventDefault(); location.href = `/api/evidence/${encodeURIComponent(id)}/download`; setTimeout(load, 1500); });

  document.getElementById('redact-form').addEventListener('submit', async ev => {
    ev.preventDefault();
    const f = ev.target; const file = f.file.files[0];
    if (!file) return HAD.alertBox(msg, 'error', 'Choose a file', 'Select the redacted copy to upload.');
    const fd = new FormData(); fd.append('note', f.note.value); const h = await HAD.sha256Hex(file); if (h) fd.append('sha256', h); fd.append('file', file, file.name);
    try { await HAD.upload(`/api/evidence/${encodeURIComponent(id)}/redacted`, fd); HAD.alertBox(msg, 'success', 'Redacted copy saved', 'The original was not changed.'); f.reset(); await load(); }
    catch (err) { HAD.alertBox(msg, 'error', 'Upload failed', err.message + ' Your file is still selected; try again.'); }
  });

  document.getElementById('parse').addEventListener('click', async ev => {
    const btn = ev.currentTarget; btn.disabled = true; btn.textContent = 'Analysing…';
    try { const r = await HAD.api('POST', `/api/evidence/${encodeURIComponent(id)}/parse-whatsapp`, {}); renderChat(r.result); await load(); }
    catch (err) { HAD.alertBox(msg, 'error', 'Could not analyse', err.message); }
    finally { btn.disabled = false; btn.textContent = 'Analyse again'; }
  });

  function renderChat(r) {
    const box = document.getElementById('wa'); box.innerHTML = '';
    const disc = document.createElement('div'); disc.className = 'alert warn'; const s = document.createElement('strong'); s.textContent = 'Automated reading, not authenticated'; disc.appendChild(s);
    const ul0 = document.createElement('ul'); ul0.style.margin = '6px 0 0'; ul0.style.paddingLeft = '18px';
    for (const d of r.disclaimers) { const li = document.createElement('li'); li.textContent = d; ul0.appendChild(li); }
    disc.appendChild(ul0); box.appendChild(disc);
    if (!r.ok) { HAD.alertBox(box.appendChild(document.createElement('div')), 'error', 'No messages recognised', r.uncertainties.map(u => u.detail).join(' ')); return; }
    const stats = document.createElement('div'); stats.className = 'grid cols-4';
    for (const [k, v] of [['Messages', r.summary.messageCount], ['Senders', r.summary.senderCount], ['Possible threats', r.summary.possibleThreatCount], ['Phone numbers', r.summary.phoneNumbersFound.length]]) {
      const d = document.createElement('div'); d.className = 'stat'; d.innerHTML = '<div class="v"></div><div class="k"></div>'; d.querySelector('.v').textContent = v; d.querySelector('.k').textContent = k; stats.appendChild(d);
    }
    box.appendChild(stats);
    const sec = (title) => { const h = document.createElement('h3'); h.textContent = title; h.style.marginTop = '18px'; box.appendChild(h); };
    sec('Parsing notes');
    const ul = document.createElement('ul'); ul.className = 'small muted';
    for (const u of r.uncertainties) { const li = document.createElement('li'); li.textContent = u.detail; ul.appendChild(li); }
    box.appendChild(ul);
    sec('Senders (as labelled on the exporting phone)');
    const sp = document.createElement('p'); sp.className = 'small'; sp.textContent = r.senders.map(s => `${s.label}${s.isPhoneNumber ? ' (number)' : ''}: ${s.messageCount}`).join(' · ') || '—'; box.appendChild(sp);
    sec('Repeated identifiers');
    if (!r.repeatedIdentifiers.length) { const p = document.createElement('p'); p.className = 'small muted'; p.textContent = 'None found.'; box.appendChild(p); }
    else {
      const t = document.createElement('div'); t.className = 'table-wrap'; t.innerHTML = '<table><thead><tr><th>Type</th><th>Value</th><th>Times</th></tr></thead><tbody></tbody></table>';
      for (const x of r.repeatedIdentifiers) { const tr = document.createElement('tr'); tr.innerHTML = '<td></td><td class="mono"></td><td></td>'; tr.children[0].textContent = x.type.replace(/_/g, ' '); tr.children[1].textContent = x.value; tr.children[2].textContent = x.occurrences; t.querySelector('tbody').appendChild(tr); }
      box.appendChild(t);
    }
    sec('Conversation (chronological)');
    const filt = document.createElement('label'); filt.className = 'check small'; filt.innerHTML = '<input type="checkbox"> <span>Show only messages flagged for review</span>'; box.appendChild(filt);
    const chat = document.createElement('div'); chat.className = 'chat';
    for (const m of r.messages) {
      const d = document.createElement('div'); d.className = 'msg' + (m.possibleThreat ? ' threat' : '') + (m.kind === 'system' ? ' system' : '');
      d.innerHTML = '<div class="meta"><span data-s></span><span data-t></span><span data-l></span><span data-f></span></div><div class="body"></div>';
      d.querySelector('[data-s]').textContent = m.sender || '(system)';
      d.querySelector('[data-t]').textContent = m.timestamp ? m.timestamp.replace('T', ' ') : 'date unclear';
      d.querySelector('[data-l]').textContent = 'line ' + m.lineNumber;
      if (m.possibleThreat) d.querySelector('[data-f]').appendChild(HAD.badge('Review: ' + m.threatSignals.map(t => t.term).join(', '), 'danger'));
      else if (m.flags.length) d.querySelector('[data-f]').textContent = m.flags.join(', ').replace(/_/g, ' ');
      d.querySelector('.body').textContent = m.text;
      d.dataset.threat = m.possibleThreat ? '1' : '0';
      chat.appendChild(d);
    }
    filt.querySelector('input').onchange = ev => chat.querySelectorAll('.msg').forEach(x => { x.classList.toggle('hidden', ev.target.checked && x.dataset.threat !== '1'); });
    box.appendChild(chat);
  }
})().catch(e => HAD.alertBox('#msg', 'error', 'Could not load this evidence', e.message));
