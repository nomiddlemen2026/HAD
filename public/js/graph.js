'use strict';
(async () => {
  const me = await HAD.appShell('/graph.html');
  const staff = me.role !== 'user';
  if (staff) document.querySelector('[data-staff]').classList.remove('hidden');
  const msg = document.getElementById('msg');
  const detail = document.getElementById('detail');
  let cy = null, scope = 'mine', data = null;
  const STATUS = r => (HAD.LABELS.reportStatus[r.status] || [r.status])[0];

  function caseLink(caseId, text) { const a = document.createElement('a'); a.href = '/case.html?id=' + encodeURIComponent(caseId); a.textContent = text; return a; }
  function nodeLabel(id) { const n = data.nodes.find(x => x.id === id); return n ? n.label : id; }

  async function setOverride(key, status) {
    let note = '';
    if (status !== 'clear') { note = prompt(status === 'removed' ? 'Why is this link wrong? (saved in the audit log)' : 'Why is this link confirmed?'); if (!note) return; }
    try { await HAD.api('POST', '/api/mod/relationships', { key, status, note }); HAD.alertBox(msg, 'success', 'Saved', ''); await load(scope); }
    catch (e) { HAD.alertBox(msg, 'error', 'Could not save', e.message); }
  }
  function staffButtons(item) {
    const row = document.createElement('div'); row.className = 'row'; row.style.marginTop = '8px';
    if (!staff || scope !== 'all') return row;
    if (item.override) {
      row.appendChild(HAD.badge((item.override.status === 'removed' ? 'Removed: ' : 'Confirmed: ') + item.override.note, item.override.status === 'removed' ? 'danger' : 'ok'));
      const b = document.createElement('button'); b.className = 'btn sm'; b.textContent = 'Undo'; b.onclick = () => setOverride(item.id, 'clear'); row.appendChild(b);
    } else {
      const r = document.createElement('button'); r.className = 'btn sm danger'; r.textContent = 'Remove as wrong'; r.onclick = () => setOverride(item.id, 'removed');
      const c = document.createElement('button'); c.className = 'btn sm'; c.textContent = 'Mark confirmed'; c.onclick = () => setOverride(item.id, 'confirmed');
      row.append(r, c);
    }
    return row;
  }

  function showEdge(e) {
    detail.innerHTML = ''; detail.classList.remove('muted');
    const t = document.createElement('div'); t.className = 't'; t.textContent = e.label; detail.appendChild(t);
    const p = document.createElement('p'); p.style.margin = '4px 0 8px'; p.textContent = `${nodeLabel(e.source)} → ${nodeLabel(e.target)}`; detail.appendChild(p);
    detail.appendChild(HAD.badge(e.certainty === 'possible' ? 'Possible association — not proven' : 'As reported by the victim', e.certainty === 'possible' ? 'warn' : 'plain'));
    const h = document.createElement('div'); h.className = 'faint'; h.style.marginTop = '10px'; h.textContent = `Supporting report(s): ${e.reports.length}`; detail.appendChild(h);
    const ul = document.createElement('ul'); ul.style.paddingLeft = '18px';
    for (const r of e.reports) { const li = document.createElement('li'); li.appendChild(caseLink(r.caseId, `Report from ${HAD.fmtDate(r.createdAt)}`)); li.append(` · ${STATUS(r)}`); ul.appendChild(li); }
    detail.appendChild(ul);
    detail.appendChild(staffButtons(e));
  }
  function showNode(n) {
    detail.innerHTML = ''; detail.classList.remove('muted');
    const t = document.createElement('div'); t.className = 't mono'; t.textContent = n.label; detail.appendChild(t);
    const p = document.createElement('p'); p.style.margin = '4px 0';
    p.textContent = { case: 'Case', phone: 'Phone number', account: 'Bank account' }[n.type];
    detail.appendChild(p);
    if (n.type === 'case') detail.appendChild(caseLink(n.id.slice(5), 'Open case'));
    if (typeof n.othersReviewed === 'number') {
      const q = document.createElement('p');
      q.textContent = n.othersReviewed ? `Also appears in ${n.othersReviewed} reviewed report(s) by other people. Details of other victims' reports are private.` : 'Not found in any reviewed report by other people.';
      detail.appendChild(q);
      if (n.type === 'phone') { const a = document.createElement('a'); a.href = '/search.html?phone=' + encodeURIComponent(n.label); a.textContent = 'Search this number'; detail.appendChild(a); }
    }
  }

  function renderFindings() {
    const box = document.getElementById('findings'); box.innerHTML = '';
    if (scope === 'mine') {
      const hits = data.nodes.filter(n => n.othersReviewed > 0);
      const p = document.createElement('p'); p.className = 'small muted';
      p.textContent = 'This view shows only your own cases. To protect other victims, their cases are never shown to you, only whether your numbers or accounts appear in reviewed reports by other people.';
      box.appendChild(p);
      if (!hits.length) { const e = document.createElement('p'); e.className = 'muted'; e.style.margin = '0'; e.textContent = data.nodes.length ? 'None of your numbers or accounts appear in other people\'s reviewed reports yet.' : 'No reports yet. Report a threat to start building your network.'; box.appendChild(e); }
      for (const n of hits) {
        const d = document.createElement('div'); d.className = 'finding';
        d.innerHTML = '<div class="row between"><span class="t mono"></span><span data-b></span></div>';
        d.querySelector('.t').textContent = n.label;
        d.querySelector('[data-b]').appendChild(HAD.badge(`${n.othersReviewed} other reviewed report(s)`, 'warn'));
        box.appendChild(d);
      }
      return;
    }
    if (!data.findings.length) { box.innerHTML = '<p class="muted" style="margin:0">No identifiers are shared between cases.</p>'; return; }
    for (const f of data.findings) {
      const d = document.createElement('div'); d.className = 'finding';
      d.innerHTML = '<div class="row between"><span class="t"></span><span class="row" data-b></span></div><div class="mono small" data-i></div><div class="small faint" data-n></div><div class="small" data-c></div>';
      d.querySelector('.t').textContent = f.label;
      d.querySelector('[data-b]').appendChild(HAD.badge(`${new Set(f.cases).size} cases · ${f.reports.length} reports`, f.type === 'possible_association' ? 'warn' : 'info'));
      d.querySelector('[data-i]').textContent = f.identifier;
      d.querySelector('[data-n]').textContent = f.note;
      const c = d.querySelector('[data-c]');
      [...new Set(f.cases)].forEach((id, i) => { if (i) c.append(' · '); c.appendChild(caseLink(id, 'Case ' + id.slice(0, 8))); });
      d.appendChild(staffButtons(f));
      box.appendChild(d);
    }
  }

  function renderGraph() {
    const el = document.getElementById('graph');
    if (!window.cytoscape) { el.innerHTML = ''; HAD.alertBox(el, 'warn', 'Graph view unavailable', 'The graph library failed to load. The findings list above still works.'); return; }
    if (cy) cy.destroy();
    if (!data.nodes.length) { el.innerHTML = '<p class="empty">Nothing to show yet.</p>'; return; }
    el.innerHTML = '';
    const elements = [
      ...data.nodes.map(n => ({ data: { id: n.id, label: n.type === 'case' ? (n.label.length > 28 ? n.label.slice(0, 27) + '…' : n.label) : n.label, type: n.type, hit: n.othersReviewed > 0 ? 1 : 0 } })),
      ...data.edges.map(e => ({ data: { id: e.id, source: e.source, target: e.target, certainty: e.certainty, removed: e.override && e.override.status === 'removed' ? 1 : 0 } })),
    ];
    cy = cytoscape({
      container: el, elements, maxZoom: 1.5, minZoom: 0.2,
      layout: { name: 'cose', animate: false, padding: 40, nodeDimensionsIncludeLabels: true, nodeRepulsion: 400000, idealEdgeLength: 120, componentSpacing: 100, randomize: false },
      style: [
        { selector: 'node', style: { label: 'data(label)', color: '#cfeeff', 'font-family': 'JetBrains Mono, monospace', 'font-size': 9, 'text-valign': 'bottom', 'text-margin-y': 4, 'text-outline-color': '#02060c', 'text-outline-width': 2, width: 22, height: 22 } },
        { selector: 'node[type="case"]', style: { shape: 'round-rectangle', 'background-color': '#00e5ff', 'border-width': 1, 'border-color': '#bff8ff', width: 28, height: 20 } },
        { selector: 'node[type="phone"]', style: { shape: 'ellipse', 'background-color': '#4c8dff' } },
        { selector: 'node[type="account"]', style: { shape: 'diamond', 'background-color': '#ffb000' } },
        { selector: 'node[hit = 1]', style: { 'border-width': 3, 'border-color': '#ff3b5c' } },
        { selector: 'edge', style: { width: 2, 'line-color': '#1f6f80', 'curve-style': 'bezier' } },
        { selector: 'edge[certainty="possible"]', style: { 'line-style': 'dashed', 'line-color': '#ff7a9a' } },
        { selector: 'edge[removed = 1]', style: { 'line-style': 'dotted', opacity: 0.35 } },
        { selector: ':selected', style: { 'overlay-color': '#00e5ff', 'overlay-opacity': 0.25 } },
      ],
    });
    cy.on('tap', 'node', ev => showNode(data.nodes.find(n => n.id === ev.target.id())));
    cy.on('tap', 'edge', ev => showEdge(data.edges.find(e => e.id === ev.target.id())));
  }

  async function load(s) {
    scope = s;
    document.querySelectorAll('#scopes button').forEach(b => b.setAttribute('aria-selected', b.dataset.scope === s));
    detail.className = 'small muted'; detail.textContent = 'Tap a dot or a line to see the reports behind it.';
    try { data = await HAD.api('GET', '/api/graph?scope=' + s); renderFindings(); renderGraph(); }
    catch (e) { HAD.alertBox(msg, 'error', 'Could not load the graph', e.message); }
  }
  document.querySelectorAll('#scopes button').forEach(b => b.addEventListener('click', () => load(b.dataset.scope)));
  await load('mine');
})().catch(e => HAD.alertBox('#msg', 'error', 'Could not load the graph', e.message));
