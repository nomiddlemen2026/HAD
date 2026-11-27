'use strict';
(async () => {
  const me = await HAD.appShell('/map.html');
  const staff = me.role !== 'user';
  if (staff) document.querySelector('[data-staff]').classList.remove('hidden');
  const msg = document.getElementById('msg');
  const VCOLOR = { verified: '#34d399', corroborated: '#2ea8ff', unverified: '#ffb547', approximate: '#8b6cff', unknown: '#8a93b8', disputed: '#ff5c7a', rejected: '#ff5c7a' };
  const SHAPE = {
    incident_location: 'circle', location_mentioned_in_threat: 'tri', voluntarily_shared_location: 'ring',
    public_business_address: 'square', approximate_network_location: 'area', officially_confirmed_suspect_location: 'diamond',
  };
  const RADIUS = { exact: 0, approximate: 150, area: 1000 };
  const NOTES = {
    mine: 'Locations from your own cases. Only you and moderators can see these. Homes are stored only to about 1 km.',
    community: 'Only locations a moderator has verified or corroborated and approved for sharing. Homes, victims\' locations, places named in threats and IP estimates never appear here. Incidents are shown as a 1 km area.',
    all: 'Every stored location (staff only). Your viewing is recorded in the audit log.',
  };

  // Legend + filters
  const filters = document.getElementById('filters');
  const active = new Set(Object.keys(HAD.LABELS.location));
  for (const [cat, label] of Object.entries(HAD.LABELS.location)) {
    const l = document.createElement('label'); l.className = 'check small';
    l.innerHTML = `<input type="checkbox" checked> <span class="mk ${SHAPE[cat]}" style="background:#a3acd1;color:#a3acd1"></span> <span></span>`;
    l.lastElementChild.textContent = label;
    l.querySelector('input').onchange = e => { e.target.checked ? active.add(cat) : active.delete(cat); render(); };
    filters.appendChild(l);
  }
  const legend = document.getElementById('legend');
  for (const [v, c] of Object.entries(VCOLOR)) {
    if (v === 'rejected') continue;
    const row = document.createElement('div'); row.className = 'legend-row';
    row.innerHTML = `<span class="mk circle" style="background:${c}"></span><span></span>`;
    row.lastElementChild.textContent = HAD.LABELS.verification[v][0] + (v === 'disputed' ? ' / rejected' : '');
    legend.appendChild(row);
  }
  const arow = document.createElement('div'); arow.className = 'legend-row';
  arow.innerHTML = '<span class="mk area" style="color:#a3acd1"></span><span>Dashed circle: approximate area, not an exact point</span>';
  legend.appendChild(arow);

  // Map (with graceful fallback)
  let map = null, layer = null;
  const fallback = document.getElementById('map-fallback');
  function showFallback(text) {
    fallback.classList.remove('hidden'); fallback.innerHTML = '';
    HAD.alertBox(fallback, 'warn', 'Map unavailable', text + ' The list of location records below still works.');
    fallback.style.padding = '12px';
  }
  try {
    if (!window.L) throw new Error('Map library failed to load.');
    const cfg = await HAD.api('GET', '/api/map/config');
    map = L.map('map', { worldCopyJump: true }).setView([4.2, 108.5], 5);
    let loaded = 0, failed = 0;
    const tiles = L.tileLayer(cfg.tiles.url, { maxZoom: 18, attribution: cfg.tiles.attribution });
    tiles.on('tileload', () => { loaded++; });
    tiles.on('tileerror', () => { failed++; if (failed === 6 && loaded === 0) showFallback('Map tiles could not be loaded (the map provider may be down or blocked).'); });
    tiles.addTo(map);
    layer = L.layerGroup().addTo(map);
  } catch (e) {
    document.getElementById('map').classList.add('hidden');
    showFallback(e.message);
  }

  let scope = 'mine', records = [];
  function popup(l) {
    const d = document.createElement('div');
    const t = document.createElement('div'); t.className = 't'; t.textContent = l.label; d.appendChild(t);
    const row = document.createElement('div'); row.className = 'row'; row.style.margin = '6px 0';
    row.append(HAD.statusBadge('verification', l.verificationStatus), HAD.badge(HAD.LABELS.location[l.category], 'plain'));
    d.appendChild(row);
    const dl = document.createElement('dl'); dl.className = 'kv small';
    const kv = (k, v) => { if (v === null || v === undefined || v === '') return; const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = v; dl.append(dt, dd); };
    kv('Address / area', l.addressText);
    kv('Coordinates', l.lat != null ? `${l.lat}, ${l.lng} (${l.precision})` : null);
    kv('Country', l.country);
    kv('Source', l.sourceReference);
    kv('Source reliability', l.sourceReliability);
    kv('Collected', HAD.fmtDate(l.collectedAt));
    kv('Last verified', l.lastVerifiedAt ? HAD.fmtDate(l.lastVerifiedAt) : 'Never');
    if (l.caseTitle) kv('Case', l.caseTitle);
    if (typeof l.evidence === 'string') kv('Evidence', l.evidence);
    d.appendChild(dl);
    if (l.evidenceId) { const a = document.createElement('a'); a.href = '/evidence.html?id=' + encodeURIComponent(l.evidenceId); a.textContent = 'Open supporting evidence' + (l.evidenceName ? ': ' + l.evidenceName : ''); a.className = 'small'; d.appendChild(a); }
    else if (l.caseId) { const a = document.createElement('a'); a.href = '/case.html?id=' + encodeURIComponent(l.caseId); a.textContent = 'Open case'; a.className = 'small'; d.appendChild(a); }
    if (l.isPrivateResidence || l.isVictimLocation) { const p = document.createElement('p'); p.className = 'small faint'; p.style.margin = '6px 0 0'; p.textContent = 'Private: never shown to other users.'; d.appendChild(p); }
    return d;
  }

  function render() {
    const shown = records.filter(l => active.has(l.category));
    const list = document.getElementById('loc-list'); list.innerHTML = '';
    document.getElementById('count').textContent = `${shown.length} record(s)`;
    if (!shown.length) list.innerHTML = `<li class="empty">${scope === 'community' ? 'No moderator-approved locations yet.' : 'No location records yet. Add them from a case page.'}</li>`;
    const markers = [];
    if (layer) layer.clearLayers();
    for (const l of shown) {
      const color = VCOLOR[l.verificationStatus] || '#8a93b8';
      if (map && l.lat != null) {
        const r = RADIUS[l.precision] || 0;
        if (r) markers.push(L.circle([l.lat, l.lng], { radius: r, color, weight: 2, dashArray: '6 6', fillColor: color, fillOpacity: .12 }).bindPopup(() => popup(l)).addTo(layer));
        const icon = L.divIcon({ className: 'had-pin', html: `<span class="mk ${SHAPE[l.category]}" style="background:${color};color:${color}"></span>`, iconSize: [18, 18], iconAnchor: [9, 9] });
        markers.push(L.marker([l.lat, l.lng], { icon, title: l.label, keyboard: true }).bindPopup(() => popup(l)).addTo(layer));
      }
      const li = document.createElement('li');
      li.innerHTML = '<div class="row between"><span class="t"></span><span class="row" data-b></span></div><div class="small muted" data-a></div><div class="small faint" data-s></div>';
      li.querySelector('.t').textContent = l.label;
      const b = li.querySelector('[data-b]');
      b.append(HAD.statusBadge('verification', l.verificationStatus), HAD.badge(HAD.LABELS.location[l.category], 'plain'));
      if (l.communityVisible && scope !== 'community') b.appendChild(HAD.badge('On community map', 'info'));
      li.querySelector('[data-a]').textContent = [l.addressText, l.lat != null ? `${l.lat}, ${l.lng} (${l.precision})` : 'No coordinates: not on map', l.country].filter(Boolean).join(' · ');
      li.querySelector('[data-s]').textContent = `Source: ${l.sourceReference} · reliability ${l.sourceReliability} · collected ${HAD.fmtDate(l.collectedAt)}`;
      if (map && l.lat != null) { li.style.cursor = 'pointer'; li.tabIndex = 0; const go = () => { map.setView([l.lat, l.lng], Math.max(map.getZoom(), 13)); document.getElementById('map').scrollIntoView({ behavior: 'smooth', block: 'center' }); }; li.onclick = go; li.onkeydown = e => { if (e.key === 'Enter') go(); }; }
      list.appendChild(li);
    }
    if (map && markers.length) map.fitBounds(L.featureGroup(markers).getBounds().pad(0.3), { maxZoom: 13 });
  }

  async function load(s) {
    scope = s;
    document.querySelectorAll('#scopes button').forEach(b => b.setAttribute('aria-selected', b.dataset.scope === s));
    document.getElementById('scope-note').textContent = NOTES[s];
    try { records = (await HAD.api('GET', '/api/map/locations?scope=' + s)).locations; render(); }
    catch (e) { HAD.alertBox(msg, 'error', 'Could not load locations', e.message); }
  }
  document.querySelectorAll('#scopes button').forEach(b => b.addEventListener('click', () => load(b.dataset.scope)));
  await load('mine');
})().catch(e => HAD.alertBox('#msg', 'error', 'Could not load the map', e.message));
