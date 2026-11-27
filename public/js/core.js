/* H.A.D shared front-end helpers. No framework; every value from the server is
   inserted as text (never innerHTML) unless passed through esc(). */
'use strict';

const HAD = (() => {
  const LABELS = {
    category: {
      death_threat: 'Death threat', threat_family: 'Threat against family', threat_property: 'Threat against property',
      threat_visit: 'Threat to visit home or workplace', harassment: 'Harassment', blackmail: 'Blackmail',
      loan_intimidation: 'Loan collection intimidation', illegal_lending: 'Suspected illegal lending',
      payment_demand: 'Suspicious payment demand', other: 'Other',
    },
    channel: {
      whatsapp_message: 'WhatsApp message', whatsapp_call: 'WhatsApp call', phone_call: 'Phone call', sms: 'SMS',
      telegram: 'Telegram', social_media: 'Social media', in_person: 'In person', other: 'Other',
    },
    location: {
      incident_location: 'Location of incident',
      location_mentioned_in_threat: 'Location mentioned in a threat',
      voluntarily_shared_location: 'Location voluntarily shared by a person',
      public_business_address: 'Public business address',
      approximate_network_location: 'Approximate network (IP) location',
      officially_confirmed_suspect_location: 'Officially confirmed suspect location',
    },
    reportStatus: {
      pending_review: ['Private · awaiting review', 'warn'], published: ['Reviewed · published (masked)', 'ok'],
      rejected: ['Not published', 'danger'], taken_down: ['Taken down', 'danger'], withdrawn: ['Withdrawn', 'plain'],
    },
    verification: {
      verified: ['Verified', 'ok'], corroborated: ['Corroborated', 'info'], unverified: ['Unverified', 'warn'],
      approximate: ['Approximate', 'purple'], unknown: ['Unknown', 'plain'], disputed: ['Disputed', 'danger'], rejected: ['Rejected', 'danger'],
    },
  };

  const ICONS = {
    dash: '<path d="M3 13h8V3H3zm10 8h8V11h-8zM3 21h8v-6H3zm10-18v6h8V3z"/>',
    search: '<path d="M10 2a8 8 0 105.3 14l5.4 5.4 1.4-1.4-5.4-5.4A8 8 0 0010 2zm0 2a6 6 0 110 12 6 6 0 010-12z"/>',
    folder: '<path d="M10 4l2 2h8a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V6a2 2 0 012-2z"/>',
    alert: '<path d="M12 2L1 21h22zm0 5l7.5 12h-15zm-1 4v4h2v-4zm0 5v2h2v-2z"/>',
    shield: '<path d="M12 2l8 3v6c0 5-3.4 9.7-8 11-4.6-1.3-8-6-8-11V5z"/>',
    user: '<path d="M12 12a5 5 0 100-10 5 5 0 000 10zm0 2c-5 0-9 2.5-9 5.5V22h18v-2.5C21 16.5 17 14 12 14z"/>',
    gavel: '<path d="M2 21h12v2H2zM5.2 8.2l2.8-2.8 11.3 11.3-2.8 2.8zM9.4 4l2.8-2.8 5.7 5.6-2.9 2.9zM3.8 9.6l2.8-2.8 5.7 5.6-2.9 2.9z"/>',
    phone: '<path d="M6.6 10.8a15 15 0 006.6 6.6l2.2-2.2a1 1 0 011-.25 11.4 11.4 0 003.6.6 1 1 0 011 1V20a1 1 0 01-1 1A17 17 0 013 4a1 1 0 011-1h3.5a1 1 0 011 1c0 1.25.2 2.45.6 3.6a1 1 0 01-.25 1z"/>',
    map: '<path d="M15 4l-6-2-7 3v17l7-3 6 2 7-3V1zM9 4.4l6 2v13.2l-6-2z"/>',
    life: '<path d="M12 2a10 10 0 100 20 10 10 0 000-20zm1 15h-2v-2h2zm0-4h-2V7h2z"/>',
  };
  const icon = (n, size = 18) => `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${ICONS[n] || ''}</svg>`;

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  class ApiError extends Error {
    constructor(status, code, message, extra) { super(message); this.status = status; this.code = code; this.extra = extra || {}; }
  }

  function loginRedirect(expired) {
    const next = encodeURIComponent(location.pathname + location.search);
    location.href = `/login.html?next=${next}${expired ? '&expired=1' : ''}`;
  }

  async function api(method, url, body, opts = {}) {
    const init = { method, headers: { 'X-HAD-Request': '1' }, credentials: 'same-origin' };
    if (body instanceof FormData) init.body = body;
    else if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    let res;
    try { res = await fetch(url, init); }
    catch (e) { throw new ApiError(0, 'NETWORK', 'Could not reach H.A.D. Check your connection. Nothing you typed has been lost; try again.'); }
    let data = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) { try { data = await res.json(); } catch (_) { /* ignore */ } }
    if (!res.ok) {
      const err = data && data.error ? data.error : { code: 'HTTP_' + res.status, message: 'Unexpected error (' + res.status + '). Please try again.' };
      if (res.status === 401 && opts.redirectOn401 !== false && (err.code === 'AUTH_EXPIRED' || err.code === 'AUTH_REQUIRED')) {
        loginRedirect(err.code === 'AUTH_EXPIRED');
      }
      throw new ApiError(res.status, err.code, err.message, err);
    }
    return data;
  }

  // Upload with progress (fetch has no upload progress).
  function upload(url, formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.setRequestHeader('X-HAD-Request', '1');
      xhr.upload.onprogress = e => { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); };
      xhr.onerror = () => reject(new ApiError(0, 'NETWORK', 'Upload interrupted. Your file is still selected; press Retry.'));
      xhr.ontimeout = xhr.onerror;
      xhr.onload = () => {
        let data = null; try { data = JSON.parse(xhr.responseText); } catch (_) { }
        if (xhr.status >= 200 && xhr.status < 300) return resolve(data);
        const err = (data && data.error) || { code: 'HTTP_' + xhr.status, message: 'Upload failed (' + xhr.status + ').' };
        if (xhr.status === 401) { reject(new ApiError(401, err.code, err.message)); return loginRedirect(err.code === 'AUTH_EXPIRED'); }
        reject(new ApiError(xhr.status, err.code, err.message));
      };
      xhr.send(formData);
    });
  }

  async function sha256Hex(file) {
    if (!window.crypto || !crypto.subtle) return null;
    const buf = await file.arrayBuffer();
    const h = await crypto.subtle.digest('SHA-256', buf);
    return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function alertBox(target, type, title, msg) {
    const box = typeof target === 'string' ? document.querySelector(target) : target;
    if (!box) return;
    box.innerHTML = '';
    if (!title && !msg) return;
    const d = document.createElement('div');
    d.className = 'alert ' + type;
    d.setAttribute('role', type === 'error' ? 'alert' : 'status');
    if (title) { const s = document.createElement('strong'); s.textContent = title; d.appendChild(s); }
    if (msg) d.appendChild(document.createTextNode(msg));
    box.appendChild(d);
  }

  function formObject(form) {
    const o = {};
    for (const el of form.elements) {
      if (!el.name || el.disabled) continue;
      if (el.type === 'checkbox') o[el.name] = el.checked;
      else if (el.type === 'file') continue;
      else o[el.name] = el.value;
    }
    return o;
  }

  // Keep unsent form content in this browser so a failed submit, expired
  // session or closed tab never loses what a victim typed.
  function keepDraft(form, key) {
    const k = 'had-draft:' + key;
    try {
      const saved = JSON.parse(localStorage.getItem(k) || 'null');
      if (saved) for (const [n, v] of Object.entries(saved)) {
        const el = form.elements[n]; if (!el || el.type === 'file' || el.type === 'hidden') continue;
        if (el.type === 'checkbox') el.checked = !!v; else el.value = v;
      }
    } catch (_) { }
    const save = () => { try { const o = formObject(form); delete o.idempotencyKey; localStorage.setItem(k, JSON.stringify(o)); } catch (_) { } };
    form.addEventListener('input', save);
    return { clear: () => { try { localStorage.removeItem(k); } catch (_) { } } };
  }

  function badge(text, kind) { const b = document.createElement('span'); b.className = 'badge ' + (kind || ''); b.textContent = text; return b; }
  function statusBadge(map, key) { const [t, k] = LABELS[map][key] || [key, 'plain']; return badge(t, k); }

  const fmtDate = s => s ? new Date(s.length <= 16 && !s.endsWith('Z') ? s : s).toLocaleString('en-MY', { dateStyle: 'medium', timeStyle: s.length > 10 ? 'short' : undefined }) : '—';
  const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
  const qs = n => new URLSearchParams(location.search).get(n);

  async function demoBanner() {
    try {
      const h = await fetch('/api/health').then(r => r.json());
      if (h.demoMode) {
        const d = document.createElement('div');
        d.className = 'demo-banner'; d.setAttribute('role', 'note');
        d.textContent = 'DEMO MODE — all data on this site is synthetic and is not a real community report.';
        document.body.prepend(d);
      }
    } catch (_) { }
  }

  // ---------- public layout ----------
  function publicNav(active) {
    const header = document.createElement('header');
    header.className = 'topnav';
    header.innerHTML = `
      <a class="brand" href="/"><span class="mark">H</span><span>H.A.D<small>Hunt Ahlong Down</small></span></a>
      <button class="btn sm ghost menu-btn" aria-expanded="false" aria-controls="pubnav">Menu</button>
      <nav id="pubnav" aria-label="Main">
        <a href="/#search">Search a number</a>
        <a href="/safety.html">Safety &amp; emergency</a>
        <a href="/about.html">About</a>
        <a href="/appeal.html">Corrections</a>
        <a href="/login.html" data-auth="out">Log in</a>
        <a class="btn sm primary" href="/register.html" data-auth="out">Report a threat</a>
        <a class="btn sm primary hidden" href="/dashboard.html" data-auth="in">My dashboard</a>
      </nav>`;
    header.querySelectorAll('nav a').forEach(a => { if (a.getAttribute('href') === active) a.setAttribute('aria-current', 'page'); });
    const btn = header.querySelector('.menu-btn'); const nav = header.querySelector('nav');
    btn.addEventListener('click', () => { const o = nav.classList.toggle('open'); btn.setAttribute('aria-expanded', o); });
    document.body.prepend(header);
    api('GET', '/api/auth/session').then(r => {
      if (!r.user) return;
      header.querySelectorAll('[data-auth=out]').forEach(e => e.classList.add('hidden'));
      header.querySelectorAll('[data-auth=in]').forEach(e => e.classList.remove('hidden'));
    }).catch(() => { });
    const f = document.createElement('footer');
    f.className = 'footer';
    f.innerHTML = `<div class="inner"><span>H.A.D (Hunt Ahlong Down). Community reports are allegations, not findings. In danger now? Call <strong>999</strong>.</span>
      <span class="row"><a href="/privacy.html">Privacy</a><a href="/terms.html">Terms</a><a href="/appeal.html">Corrections &amp; takedowns</a><a href="/safety.html">Emergency help</a></span></div>`;
    document.body.appendChild(f);
    demoBanner();
  }

  // ---------- app shell (authenticated) ----------
  async function appShell(active) {
    let me;
    try { me = (await api('GET', '/api/auth/me')).user; } catch (e) { if (e.status !== 401) document.body.textContent = e.message; return new Promise(() => { }); }
    const staff = me.role === 'moderator' || me.role === 'admin';
    const main = document.querySelector('main');
    const shell = document.createElement('div');
    shell.className = 'shell';
    const links = [
      ['/dashboard.html', 'dash', 'Dashboard'],
      ['/search.html', 'search', 'Phone intelligence'],
      ['/report.html', 'alert', 'Report a threat'],
      ['/cases.html', 'folder', 'My cases & evidence'],
      ['/map.html', 'map', 'Intelligence map'],
    ];
    const staffLinks = staff ? [['/mod.html', 'gavel', 'Moderation']] : [];
    const navHtml = l => `<a class="nav" href="${l[0]}"${l[0] === active ? ' aria-current="page"' : ''}>${icon(l[1])}<span>${l[2]}</span></a>`;
    shell.innerHTML = `
      <aside class="sidebar" aria-label="Sidebar">
        <a class="brand" href="/dashboard.html"><span class="mark">H</span><span>H.A.D<small>Hunt Ahlong Down</small></span></a>
        <nav aria-label="App">
          ${links.map(navHtml).join('')}
          ${staff ? '<div class="section">Staff</div>' + staffLinks.map(navHtml).join('') : ''}
          <div class="section">Help</div>
          ${navHtml(['/safety.html', 'life', 'Safety & emergency'])}
          ${navHtml(['/account.html', 'user', 'Account'])}
        </nav>
        <div class="spacer"></div>
        <div class="who"><div class="t" data-me-name></div><div class="small faint" data-me-role></div></div>
      </aside>`;
    const content = document.createElement('div');
    content.style.minWidth = '0';
    const mobileTop = document.createElement('div');
    mobileTop.className = 'mobile-top';
    mobileTop.innerHTML = `<a class="brand" href="/dashboard.html"><span class="mark">H</span><span>H.A.D</span></a><span class="row" style="gap:6px"><a class="btn sm ghost" href="/safety.html">${icon('life', 16)} Help</a><a class="btn sm ghost" href="/account.html">${icon('user', 16)} Account</a></span>`;
    main.classList.add('main');
    main.prepend(mobileTop);
    main.id = 'main';
    content.appendChild(main);
    shell.appendChild(content);
    document.body.prepend(shell);
    const bottom = document.createElement('nav');
    bottom.className = 'bottomnav'; bottom.setAttribute('aria-label', 'Mobile');
    const mob = [['/dashboard.html', 'dash', 'Home'], ['/search.html', 'search', 'Search'], ['/report.html', 'alert', 'Report'], ['/cases.html', 'folder', 'Cases'], ['/map.html', 'map', 'Map']];
    if (staff) mob.push(['/mod.html', 'gavel', 'Mod']);
    bottom.innerHTML = mob.map(l => `<a href="${l[0]}"${l[0] === active ? ' aria-current="page"' : ''}>${icon(l[1], 20)}<span>${l[2]}</span></a>`).join('');
    document.body.appendChild(bottom);
    shell.querySelector('[data-me-name]').textContent = me.displayName;
    shell.querySelector('[data-me-role]').textContent = me.role === 'user' ? 'Registered victim' : me.role[0].toUpperCase() + me.role.slice(1);
    demoBanner();
    return me;
  }

  function fillSelect(sel, map, placeholder) {
    sel.innerHTML = '';
    if (placeholder) { const o = document.createElement('option'); o.value = ''; o.textContent = placeholder; sel.appendChild(o); }
    for (const [v, t] of Object.entries(map)) { const o = document.createElement('option'); o.value = v; o.textContent = Array.isArray(t) ? t[0] : t; sel.appendChild(o); }
  }

  function markInvalid(form, err) {
    form.querySelectorAll('[aria-invalid]').forEach(e => e.removeAttribute('aria-invalid'));
    if (!err || !err.message) return;
    const m = err.message.toLowerCase();
    for (const el of form.elements) {
      const lbl = form.querySelector(`label[for="${el.id}"]`);
      const name = (lbl ? lbl.textContent : el.name || '').toLowerCase().replace(/\(optional\)/, '').trim();
      if (name && m.startsWith(name.split(' ')[0]) && m.includes(name.split(' ').slice(0, 2).join(' '))) { el.setAttribute('aria-invalid', 'true'); el.focus(); break; }
    }
  }

  return { LABELS, icon, esc, api, upload, sha256Hex, alertBox, formObject, keepDraft, badge, statusBadge, fmtDate, fmtSize, qs, publicNav, appShell, fillSelect, markInvalid, ApiError };
})();
