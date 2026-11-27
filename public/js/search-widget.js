'use strict';
// Renders a phone search form + result into `root`. Used on the landing page and in the app.
function renderSearch(root, { autofocus } = {}) {
  root.innerHTML = `
    <form class="searchbox" role="search" novalidate>
      <label for="q" class="skip">Phone number</label>
      <input id="q" name="phone" type="tel" inputmode="tel" autocomplete="off" placeholder="e.g. 012-345 6789 or +60 12-345 6789" required ${autofocus ? 'autofocus' : ''}>
      <button class="btn primary" type="submit">${HAD.icon('search', 16)} Search</button>
    </form>
    <div class="result" aria-live="polite"></div>`;
  const form = root.querySelector('form');
  const out = root.querySelector('.result');
  async function run(phone) {
    out.innerHTML = '<p class="muted">Searching…</p>';
    try {
      const r = await HAD.api('GET', '/api/search?phone=' + encodeURIComponent(phone));
      out.innerHTML = '';
      const card = document.createElement('div');
      card.className = 'card';
      const kind = r.reviewedReportCount === 0 ? 'info' : r.reviewedReportCount > 1 ? 'danger' : 'warn';
      card.innerHTML = `
        <div class="row between"><div><div class="small muted">Number (masked)</div><div class="num"></div></div><span data-badge></span></div>
        <dl class="kv" style="margin-top:14px">
          <dt>Issued in</dt><dd data-region></dd>
          <dt>Format</dt><dd data-format></dd>
          <dt>Reviewed community reports</dt><dd data-count></dd>
          <dt>Distinct reporters</dt><dd data-reporters></dd>
          <dt>Categories</dt><dd data-cats></dd>
          <dt>Reporting period</dt><dd data-period></dd>
        </dl>
        <div data-reports style="margin-top:12px"></div>
        <details style="margin-top:14px"><summary class="small muted">How to read this result</summary><ul class="small muted" data-disc></ul></details>
        <p class="small faint" style="margin-top:12px">Think a report about this number is wrong? <a href="/appeal.html">Request a correction or takedown</a>.</p>`;
      card.querySelector('.num').textContent = r.number;
      card.querySelector('[data-badge]').appendChild(HAD.badge(r.status, kind));
      card.querySelector('[data-region]').textContent = (r.numberingRegion || 'Unknown') + ' — ' + r.numberingRegionNote;
      card.querySelector('[data-format]').textContent = 'Valid ' + (r.numberType ? r.numberType.toLowerCase().replace(/_/g, ' ') : 'phone') + ' number format';
      card.querySelector('[data-count]').textContent = r.reviewedReportCount;
      card.querySelector('[data-reporters]').textContent = r.distinctReporters;
      const cats = Object.entries(r.categories).map(([k, v]) => `${HAD.LABELS.category[k] || k} (${v})`).join(', ');
      card.querySelector('[data-cats]').textContent = cats || '—';
      card.querySelector('[data-period]').textContent = r.firstReportedMonth ? (r.firstReportedMonth === r.lastReportedMonth ? r.firstReportedMonth : `${r.firstReportedMonth} to ${r.lastReportedMonth}`) : '—';
      const list = card.querySelector('[data-reports]');
      if (r.reports.length) {
        const ul = document.createElement('ul'); ul.className = 'list';
        for (const rep of r.reports) {
          const li = document.createElement('li');
          const head = document.createElement('div'); head.className = 'row';
          head.append(HAD.badge(HAD.LABELS.category[rep.category] || rep.category, 'purple'), HAD.badge(HAD.LABELS.channel[rep.channel] || rep.channel, 'plain'));
          const when = document.createElement('span'); when.className = 'small faint'; when.textContent = `Incident ${rep.month} · reviewed ${rep.reviewedAt}`;
          head.appendChild(when);
          const p = document.createElement('p'); p.style.margin = '8px 0 0'; p.textContent = rep.summary;
          li.append(head, p); ul.appendChild(li);
        }
        list.appendChild(ul);
      } else {
        const p = document.createElement('p'); p.className = 'muted'; p.style.margin = '0';
        p.textContent = 'No community reports found. This does not mean the number is safe. If it is threatening you, report it.';
        list.appendChild(p);
      }
      const ul = card.querySelector('[data-disc]');
      for (const d of r.disclaimers) { const li = document.createElement('li'); li.textContent = d; ul.appendChild(li); }
      out.appendChild(card);
    } catch (e) {
      out.innerHTML = '';
      HAD.alertBox(out, 'error', e.code === 'INVALID_PHONE' ? 'Check the number' : 'Search failed', e.message);
    }
  }
  form.addEventListener('submit', e => {
    e.preventDefault();
    const v = form.phone.value.trim();
    if (!v) { HAD.alertBox(out, 'error', 'Enter a phone number', 'Type the number you want to check.'); form.phone.focus(); return; }
    history.replaceState(null, '', location.pathname + '?phone=' + encodeURIComponent(v) + location.hash);
    run(v);
  });
  const pre = HAD.qs('phone');
  if (pre) { form.phone.value = pre; run(pre); }
}
