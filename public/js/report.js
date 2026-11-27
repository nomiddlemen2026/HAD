'use strict';
(async () => {
  await HAD.appShell('/report.html');
  const form = document.getElementById('report-form');
  const msg = document.getElementById('msg');
  HAD.fillSelect(form.channel, HAD.LABELS.channel, 'Choose…');
  HAD.fillSelect(form.category, HAD.LABELS.category, 'Choose…');
  const { cases } = await HAD.api('GET', '/api/cases');
  const opts = { '': '+ Start a new case' };
  for (const c of cases.filter(c => c.status === 'open')) opts[c.id] = c.title;
  HAD.fillSelect(form.caseId, opts);
  const pre = HAD.qs('case'); if (pre && opts[pre]) form.caseId.value = pre;
  const newField = document.getElementById('newCaseField');
  const toggle = () => newField.classList.toggle('hidden', !!form.caseId.value);
  form.caseId.addEventListener('change', toggle);
  const draft = HAD.keepDraft(form, 'report');
  toggle();
  const newKey = () => { form.idempotencyKey.value = crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random(); };
  newKey();
  const uploader = createUploader(document.getElementById('uploader'));
  let caseId = null; let reportDone = false;

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const d = HAD.formObject(form);
    const need = [['phone', 'Enter the suspected phone number.'], ['channel', 'Choose how they contacted you.'], ['category', 'Choose a threat category.'], ['description', 'Describe what happened (at least 10 characters).']];
    for (const [n, m] of need) {
      if (!d[n] || (n === 'description' && d[n].trim().length < 10)) { form[n].setAttribute('aria-invalid', 'true'); form[n].focus(); return HAD.alertBox(msg, 'error', 'Missing information', m); }
      form[n].removeAttribute('aria-invalid');
    }
    if (!d.caseId && !reportDone && (!d.caseTitle || d.caseTitle.trim().length < 3)) d.caseTitle = `Threats from ${d.phone}`;
    const btn = document.getElementById('submit'); btn.disabled = true;
    HAD.alertBox(msg, 'info', 'Submitting…', 'Please keep this page open.');
    const warnings = [];
    try {
      caseId = caseId || d.caseId || (await HAD.api('POST', '/api/cases', { title: d.caseTitle, description: '' })).case.id;
      if (!reportDone) {
        const r = await HAD.api('POST', `/api/cases/${caseId}/reports`, {
          phone: d.phone, channel: d.channel, category: d.category, description: d.description, incidentAt: d.incidentAt || undefined,
          relatedPhones: d.relatedPhones, relatedBankAccounts: d.relatedBankAccounts, policeReportRef: d.policeReportRef, idempotencyKey: d.idempotencyKey,
        });
        warnings.push(...(r.warnings || []));
        const reportId = r.report.id;
        const locs = [];
        if (d.incLabel || d.incAddress) locs.push({ category: 'incident_location', label: d.incLabel || 'Incident location', addressText: d.incAddress, precision: 'area', isPrivateResidence: d.incIsHome, isVictimLocation: d.incIsHome, sourceReference: 'Victim statement in report', reportId });
        if (d.thrLabel || d.thrAddress) locs.push({ category: 'location_mentioned_in_threat', label: d.thrLabel || 'Place mentioned in threat', addressText: d.thrAddress, precision: 'area', sourceReference: 'Threat message as described by victim', reportId });
        for (const l of locs) {
          if (!l.addressText) { warnings.push(`"${l.label}" was not saved as a location because it had no address or area.`); continue; }
          await HAD.api('POST', `/api/cases/${caseId}/locations`, l);
        }
        reportDone = true; // retries reuse the idempotency key, so the report is never duplicated
      }
      const up = await uploader.uploadAll(caseId);
      draft.clear();
      if (up.failed) {
        HAD.alertBox(msg, 'warn', 'Report saved, but some files did not upload', `${up.failed} file(s) failed. They are still listed below. Press Retry on each, or add them later from your case page.`);
        btn.textContent = 'Retry failed uploads'; btn.disabled = false;
        return;
      }
      location.href = `/case.html?id=${encodeURIComponent(caseId)}&submitted=1${warnings.length ? '&warn=' + encodeURIComponent(warnings.join(' ')) : ''}`;
    } catch (err) {
      btn.disabled = false;
      HAD.alertBox(msg, 'error', err.code === 'NETWORK' ? 'Connection problem' : 'Could not submit', err.message + (err.code === 'NETWORK' ? '' : ' Your answers are still here.'));
      HAD.markInvalid(form, err);
    }
  });
})().catch(e => HAD.alertBox('#msg', 'error', 'Could not load the form', e.message));
