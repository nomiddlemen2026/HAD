'use strict';
// Evidence uploader with per-file progress and retry. Files are never dropped
// silently: a failed upload stays in the list with a Retry button.
function createUploader(root, { onUploaded } = {}) {
  root.innerHTML = `<div class="dropzone" tabindex="0" role="button" aria-label="Choose evidence files">
      <strong>Drop files here</strong> or <span style="color:var(--blue)">choose files</span>
      <input type="file" multiple hidden accept=".jpg,.jpeg,.png,.webp,.pdf,.txt,.mp3,.m4a,.ogg,.opus,.mp4">
    </div><div class="files"></div>`;
  const dz = root.querySelector('.dropzone'); const input = dz.querySelector('input'); const list = root.querySelector('.files');
  const items = [];
  let caseId = null;
  const ALLOWED = /\.(jpe?g|png|webp|pdf|txt|mp3|m4a|ogg|opus|mp4)$/i;
  function add(files) {
    for (const f of files) {
      const row = document.createElement('div'); row.className = 'upload-row';
      row.innerHTML = '<span class="name"></span><span class="small faint" data-size></span><span data-state class="small"></span><progress max="1" value="0" class="hidden"></progress><button type="button" class="btn sm hidden" data-retry>Retry</button><button type="button" class="btn sm ghost" data-remove aria-label="Remove">✕</button>';
      row.querySelector('.name').textContent = f.name;
      row.querySelector('[data-size]').textContent = HAD.fmtSize(f.size);
      const it = { file: f, row, state: 'queued' };
      if (!ALLOWED.test(f.name)) { it.state = 'invalid'; row.querySelector('[data-state]').textContent = 'File type not accepted'; row.querySelector('[data-state]').style.color = 'var(--danger)'; }
      else if (f.size > 25 * 1048576) { it.state = 'invalid'; row.querySelector('[data-state]').textContent = 'Over 25 MB'; row.querySelector('[data-state]').style.color = 'var(--danger)'; }
      else row.querySelector('[data-state]').textContent = 'Ready';
      row.querySelector('[data-remove]').onclick = () => { if (it.state === 'uploading') return; items.splice(items.indexOf(it), 1); row.remove(); };
      row.querySelector('[data-retry]').onclick = () => send(it);
      items.push(it); list.appendChild(row);
    }
    if (caseId) uploadAll(caseId);
  }
  async function send(it) {
    const st = it.row.querySelector('[data-state]'); const pr = it.row.querySelector('progress'); const rb = it.row.querySelector('[data-retry]');
    it.state = 'uploading'; rb.classList.add('hidden'); pr.classList.remove('hidden'); st.style.color = ''; st.textContent = 'Fingerprinting…';
    try {
      const hash = await HAD.sha256Hex(it.file);
      const fd = new FormData();
      if (hash) fd.append('sha256', hash);
      fd.append('file', it.file, it.file.name);
      st.textContent = 'Uploading…';
      const r = await HAD.upload(`/api/cases/${encodeURIComponent(caseId)}/evidence`, fd, p => { pr.value = p; });
      it.state = 'done'; pr.classList.add('hidden');
      st.textContent = r.duplicate ? 'Already in this case' : 'Saved · SHA-256 ' + r.evidence.sha256.slice(0, 12) + '…';
      st.style.color = 'var(--ok)';
      it.row.querySelector('[data-remove]').classList.add('hidden');
      if (onUploaded) onUploaded(r.evidence);
    } catch (e) {
      it.state = 'failed'; pr.classList.add('hidden'); st.textContent = e.message; st.style.color = 'var(--danger)'; rb.classList.remove('hidden');
    }
  }
  async function uploadAll(id) {
    caseId = id;
    for (const it of items) if (it.state === 'queued' || it.state === 'failed') await send(it);
    return { failed: items.filter(i => i.state === 'failed').length, done: items.filter(i => i.state === 'done').length };
  }
  dz.onclick = () => input.click();
  dz.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
  input.onchange = () => { add(input.files); input.value = ''; };
  dz.ondragover = e => { e.preventDefault(); dz.classList.add('drag'); };
  dz.ondragleave = () => dz.classList.remove('drag');
  dz.ondrop = e => { e.preventDefault(); dz.classList.remove('drag'); add(e.dataTransfer.files); };
  window.addEventListener('beforeunload', e => { if (items.some(i => i.state === 'uploading' || (caseId && i.state === 'failed'))) { e.preventDefault(); e.returnValue = ''; } });
  return { uploadAll, setCase: id => { caseId = id; }, pending: () => items.filter(i => i.state === 'queued' || i.state === 'failed').length, items };
}
