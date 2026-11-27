'use strict';
/**
 * Evidence file storage. Originals are write-once in both back ends.
 *  - local:    files on disk, chmod 0444 (development, tests, the demo)
 *  - supabase: a PRIVATE Supabase Storage bucket, reached only by the server
 *              with the service-role key. There are no public URLs and no
 *              signed URLs: every download goes through H.A.D's access checks
 *              and is written to the chain of custody.
 */
const fs = require('fs');
const path = require('path');

function localStorage(dir) {
  const originals = path.join(dir, 'originals');
  fs.mkdirSync(originals, { recursive: true });
  const file = ref => path.join(originals, path.basename(ref));
  return {
    kind: 'local',
    async putFromFile(ref, tmpPath) {
      const dest = file(ref);
      if (fs.existsSync(dest)) throw new Error('Refusing to overwrite an original');
      fs.renameSync(tmpPath, dest);
      fs.chmodSync(dest, 0o444);
    },
    async get(ref) {
      const p = file(ref);
      if (!fs.existsSync(p)) return null;
      return fs.readFileSync(p);
    },
    async remove(refs) {
      for (const ref of refs) { try { fs.chmodSync(file(ref), 0o600); fs.unlinkSync(file(ref)); } catch (_) { /* already gone */ } }
    },
  };
}

function supabaseStorage({ url, serviceKey, bucket, prefix = '' }) {
  const base = url.replace(/\/+$/, '') + '/storage/v1';
  const headers = { Authorization: `Bearer ${serviceKey}`, apikey: serviceKey };
  const key = ref => encodeURIComponent(prefix + path.basename(ref)).replace(/%2F/g, '/');
  let ready = null;
  async function ensureBucket() {
    if (!ready) {
      ready = (async () => {
        const r = await fetch(`${base}/bucket/${bucket}`, { headers });
        if (r.ok) {
          const b = await r.json();
          if (b.public) throw new Error(`Storage bucket "${bucket}" is PUBLIC. Make it private in Supabase before storing evidence.`);
          return;
        }
        const c = await fetch(`${base}/bucket`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ id: bucket, name: bucket, public: false }) });
        if (!c.ok && c.status !== 409) throw new Error(`Could not create storage bucket (${c.status}): ${await c.text()}`);
      })().catch(e => { ready = null; throw e; });
    }
    return ready;
  }
  return {
    kind: 'supabase',
    async putFromFile(ref, tmpPath) {
      await ensureBucket();
      const body = fs.readFileSync(tmpPath);
      // x-upsert: false makes the object write-once: a second write is refused.
      const r = await fetch(`${base}/object/${bucket}/${key(ref)}`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/octet-stream', 'x-upsert': 'false' }, body });
      if (!r.ok) { const e = new Error(`Storage upload failed (${r.status})`); e.code = 'STORAGE_UNAVAILABLE'; throw e; }
      fs.unlinkSync(tmpPath);
    },
    async get(ref) {
      await ensureBucket();
      const r = await fetch(`${base}/object/authenticated/${bucket}/${key(ref)}`, { headers });
      if (r.status === 404 || r.status === 400) return null;
      if (!r.ok) { const e = new Error(`Storage download failed (${r.status})`); e.code = 'STORAGE_UNAVAILABLE'; throw e; }
      return Buffer.from(await r.arrayBuffer());
    },
    async remove(refs) {
      if (!refs.length) return;
      await ensureBucket();
      await fetch(`${base}/object/${bucket}`, { method: 'DELETE', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ prefixes: refs.map(r => prefix + path.basename(r)) }) });
    },
  };
}

function createStorage({ dir, supabaseUrl = process.env.SUPABASE_URL, serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY,
  bucket = process.env.HAD_STORAGE_BUCKET || 'evidence', prefix = process.env.HAD_STORAGE_PREFIX || '', forceLocal = false } = {}) {
  if (!forceLocal && supabaseUrl && serviceKey) return supabaseStorage({ url: supabaseUrl, serviceKey, bucket, prefix });
  return localStorage(dir);
}

module.exports = { createStorage };
