'use strict';
// Checks that matter only once the database is a shared Postgres server
// (Supabase): concurrency, API lock-down, and the private storage bucket.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { makeApp, newUser, newCase } = require('./helpers');
const { createStorage } = require('../src/storage');

test('custody chain stays intact under many concurrent accesses', async () => {
  const app = await makeApp();
  const c = await newUser(app);
  const kase = await newCase(c);
  const up = await c.post(`/api/cases/${kase.id}/evidence`).attach('file', Buffer.from('evidence body'), 'note.txt');
  assert.equal(up.status, 201);
  const id = up.body.evidence.id;
  await Promise.all(Array.from({ length: 25 }, () => c.get(`/api/evidence/${id}`)));
  const r = await c.get(`/api/evidence/${id}`);
  assert.equal(r.body.chainIntegrity.ok, true, JSON.stringify(r.body.chainIntegrity));
  assert.equal(r.body.chainIntegrity.entries, 27); // upload + 25 + this view
});

test('tables live outside "public" and have row level security switched on', async () => {
  const app = await makeApp();
  const db = app.locals.db;
  assert.notEqual(db.schema, 'public');
  const rows = await db.prepare('SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = ?').all(db.schema);
  assert.ok(rows.length >= 12, 'all tables created');
  for (const t of rows) assert.equal(t.rowsecurity, true, `${t.tablename} has RLS`);
  const pub = await db.prepare("SELECT COUNT(*) n FROM pg_tables WHERE schemaname = 'public' AND tablename IN ('users','evidence','reports')").get();
  assert.equal(pub.n, 0, 'nothing exposed in the public schema');
});

test('a failed database transaction leaves nothing half-saved', async () => {
  const app = await makeApp();
  const db = app.locals.db;
  await assert.rejects(db.tx(async () => {
    await db.prepare("INSERT INTO users (id, email, display_name, created_at) VALUES ('u-tx', 'tx@example.com', 'Tx', '2026-01-01')").run();
    throw new Error('boom');
  }), /boom/);
  assert.equal(await db.prepare("SELECT 1 FROM users WHERE id = 'u-tx'").get(), undefined);
});

// A tiny stand-in for the Supabase Storage API, enough to test our client.
function fakeSupabase({ publicBucket = false } = {}) {
  const objects = new Map(); const calls = [];
  let bucket = null;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', d => chunks.push(d));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      calls.push({ method: req.method, url: req.url, auth: req.headers.authorization, upsert: req.headers['x-upsert'] });
      const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
      if (req.headers.authorization !== 'Bearer service-key') return send(401, { error: 'unauthorized' });
      if (req.method === 'GET' && req.url === '/storage/v1/bucket/evidence') return bucket ? send(200, bucket) : send(404, { error: 'not found' });
      if (req.method === 'POST' && req.url === '/storage/v1/bucket') { bucket = { ...JSON.parse(body), public: publicBucket || JSON.parse(body).public }; return send(200, { name: 'evidence' }); }
      const m = req.url.match(/^\/storage\/v1\/object\/(?:authenticated\/)?evidence\/(.+)$/);
      if (m && req.method === 'POST') {
        if (objects.has(m[1]) && req.headers['x-upsert'] !== 'true') return send(400, { statusCode: '409', error: 'Duplicate' });
        objects.set(m[1], body); return send(200, { Key: m[1] });
      }
      if (m && req.method === 'GET') { if (!objects.has(m[1])) return send(400, { statusCode: '404' }); res.writeHead(200); return res.end(objects.get(m[1])); }
      if (req.method === 'DELETE' && req.url === '/storage/v1/object/evidence') { for (const k of JSON.parse(body).prefixes) objects.delete(k); return send(200, []); }
      send(404, {});
    });
  });
  return new Promise(resolve => server.listen(0, () => resolve({ server, objects, calls, url: `http://127.0.0.1:${server.address().port}`, setPublic: () => { bucket.public = true; } })));
}

test('Supabase storage: private bucket created, originals write-once, read back byte-identical, purge deletes', async () => {
  const fake = await fakeSupabase();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'had-st-'));
  const st = createStorage({ dir, supabaseUrl: fake.url, serviceKey: 'service-key', bucket: 'evidence' });
  assert.equal(st.kind, 'supabase');
  const tmp = path.join(dir, 'a'); fs.writeFileSync(tmp, 'original bytes');
  await st.putFromFile('ev1', tmp);
  assert.equal(fake.calls.find(c => c.method === 'POST' && c.url === '/storage/v1/bucket') !== undefined, true);
  assert.equal(fake.calls.find(c => c.url.endsWith('/evidence/ev1')).upsert, 'false');
  assert.equal((await st.get('ev1')).toString(), 'original bytes');
  const tmp2 = path.join(dir, 'b'); fs.writeFileSync(tmp2, 'tampered');
  await assert.rejects(st.putFromFile('ev1', tmp2), /Storage upload failed/);
  assert.equal((await st.get('ev1')).toString(), 'original bytes', 'original unchanged');
  assert.equal(await st.get('missing'), null);
  await st.remove(['ev1']);
  assert.equal(await st.get('ev1'), null);
  fake.server.close();
});

test('Supabase storage refuses to use a public bucket', async () => {
  const fake = await fakeSupabase({ publicBucket: true });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'had-st-'));
  const first = createStorage({ dir, supabaseUrl: fake.url, serviceKey: 'service-key', bucket: 'evidence' });
  const tmp = path.join(dir, 'a'); fs.writeFileSync(tmp, 'x');
  await first.putFromFile('ev1', tmp).catch(() => {}); // creates the (public) bucket
  const again = createStorage({ dir, supabaseUrl: fake.url, serviceKey: 'service-key', bucket: 'evidence' });
  const tmp2 = path.join(dir, 'b'); fs.writeFileSync(tmp2, 'y');
  await assert.rejects(again.putFromFile('ev2', tmp2), /PUBLIC/);
  fake.server.close();
});

test('evidence upload and download work end to end through Supabase storage', async () => {
  const fake = await fakeSupabase();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'had-st-'));
  const storage = createStorage({ dir, supabaseUrl: fake.url, serviceKey: 'service-key', bucket: 'evidence' });
  const app = await makeApp({ storage });
  const c = await newUser(app);
  const kase = await newCase(c);
  const body = Buffer.from('screenshot bytes');
  const up = await c.post(`/api/cases/${kase.id}/evidence`).attach('file', body, 'shot.png');
  assert.equal(up.status, 201, JSON.stringify(up.body));
  assert.ok(fake.objects.has(up.body.evidence.id), 'stored in the bucket');
  const dl = await c.get(`/api/evidence/${up.body.evidence.id}/download`).buffer(true).parse((res, cb) => { const b = []; res.on('data', d => b.push(d)); res.on('end', () => cb(null, Buffer.concat(b))); });
  assert.equal(dl.status, 200);
  assert.deepEqual(dl.body, body);
  const other = await newUser(app);
  assert.equal((await other.get(`/api/evidence/${up.body.evidence.id}/download`)).status, 404);
  fake.server.close();
});
