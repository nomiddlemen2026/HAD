'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const request = require('supertest');
const { makeApp, client, newUser, newCase, baseReport } = require('./helpers');

const WA = fs.readFileSync(path.join(__dirname, 'fixtures', 'whatsapp-android.txt'));

test('migrations run and health reports them', async () => {
  const app = makeApp();
  const r = await request(app).get('/api/health');
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.migrations, ['001_init.sql', '002_community_map.sql', '003_relationship_overrides.sql']);
  // Re-running migrate is a no-op
  const { migrate } = require('../src/db');
  assert.deepEqual(migrate(app.locals.db), []);
});

test('authentication: register, me, logout, login, wrong password, unauthenticated access', async () => {
  const app = makeApp();
  const c = await newUser(app);
  assert.equal((await c.get('/api/auth/me')).body.user.email, c.email);
  assert.equal((await c.post('/api/auth/logout')).status, 200);
  assert.equal((await c.get('/api/auth/me')).status, 401);
  assert.equal((await c.get('/api/cases')).status, 401);
  const bad = await c.post('/api/auth/login').send({ email: c.email, password: 'wrong-password-123' });
  assert.equal(bad.status, 401);
  const unknown = await c.post('/api/auth/login').send({ email: 'nobody@example.com', password: 'wrong-password-123' });
  assert.equal(unknown.status, 401);
  assert.equal(unknown.body.error.message, bad.body.error.message, 'no account enumeration via login message');
  const ok = await c.post('/api/auth/login').send({ email: c.email, password: 'correct-horse-battery' });
  assert.equal(ok.status, 200);
  assert.equal((await c.get('/api/cases')).status, 200);
});

test('registration validation', async () => {
  const app = makeApp();
  const c = client(app);
  assert.equal((await c.post('/api/auth/register').send({ email: 'bad', password: 'correct-horse-battery', displayName: 'x' })).status, 400);
  assert.equal((await c.post('/api/auth/register').send({ email: 'a@b.co', password: 'short', displayName: 'x' })).status, 400);
  assert.equal((await c.post('/api/auth/register').send({ email: 'a@b.co', password: 'correct-horse-battery', displayName: '' })).status, 400);
});

test('session cookie is httpOnly and requests without CSRF header are refused', async () => {
  const app = makeApp();
  const r = await request(app).post('/api/auth/register').set('X-HAD-Request', '1').send({ email: 'c@d.co', password: 'correct-horse-battery', displayName: 'C' });
  assert.match(r.headers['set-cookie'][0], /HttpOnly/i);
  assert.match(r.headers['set-cookie'][0], /SameSite=Lax/i);
  const noHeader = await request(app).post('/api/auth/login').send({ email: 'c@d.co', password: 'correct-horse-battery' });
  assert.equal(noHeader.status, 403);
});

test('expired session returns AUTH_EXPIRED', async () => {
  const app = makeApp();
  const c = await newUser(app);
  app.locals.db.prepare("UPDATE sessions SET expires_at = '2000-01-01T00:00:00.000Z'").run();
  const r = await c.get('/api/cases');
  assert.equal(r.status, 401);
  assert.equal(r.body.error.code, 'AUTH_EXPIRED');
});

test('password recovery: generic response, token works once, old sessions revoked', async () => {
  const app = makeApp();
  const c = await newUser(app);
  const anon = client(app);
  const r1 = await anon.post('/api/auth/forgot').send({ email: c.email });
  const r2 = await anon.post('/api/auth/forgot').send({ email: 'nobody@example.com' });
  assert.equal(r1.body.message, r2.body.message);
  assert.equal(app.locals.sent.length, 1);
  const token = app.locals.sent[0].text.match(/token=([\w-]+)/)[1];
  assert.equal((await anon.post('/api/auth/reset').send({ token, password: 'brand-new-password-1' })).status, 200);
  assert.equal((await anon.post('/api/auth/reset').send({ token, password: 'another-password-22' })).status, 400, 'token single-use');
  assert.equal((await c.get('/api/cases')).status, 401, 'existing sessions revoked');
  assert.equal((await anon.post('/api/auth/login').send({ email: c.email, password: 'brand-new-password-1' })).status, 200);
});

test('phone normalisation and invalid numbers', async () => {
  const { normalizePhone, maskPhone } = require('../src/phone');
  assert.equal(normalizePhone('012-345 6789').e164, '+60123456789');
  assert.equal(normalizePhone('+60 12-345 6789').e164, '+60123456789');
  assert.equal(normalizePhone('+65 8123 4567').e164, '+6581234567');
  assert.equal(normalizePhone('12345'), null);
  assert.equal(normalizePhone('abc'), null);
  assert.equal(maskPhone('+60123456789'), '+60 12*****89');
  const app = makeApp();
  const r = await request(app).get('/api/search?phone=123');
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, 'INVALID_PHONE');
});

test('reports: validation, private by default, duplicate + idempotency handling', async () => {
  const app = makeApp();
  const c = await newUser(app);
  const kase = await newCase(c);
  assert.equal((await c.post(`/api/cases/${kase.id}/reports`).send(baseReport({ phone: 'xyz' }))).status, 400);
  assert.equal((await c.post(`/api/cases/${kase.id}/reports`).send(baseReport({ category: 'nope' }))).status, 400);
  assert.equal((await c.post(`/api/cases/${kase.id}/reports`).send(baseReport({ channel: undefined }))).status, 400);
  assert.equal((await c.post(`/api/cases/${kase.id}/reports`).send(baseReport({ description: 'short' }))).status, 400);
  assert.equal((await c.post(`/api/cases/${kase.id}/reports`).send(baseReport({ incidentAt: '2099-01-01' }))).status, 400);
  const key = crypto.randomUUID();
  const r = await c.post(`/api/cases/${kase.id}/reports`).send(baseReport({ idempotencyKey: key, relatedPhones: '019-876 5432, +60123456789', relatedBankAccounts: '1234-5678-9012', policeReportRef: 'IPD/123/26' }));
  assert.equal(r.status, 201);
  assert.equal(r.body.report.status, 'pending_review');
  assert.deepEqual(r.body.report.relatedPhones, ['+60198765432'], 'own number deduped from related list');
  assert.deepEqual(r.body.report.relatedBankAccounts, ['123456789012']);
  // Network retry with same key returns the same report, not a new one
  const retry = await c.post(`/api/cases/${kase.id}/reports`).send(baseReport({ idempotencyKey: key }));
  assert.equal(retry.status, 200);
  assert.equal(retry.body.report.id, r.body.report.id);
  assert.equal(retry.body.duplicate, true);
  // Same number again within 24h without key -> 409
  const dup = await c.post(`/api/cases/${kase.id}/reports`).send(baseReport());
  assert.equal(dup.status, 409);
  // Not visible publicly
  const s = await request(app).get('/api/search?phone=0123456789');
  assert.equal(s.body.reviewedReportCount, 0);
  assert.equal(s.body.status, 'No community reports found.');
});

test('evidence: upload, hash, original preserved read-only, duplicate kept, custody log, redacted copy', async () => {
  const app = makeApp();
  const c = await newUser(app);
  const kase = await newCase(c);
  const up = await c.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat.txt');
  assert.equal(up.status, 201, JSON.stringify(up.body));
  const ev = up.body.evidence;
  assert.equal(ev.sha256, crypto.createHash('sha256').update(WA).digest('hex'));
  const stored = path.join(app.locals.dir, 'storage', 'originals', ev.id);
  assert.ok(fs.existsSync(stored));
  assert.equal(fs.statSync(stored).mode & 0o222, 0, 'original is read-only');
  const dup = await c.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat-again.txt');
  assert.equal(dup.status, 200);
  assert.equal(dup.body.duplicate, true);
  assert.equal(dup.body.evidence.id, ev.id);
  // Redacted copy does not change the original
  const red = await c.post(`/api/evidence/${ev.id}/redacted`).field('note', 'removed my address').attach('file', Buffer.from('redacted text'), 'chat-redacted.txt');
  assert.equal(red.status, 201);
  assert.equal(red.body.evidence.derivedFrom, ev.id);
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(stored)).digest('hex'), ev.sha256);
  // Download returns identical bytes
  const dl = await c.get(`/api/evidence/${ev.id}/download`).buffer(true).parse((res, cb) => { const d = []; res.on('data', x => d.push(x)); res.on('end', () => cb(null, Buffer.concat(d))); });
  assert.equal(dl.status, 200);
  assert.ok(Buffer.compare(dl.body, WA) === 0);
  assert.equal(dl.headers['x-evidence-sha256'], ev.sha256);
  const meta = await c.get(`/api/evidence/${ev.id}`);
  const types = meta.body.custody.map(e => e.event_type);
  for (const t of ['upload', 'duplicate_upload', 'redaction', 'download', 'access']) assert.ok(types.includes(t), 'custody has ' + t);
  assert.equal(meta.body.chainIntegrity.ok, true);
  assert.equal(meta.body.derivedCopies.length, 1);
  // Custody log is append-only at the database level
  assert.throws(() => app.locals.db.prepare('DELETE FROM evidence_events').run(), /append-only/);
  assert.throws(() => app.locals.db.prepare("UPDATE evidence_events SET actor_id = 'x'").run(), /append-only/);
});

test('evidence: rejects bad types, oversize files, missing file; temp files cleaned', async () => {
  const app = makeApp({ maxUploadBytes: 1024 });
  const c = await newUser(app);
  const kase = await newCase(c);
  assert.equal((await c.post(`/api/cases/${kase.id}/evidence`).attach('file', Buffer.from('MZ...'), 'evil.exe')).status, 415);
  assert.equal((await c.post(`/api/cases/${kase.id}/evidence`).attach('file', Buffer.alloc(4096), 'big.png')).status, 413);
  assert.equal((await c.post(`/api/cases/${kase.id}/evidence`).send({})).status, 400);
  assert.equal(fs.readdirSync(path.join(app.locals.dir, 'storage', 'tmp')).length, 0);
  // Client-side hash mismatch = corrupted transfer, nothing saved
  const mm = await c.post(`/api/cases/${kase.id}/evidence`).field('sha256', 'a'.repeat(64)).attach('file', Buffer.from('hello'), 'a.txt');
  assert.equal(mm.status, 422);
  assert.equal((await c.get(`/api/cases/${kase.id}`)).body.evidence.length, 0);
});

test('WhatsApp parse via API records processing in custody without touching original', async () => {
  const app = makeApp();
  const c = await newUser(app);
  const kase = await newCase(c);
  const ev = (await c.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat.txt')).body.evidence;
  const r = await c.post(`/api/evidence/${ev.id}/parse-whatsapp`).send({});
  assert.equal(r.status, 200);
  assert.ok(r.body.result.messages.length >= 5);
  assert.ok(r.body.result.disclaimers.some(d => /not been independently authenticated/.test(d)));
  const meta = await c.get(`/api/evidence/${ev.id}`);
  assert.ok(meta.body.custody.some(e => e.event_type === 'processing' && e.details.action === 'whatsapp_parse'));
});

test('case PDF export produces a real PDF and is logged', async () => {
  const app = makeApp();
  const c = await newUser(app);
  const kase = await newCase(c);
  await c.post(`/api/cases/${kase.id}/reports`).send(baseReport({ policeReportRef: 'IPD/999/26' }));
  const ev = (await c.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat.txt')).body.evidence;
  await c.post(`/api/cases/${kase.id}/locations`).send({ category: 'incident_location', label: 'Outside my office', addressText: 'Petaling Jaya', precision: 'area', sourceReference: 'Victim statement', country: 'MY' });
  const r = await c.get(`/api/cases/${kase.id}/export.pdf`).buffer(true).parse((res, cb) => { const d = []; res.on('data', x => d.push(x)); res.on('end', () => cb(null, Buffer.concat(d))); });
  assert.equal(r.status, 200);
  assert.equal(r.headers['content-type'], 'application/pdf');
  assert.equal(r.body.slice(0, 5).toString(), '%PDF-');
  assert.ok(r.body.length > 2000);
  const meta = await c.get(`/api/evidence/${ev.id}`);
  assert.ok(meta.body.custody.some(e => e.event_type === 'export'));
});

test('moderation: publish requires evidence, PII-free summary, not own report; search then shows masked result', async () => {
  const app = makeApp();
  const victim = await newUser(app);
  const mod = await newUser(app, 'moderator');
  const kase = await newCase(victim);
  const rep = (await victim.post(`/api/cases/${kase.id}/reports`).send(baseReport())).body.report;
  const summary = 'Reported for repeated loan collection intimidation over WhatsApp, including threats to visit the home.';
  let r = await mod.post(`/api/mod/reports/${rep.id}/decision`).send({ decision: 'publish', publicSummary: summary });
  assert.equal(r.body.error.code, 'NO_EVIDENCE');
  await victim.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat.txt');
  r = await mod.post(`/api/mod/reports/${rep.id}/decision`).send({ decision: 'publish', publicSummary: 'Lives at No. 12 Jalan Bunga, call 0123456789' });
  assert.equal(r.body.error.code, 'PII_IN_SUMMARY');
  r = await mod.post(`/api/mod/reports/${rep.id}/decision`).send({ decision: 'publish', publicSummary: summary });
  assert.equal(r.status, 200);
  const s = await request(app).get('/api/search?phone=%2B60123456789');
  assert.equal(s.body.reviewedReportCount, 1);
  assert.equal(s.body.number, '+60 12*****89');
  assert.equal(s.body.reports[0].summary, summary);
  const body = JSON.stringify(s.body);
  assert.ok(!body.includes('Repeated demands'), 'private description never public');
  assert.ok(!body.includes(victim.user.displayName), 'victim name never public');
  assert.ok(!body.includes('+60123456789'), 'full number not shown');
});

test('appeals: public filing, moderator upholds, report taken down', async () => {
  const app = makeApp();
  const victim = await newUser(app);
  const mod = await newUser(app, 'moderator');
  const kase = await newCase(victim);
  const rep = (await victim.post(`/api/cases/${kase.id}/reports`).send(baseReport())).body.report;
  await victim.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat.txt');
  await mod.post(`/api/mod/reports/${rep.id}/decision`).send({ decision: 'publish', publicSummary: 'Reported for loan collection intimidation over WhatsApp messages.' });
  const anon = client(app);
  const a = await anon.post('/api/appeals').send({ type: 'takedown', phone: '0123456789', requesterName: 'Number owner', requesterContact: 'owner@example.com', reason: 'I received this number from my telco in November 2026; reports are about the previous user.' });
  assert.equal(a.status, 201);
  const list = await mod.get('/api/mod/appeals');
  assert.equal(list.body.appeals.length, 1);
  const d = await mod.post(`/api/mod/appeals/${a.body.id}/decision`).send({ decision: 'upheld', note: 'Number reassigned; confirmed with telco letter.' });
  assert.equal(d.body.takenDown, 1);
  const s = await request(app).get('/api/search?phone=0123456789');
  assert.equal(s.body.reviewedReportCount, 0);
});

test('search rate limit', async () => {
  const app = makeApp({ limits: { search: [3, 60e3] } });
  for (let i = 0; i < 3; i++) assert.equal((await request(app).get('/api/search?phone=0123456789')).status, 200);
  const r = await request(app).get('/api/search?phone=0123456789');
  assert.equal(r.status, 429);
  assert.ok(r.headers['retry-after']);
});

test('database failure returns 503 with a clear message', async () => {
  const app = makeApp();
  const c = await newUser(app);
  app.locals.db.close();
  const r = await c.get('/api/cases');
  assert.equal(r.status, 503);
  assert.equal(r.body.error.code, 'DB_UNAVAILABLE');
  assert.match(r.body.error.message, /NOT saved/);
});

test('security headers and no secrets in static frontend', async () => {
  const app = makeApp();
  const r = await request(app).get('/');
  assert.equal(r.status, 200);
  assert.ok(r.headers['content-security-policy']);
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  const pub = path.join(__dirname, '..', 'public');
  for (const f of fs.readdirSync(pub, { recursive: true })) {
    const p = path.join(pub, f);
    if (fs.statSync(p).isFile()) assert.ok(!/SMTP_URL|password_hash|service_role|secret/i.test(fs.readFileSync(p, 'utf8')), 'no secrets in ' + f);
  }
});
