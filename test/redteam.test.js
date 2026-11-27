'use strict';
// Part 15 section I: final red-team scenarios, executed against the real API.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const request = require('supertest');
const { makeApp, client, newUser, newCase, baseReport } = require('./helpers');
const WA = fs.readFileSync(path.join(__dirname, 'fixtures', 'whatsapp-android.txt'));

test('RT1: false accusation is never auto-published and can be rejected/appealed', async () => {
  const app = await makeApp();
  const liar = await newUser(app);
  const mod = await newUser(app, 'moderator');
  const kase = await newCase(liar, 'Fake case');
  const rep = (await liar.post(`/api/cases/${kase.id}/reports`).send(baseReport({ phone: '+60 19-222 3333', description: 'This person is an ah long and a criminal, everyone should call him.' }))).body.report;
  await liar.post(`/api/cases/${kase.id}/evidence`).attach('file', Buffer.from('fake'), 'fake.txt');
  // Nothing public before review
  let s = await request(app).get('/api/search?phone=0192223333');
  assert.equal(s.body.reviewedReportCount, 0);
  // Moderator rejects
  assert.equal((await mod.post(`/api/mod/reports/${rep.id}/decision`).send({ decision: 'reject', note: 'No supporting evidence.' })).body.report.status, 'rejected');
  s = await request(app).get('/api/search?phone=0192223333');
  assert.equal(s.body.reviewedReportCount, 0);
  // Reporter cannot self-moderate even if they were a moderator
  await app.locals.db.prepare("UPDATE users SET role='moderator' WHERE id=?").run(liar.user.id);
  const rep2 = (await liar.post(`/api/cases/${kase.id}/reports`).send(baseReport({ phone: '+60 19-444 5555' }))).body.report;
  const self = await liar.post(`/api/mod/reports/${rep2.id}/decision`).send({ decision: 'publish', publicSummary: 'Reported for loan collection intimidation over WhatsApp.' });
  assert.equal(self.status, 403);
  assert.equal(self.body.error.code, 'CONFLICT_OF_INTEREST');
});

test('RT2: victim uploads home address — warned, never public, residence coordinates coarsened', async () => {
  const app = await makeApp();
  const v = await newUser(app);
  const kase = await newCase(v);
  const r = await v.post(`/api/cases/${kase.id}/reports`).send(baseReport({ description: 'They came to my house at No. 5 Jalan Mawar 3, Taman Melati and splashed red paint.' }));
  assert.equal(r.status, 201);
  assert.ok(r.body.warnings.length === 1 && /address/.test(r.body.warnings[0]));
  const loc = await v.post(`/api/cases/${kase.id}/locations`).send({ category: 'incident_location', label: 'My home', addressText: 'No. 5 Jalan Mawar 3', lat: 3.1412345, lng: 101.6865432, precision: 'exact', isPrivateResidence: true, isVictimLocation: true, sourceReference: 'Victim' });
  assert.equal(loc.status, 201);
  assert.equal(loc.body.location.precision, 'area');
  assert.equal(loc.body.location.lat, 3.14);
  assert.equal(loc.body.location.lng, 101.69);
  // Cannot be turned into a suspect location
  const bad = await v.post(`/api/cases/${kase.id}/locations`).send({ category: 'officially_confirmed_suspect_location', label: 'x', addressText: 'y', sourceReference: 'zzz', sourceReliability: 'official' });
  assert.equal(bad.status, 403);
  const s = await request(app).get('/api/search?phone=0123456789');
  assert.ok(!JSON.stringify(s.body).includes('Mawar'));
});

test('RT3: attacker cannot read, download, parse, redact or export another user\'s evidence/case', async () => {
  const app = await makeApp();
  const v = await newUser(app);
  const attacker = await newUser(app);
  const kase = await newCase(v);
  const ev = (await v.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat.txt')).body.evidence;
  const anon = client(app);
  for (const c of [attacker, anon]) {
    const want = c === anon ? 401 : 404;
    assert.equal((await c.get(`/api/evidence/${ev.id}`)).status, want);
    assert.equal((await c.get(`/api/evidence/${ev.id}/download`)).status, want);
    assert.equal((await c.post(`/api/evidence/${ev.id}/parse-whatsapp`).send({})).status, want);
    assert.equal((await c.post(`/api/evidence/${ev.id}/redacted`).attach('file', Buffer.from('x'), 'x.txt')).status, want);
    assert.equal((await c.get(`/api/cases/${kase.id}`)).status, want);
    assert.equal((await c.get(`/api/cases/${kase.id}/export.pdf`)).status, want);
    assert.equal((await c.post(`/api/cases/${kase.id}/evidence`).attach('file', Buffer.from('x'), 'x.txt')).status, want);
    assert.equal((await c.post(`/api/cases/${kase.id}/reports`).send(baseReport())).status, want);
  }
  // Static storage path is not served
  assert.equal((await request(app).get(`/storage/originals/${ev.id}`)).status, 404);
  assert.equal((await request(app).get(`/originals/${ev.id}`)).status, 404);
  // Path traversal in id is harmless
  assert.equal((await attacker.get('/api/evidence/..%2F..%2Fdata%2Fhad.db/download')).status, 404);
  // Attempts are audited, and no download event was written for the attacker
  const denied = (await app.locals.db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action IN ('denied_evidence_access','denied_case_access') AND actor_id = ?").get(attacker.user.id)).n;
  assert.ok(denied > 0);
  const dl = (await app.locals.db.prepare("SELECT COUNT(*) n FROM evidence_events WHERE actor_id = ? ").get(attacker.user.id)).n;
  assert.equal(dl, 0);
  // Attacker's case list is empty
  assert.equal((await attacker.get('/api/cases')).body.cases.length, 0);
});

test('RT4: 100 fake reports — capped, none published, public count unchanged', async () => {
  const app = await makeApp();
  const spammer = await newUser(app);
  const kase = await newCase(spammer);
  const codes = {};
  for (let i = 0; i < 100; i++) {
    const phone = '+6012' + String(1000000 + i);
    const r = await spammer.post(`/api/cases/${kase.id}/reports`).send(baseReport({ phone }));
    codes[r.status] = (codes[r.status] || 0) + 1;
  }
  assert.equal(codes[201], 5, 'only 5 accepted per hour');
  assert.equal(codes[429], 95);
  const pending = (await app.locals.db.prepare("SELECT COUNT(*) n FROM reports WHERE status='published'").get()).n;
  assert.equal(pending, 0);
  // Same number repeatedly from one account is blocked as duplicate
  const app2 = await makeApp();
  const s2 = await newUser(app2);
  const k2 = await newCase(s2);
  const results = [];
  for (let i = 0; i < 10; i++) results.push((await s2.post(`/api/cases/${k2.id}/reports`).send(baseReport())).status);
  assert.deepEqual(results, [201, 409, 409, 409, 409, 409, 409, 409, 409, 409]);
  // Distinct reporter count in public search counts accounts, not reports
  const mod = await newUser(app2, 'moderator');
  const rid = (await app2.locals.db.prepare('SELECT id FROM reports').get()).id;
  await s2.post(`/api/cases/${k2.id}/evidence`).attach('file', Buffer.from('e'), 'e.txt');
  await mod.post(`/api/mod/reports/${rid}/decision`).send({ decision: 'publish', publicSummary: 'Reported for loan collection intimidation over WhatsApp.' });
  const s = await request(app2).get('/api/search?phone=0123456789');
  assert.equal(s.body.distinctReporters, 1);
});

test('RT5: same number used by different people at different times — dates shown, reassignment warning, takedown path', async () => {
  const app = await makeApp();
  const v = await newUser(app);
  const mod = await newUser(app, 'moderator');
  const kase = await newCase(v);
  const rep = (await v.post(`/api/cases/${kase.id}/reports`).send(baseReport({ incidentAt: '2023-02-10' }))).body.report;
  await v.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat.txt');
  await mod.post(`/api/mod/reports/${rep.id}/decision`).send({ decision: 'publish', publicSummary: 'Reported for loan collection intimidation over WhatsApp messages.' });
  const s = await request(app).get('/api/search?phone=0123456789');
  assert.equal(s.body.reports[0].month, '2023-02');
  assert.ok(s.body.disclaimers.some(d => /recycled/.test(d)));
  assert.equal(s.body.lastReportedMonth, '2023-02');
});

test('RT6: Malaysian prefix used overseas — region labelled as numbering plan only, never a location', async () => {
  const app = await makeApp();
  const s = await request(app).get('/api/search?phone=%2B60123456789');
  assert.equal(s.body.numberingRegion, 'MY');
  assert.match(s.body.numberingRegionNote, /not where its user is/);
  assert.ok(s.body.disclaimers.some(d => /does not mean its user is in Malaysia/.test(d)));
  assert.ok(!('location' in s.body) && !('lat' in s.body));
});

test('RT7: inaccurate IP geolocation — forced to area precision, low reliability, cannot be verified', async () => {
  const app = await makeApp();
  const v = await newUser(app);
  const mod = await newUser(app, 'moderator');
  const kase = await newCase(v);
  const r = await v.post(`/api/cases/${kase.id}/locations`).send({ category: 'approximate_network_location', label: 'IP lookup from link click', lat: 3.1390123, lng: 101.6868555, precision: 'exact', sourceReliability: 'high', sourceReference: 'ipinfo lookup' });
  assert.equal(r.status, 201);
  assert.equal(r.body.location.precision, 'area');
  assert.equal(r.body.location.sourceReliability, 'low');
  assert.equal(r.body.location.lat, 3.14);
  assert.equal(r.body.location.verificationStatus, 'approximate');
  const vr = await mod.post(`/api/mod/locations/${r.body.location.id}/verify`).send({ verificationStatus: 'verified' });
  assert.equal(vr.status, 400);
});

test('RT8: two numbers wrongly associated — related numbers stay private and unverified, never merged in search', async () => {
  const app = await makeApp();
  const v = await newUser(app);
  const mod = await newUser(app, 'moderator');
  const kase = await newCase(v);
  const rep = (await v.post(`/api/cases/${kase.id}/reports`).send(baseReport({ relatedPhones: '+60 17-888 9999' }))).body.report;
  await v.post(`/api/cases/${kase.id}/evidence`).attach('file', WA, 'chat.txt');
  await mod.post(`/api/mod/reports/${rep.id}/decision`).send({ decision: 'publish', publicSummary: 'Reported for loan collection intimidation over WhatsApp messages.' });
  const other = await request(app).get('/api/search?phone=0178889999');
  assert.equal(other.body.reviewedReportCount, 0, 'a related number gets no reports by association');
  const main = await request(app).get('/api/search?phone=0123456789');
  assert.ok(!JSON.stringify(main.body).includes('888'), 'related numbers not exposed publicly');
});

test('RT9: regular user cannot reach moderator/admin functions; attempts audited', async () => {
  const app = await makeApp();
  const u = await newUser(app);
  const mod = await newUser(app, 'moderator');
  const calls = [
    u.get('/api/mod/queue'), u.get('/api/mod/appeals'),
    u.post('/api/mod/reports/x/decision').send({ decision: 'publish' }),
    u.post('/api/mod/reports/x/takedown').send({ note: 'x' }),
    u.post(`/api/admin/users/${u.user.id}/role`).send({ role: 'admin' }),
    u.post('/api/admin/cases/x/legal-hold').send({ hold: true }),
    mod.post(`/api/admin/users/${mod.user.id}/role`).send({ role: 'admin' }),
  ];
  for (const r of await Promise.all(calls)) assert.equal(r.status, 403);
  assert.equal((await u.get('/api/auth/me')).body.user.role, 'user');
  assert.equal((await mod.get('/api/auth/me')).body.user.role, 'moderator');
  const n = (await app.locals.db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action='forbidden_attempt'").get()).n;
  assert.equal(n, 7);
  // Mass-assignment: role in register body is ignored
  const c = client(app);
  const r = await c.post('/api/auth/register').send({ email: 'sneaky@example.com', password: 'correct-horse-battery', displayName: 'S', role: 'admin' });
  assert.equal(r.body.user.role, 'user');
});

test('RT10: account deletion with legal hold keeps held case + evidence, purges the rest', async () => {
  const app = await makeApp();
  const v = await newUser(app);
  const admin = await newUser(app, 'admin');
  const held = await newCase(v, 'Case under police investigation');
  const free = await newCase(v, 'Old case');
  const evHeld = (await v.post(`/api/cases/${held.id}/evidence`).attach('file', WA, 'chat.txt')).body.evidence;
  const evFree = (await v.post(`/api/cases/${free.id}/evidence`).attach('file', Buffer.from('other'), 'other.txt')).body.evidence;
  await v.post(`/api/cases/${free.id}/reports`).send(baseReport());
  assert.equal((await admin.post(`/api/admin/cases/${held.id}/legal-hold`).send({ hold: true, reason: 'PDRM request IPD/123/26' })).status, 200);
  assert.equal((await v.post('/api/account/delete').send({ password: 'wrong' })).status, 401);
  const d = await v.post('/api/account/delete').send({ password: 'correct-horse-battery' });
  assert.equal(d.status, 200);
  assert.equal(d.body.casesRetainedUnderLegalHold, 1);
  assert.equal(d.body.casesPurged, 1);
  const st = path.join(app.locals.dir, 'storage', 'originals');
  assert.ok(fs.existsSync(path.join(st, evHeld.id)), 'held evidence preserved');
  assert.ok(!fs.existsSync(path.join(st, evFree.id)), 'non-held evidence deleted');
  const u = await app.locals.db.prepare('SELECT * FROM users WHERE id = ?').get(v.user.id);
  assert.equal(u.email, null); assert.equal(u.status, 'deleted');
  assert.equal((await v.get('/api/cases')).status, 401);
  assert.equal((await v.post('/api/auth/login').send({ email: v.email, password: 'correct-horse-battery' })).status, 401);
  // Admin can still access held evidence; custody shows legal hold + later access
  const meta = await admin.get(`/api/evidence/${evHeld.id}`);
  assert.equal(meta.status, 200);
  assert.ok(meta.body.custody.some(e => e.event_type === 'legal_hold'));
  assert.equal((await admin.get(`/api/evidence/${evFree.id}`)).status, 410);
  // Purge recorded in custody chain of the deleted item
  const purge = (await app.locals.db.prepare("SELECT COUNT(*) n FROM evidence_events WHERE evidence_id = ? AND event_type = 'purge'").get(evFree.id)).n;
  assert.equal(purge, 1);
});
