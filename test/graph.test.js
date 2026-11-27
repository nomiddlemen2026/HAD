'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { makeApp, newUser, newCase, baseReport } = require('./helpers');

async function setup() {
  const app = await makeApp();
  const a = await newUser(app); const b = await newUser(app); const mod = await newUser(app, 'moderator');
  const ca = await newCase(a, 'Case A'); const cb = await newCase(b, 'Case B');
  const ra = (await a.post(`/api/cases/${ca.id}/reports`).send(baseReport({ phone: '012-345 6789', relatedPhones: '017-888 9999', relatedBankAccounts: '5000-1234-5678' }))).body.report;
  const rb = (await b.post(`/api/cases/${cb.id}/reports`).send(baseReport({ phone: '012-345 6789', relatedBankAccounts: '500012345678' }))).body.report;
  const rb2 = (await b.post(`/api/cases/${cb.id}/reports`).send(baseReport({ phone: '017-888 9999', category: 'harassment' }))).body.report;
  return { app, a, b, mod, ca, cb, ra, rb, rb2 };
}

test('staff graph finds same number, same account and possible association, each linked to reports', async () => {
  const { mod, ra, rb, rb2, ca, cb } = await setup();
  const g = (await mod.get('/api/graph?scope=all')).body;
  const same = g.findings.find(f => f.type === 'same_number' && f.identifier === '+60123456789');
  assert.ok(same); assert.deepEqual(same.cases.sort(), [ca.id, cb.id].sort()); assert.deepEqual(same.reports.sort(), [ra.id, rb.id].sort());
  const acct = g.findings.find(f => f.type === 'same_account');
  assert.equal(acct.identifier, '500012345678');
  const poss = g.findings.find(f => f.type === 'possible_association');
  assert.ok(poss, 'number named in A and reported in B is a possible association');
  assert.ok(poss.reports.includes(ra.id) && poss.reports.includes(rb2.id));
  assert.match(poss.note, /does not prove/);
  const nt = g.edges.find(e => e.type === 'named_together');
  assert.equal(nt.certainty, 'possible');
  for (const e of g.edges) assert.ok(e.reports.length >= 1, 'every edge links to reports');
});

test('victim view shows only own cases; other cases are never revealed, only reviewed counts', async () => {
  const { app, a, mod, cb, rb } = await setup();
  let g = (await a.get('/api/graph?scope=mine')).body;
  assert.ok(!g.nodes.some(n => n.id === 'case:' + cb.id), 'other victim case hidden');
  assert.equal(g.findings.length, 0, 'no cross-case findings exposed to victims');
  const phone = g.nodes.find(n => n.id === 'phone:+60123456789');
  assert.equal(phone.othersReviewed, 0, 'unreviewed reports by others are not counted');
  // After a moderator publishes B's report, A sees a count (no details)
  await app.locals.db.prepare("INSERT INTO evidence (id, case_id, uploader_id, original_filename, mime_type, size_bytes, sha256, storage_ref, uploaded_at) VALUES ('e1', ?, (SELECT owner_id FROM cases WHERE id = ?), 'x.txt', 'text/plain', 1, 'h', 'x', '2026-01-01')").run(cb.id, cb.id);
  assert.equal((await mod.post(`/api/mod/reports/${rb.id}/decision`).send({ decision: 'publish', publicSummary: 'Reported for loan collection intimidation over WhatsApp.' })).status, 200);
  g = (await a.get('/api/graph?scope=mine')).body;
  assert.equal(g.nodes.find(n => n.id === 'phone:+60123456789').othersReviewed, 1);
  assert.equal(g.nodes.find(n => n.id === 'account:500012345678').othersReviewed, 1, 'B\'s published report names the same account');
  assert.ok(!JSON.stringify(g).includes(rb.id), 'other report id not leaked');
});

test('moderator can remove a wrong link; it disappears for victims and can be restored', async () => {
  const { a, mod } = await setup();
  const g0 = (await mod.get('/api/graph?scope=all')).body;
  const nt = g0.edges.find(e => e.type === 'named_together');
  assert.equal((await mod.post('/api/mod/relationships').send({ key: nt.id, status: 'removed', note: 'Victim confirmed the second number was a typo.' })).status, 200);
  let mine = (await a.get('/api/graph?scope=mine')).body;
  assert.ok(!mine.edges.some(e => e.id === nt.id));
  assert.ok(!mine.nodes.some(n => n.id === 'phone:+60178889999'), 'orphaned node dropped');
  const staff = (await mod.get('/api/graph?scope=all')).body;
  assert.equal(staff.edges.find(e => e.id === nt.id).override.status, 'removed');
  await mod.post('/api/mod/relationships').send({ key: nt.id, status: 'clear' });
  mine = (await a.get('/api/graph?scope=mine')).body;
  assert.ok(mine.edges.some(e => e.id === nt.id));
});

test('graph access control and withdrawn reports', async () => {
  const { a, b, rb2 } = await setup();
  assert.equal((await a.get('/api/graph?scope=all')).status, 403);
  assert.equal((await a.post('/api/mod/relationships').send({ key: 'x|y|z', status: 'removed', note: 'nope' })).status, 403);
  await b.post(`/api/reports/${rb2.id}/withdraw`).send({});
  const g = (await b.get('/api/graph?scope=mine')).body;
  assert.ok(!g.nodes.some(n => n.id === 'phone:+60178889999'), 'withdrawn report not in graph');
});
