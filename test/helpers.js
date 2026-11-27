'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');
const { createApp } = require('../src/app');

function makeApp(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'had-test-'));
  const sent = [];
  const mailer = { configured: true, send: async (to, subject, text) => { sent.push({ to, subject, text }); } };
  const app = createApp({ dbPath: path.join(dir, 'test.db'), storageDir: path.join(dir, 'storage'), quiet: true, mailer, ...opts,
    limits: { register: [1000, 3600e3], login: [1000, 900e3], search: [1000, 60e3], uploads: [1000, 3600e3], appeals: [1000, 3600e3], ...(opts.limits || {}) } });
  app.locals.dir = dir;
  app.locals.sent = sent;
  return app;
}

// Agent that keeps cookies and always sends the CSRF header.
function client(app) {
  const agent = request.agent(app);
  const h = r => r.set('X-HAD-Request', '1');
  return {
    agent,
    get: u => agent.get(u),
    post: u => h(agent.post(u)),
    patch: u => h(agent.patch(u)),
    del: u => h(agent.delete(u)),
  };
}

let n = 0;
async function newUser(app, role = 'user') {
  const c = client(app);
  const email = `user${++n}_${Date.now()}@example.com`;
  const res = await c.post('/api/auth/register').send({ email, password: 'correct-horse-battery', displayName: 'Tester ' + n });
  if (res.status !== 201) throw new Error('register failed ' + res.status + JSON.stringify(res.body));
  c.user = res.body.user; c.email = email;
  if (role !== 'user') app.locals.db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, c.user.id);
  return c;
}

async function newCase(c, title = 'Harassment by unknown lender') {
  const r = await c.post('/api/cases').send({ title, description: 'Private notes' });
  if (r.status !== 201) throw new Error('case failed ' + JSON.stringify(r.body));
  return r.body.case;
}

const baseReport = (over = {}) => ({ phone: '012-345 6789', category: 'loan_intimidation', channel: 'whatsapp_message', description: 'Repeated demands for payment with threats to come to my house.', incidentAt: '2026-10-01T21:15', ...over });

module.exports = { makeApp, client, newUser, newCase, baseReport };
