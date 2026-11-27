'use strict';
/**
 * Creates a SEPARATE demo database (default data/demo.db) filled with clearly
 * labelled synthetic data. It refuses to touch the real database.
 * Run the demo with:  HAD_DEMO_MODE=1 HAD_DB_PATH=data/demo.db HAD_STORAGE_DIR=storage-demo npm start
 */
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const dbPath = path.resolve(process.env.HAD_DB_PATH || path.join(root, 'data', 'demo.db'));
const storageDir = path.resolve(process.env.HAD_STORAGE_DIR || path.join(root, 'storage-demo'));
if (!/demo/i.test(path.basename(dbPath)) || !/demo/i.test(path.basename(storageDir))) {
  console.error('Refusing: demo data must go into a database and storage folder whose names contain "demo".');
  process.exit(1);
}
for (const p of [dbPath, dbPath + '-wal', dbPath + '-shm']) if (fs.existsSync(p)) fs.rmSync(p);
if (fs.existsSync(storageDir)) { for (const f of fs.readdirSync(path.join(storageDir, 'originals'), { withFileTypes: true }).filter(d => d.isFile())) fs.chmodSync(path.join(storageDir, 'originals', f.name), 0o600); fs.rmSync(storageDir, { recursive: true }); }

const { createApp } = require('../src/app');
const app = createApp({ dbPath, storageDir, demoMode: true, quiet: true, limits: { register: [100, 1], reportsPerHour: [100, 1] } });

const server = app.listen(0, async () => {
  const base = `http://127.0.0.1:${server.address().port}`;
  const mk = () => {
    let cookie = '';
    const call = async (method, url, body, isForm) => {
      const headers = { 'X-HAD-Request': '1', cookie };
      if (body && !isForm) headers['Content-Type'] = 'application/json';
      const r = await fetch(base + url, { method, headers, body: isForm ? body : body ? JSON.stringify(body) : undefined });
      const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(`${method} ${url} -> ${r.status} ${JSON.stringify(j)}`);
      return j;
    };
    return call;
  };
  try {
    const db = app.locals.db;
    const victim = mk(); const victim2 = mk(); const mod = mk(); const admin = mk();
    await victim('POST', '/api/auth/register', { email: 'victim@demo.had', password: 'demo-password-123', displayName: '[DEMO] Aisyah' });
    await victim2('POST', '/api/auth/register', { email: 'victim2@demo.had', password: 'demo-password-123', displayName: '[DEMO] Kumar' });
    const m = await mod('POST', '/api/auth/register', { email: 'moderator@demo.had', password: 'demo-password-123', displayName: '[DEMO] Moderator' });
    const a = await admin('POST', '/api/auth/register', { email: 'admin@demo.had', password: 'demo-password-123', displayName: '[DEMO] Admin' });
    db.prepare("UPDATE users SET role='moderator' WHERE id=?").run(m.user.id);
    db.prepare("UPDATE users SET role='admin' WHERE id=?").run(a.user.id);

    const c1 = (await victim('POST', '/api/cases', { title: '[DEMO] Ahlong threats after RM3,000 loan', description: 'Synthetic demo case.' })).case;
    const r1 = (await victim('POST', `/api/cases/${c1.id}/reports`, { phone: '+60 11-1000 2001', channel: 'whatsapp_message', category: 'threat_property', incidentAt: '2026-10-14T22:10', description: '[DEMO] Messages demanding RM800 by Friday, threatening to splash red paint on my house. Synthetic text for demonstration.', relatedPhones: '+60 11-1000 2002', relatedBankAccounts: '5000 1234 5678', policeReportRef: 'DEMO/IPD/0001/26' })).report;
    const chat = fs.readFileSync(path.join(root, 'test', 'fixtures', 'whatsapp-android.txt'), 'utf8').replace(/\+60 12-345 6789/g, '+60 11-1000 2001').replace(/012-3456789/g, '011-1000 2001');
    let fd = new FormData(); fd.append('file', new Blob(['[DEMO SYNTHETIC CHAT]\n' + chat]), 'WhatsApp Chat - DEMO.txt');
    const ev1 = (await victim('POST', `/api/cases/${c1.id}/evidence`, fd, true)).evidence;
    fd = new FormData(); fd.append('file', new Blob(['%PDF-1.4\n% DEMO placeholder police report\n']), 'DEMO police report.pdf');
    await victim('POST', `/api/cases/${c1.id}/evidence`, fd, true);
    await victim('POST', `/api/evidence/${ev1.id}/parse-whatsapp`, {});
    await victim('POST', `/api/cases/${c1.id}/locations`, { category: 'incident_location', label: '[DEMO] My home (paint splashed)', addressText: 'Shah Alam (demo)', lat: 3.0733, lng: 101.5185, precision: 'exact', isPrivateResidence: true, isVictimLocation: true, sourceReference: 'Victim statement', country: 'MY', reportId: r1.id });
    await victim('POST', `/api/cases/${c1.id}/locations`, { category: 'location_mentioned_in_threat', label: '[DEMO] "We know your office"', addressText: 'Petaling Jaya (demo)', precision: 'area', sourceReference: 'WhatsApp export E1, line 5', evidenceId: ev1.id, country: 'MY' });
    await victim('POST', `/api/cases/${c1.id}/locations`, { category: 'approximate_network_location', label: '[DEMO] IP lookup of a link they sent', lat: 3.139, lng: 101.6869, precision: 'exact', sourceReliability: 'high', sourceReference: 'Free IP lookup (demo)', country: 'MY' });
    const biz = (await victim('POST', `/api/cases/${c1.id}/locations`, { category: 'public_business_address', label: '[DEMO] "Easy Credit" office in advert', addressText: 'Jalan Demo 1, Kuala Lumpur (fictional)', lat: 3.1466, lng: 101.6958, precision: 'exact', sourceReliability: 'high', sourceReference: '[DEMO] Newspaper advertisement, 12 Oct 2026', evidenceId: ev1.id, country: 'MY' })).location;
    await mod('POST', `/api/mod/locations/${biz.id}/verify`, { verificationStatus: 'verified', communityVisible: true });
    await mod('POST', `/api/mod/reports/${r1.id}/decision`, { decision: 'publish', publicSummary: '[DEMO] Reported for loan collection intimidation over WhatsApp, including threats to damage the victim\'s property.' });

    const c2 = (await victim2('POST', '/api/cases', { title: '[DEMO] Loan app harassment', description: '' })).case;
    const inc2 = (await victim2('POST', `/api/cases/${c2.id}/locations`, { category: 'incident_location', label: '[DEMO] Where collectors confronted me', addressText: 'Cheras (demo)', lat: 3.0892, lng: 101.7441, precision: 'exact', sourceReliability: 'medium', sourceReference: 'Victim statement', country: 'MY' })).location;
    await mod('POST', `/api/mod/locations/${inc2.id}/verify`, { verificationStatus: 'corroborated', communityVisible: true });
    const r2 = (await victim2('POST', `/api/cases/${c2.id}/reports`, { phone: '+60 11-1000 2001', channel: 'phone_call', category: 'threat_family', incidentAt: '2026-11-02', description: '[DEMO] Caller said they would visit my parents if I did not pay. Synthetic.' })).report;
    fd = new FormData(); fd.append('file', new Blob(['[DEMO] call log placeholder']), 'DEMO call log.txt');
    await victim2('POST', `/api/cases/${c2.id}/evidence`, fd, true);
    await mod('POST', `/api/mod/reports/${r2.id}/decision`, { decision: 'publish', publicSummary: '[DEMO] Reported for phone calls threatening the victim\'s family over a loan.' });
    await victim2('POST', `/api/cases/${c2.id}/reports`, { phone: '+60 11-1000 2003', channel: 'sms', category: 'payment_demand', description: '[DEMO] SMS demanding payment to an unknown account. Awaiting review. Synthetic.' });

    const anon = mk();
    await anon('POST', '/api/appeals', { type: 'appeal', phone: '+60 11-1000 2003', requesterName: '[DEMO] Number owner', requesterContact: 'owner@demo.had', reason: '[DEMO] I think this number was recycled. Synthetic appeal for demonstration.' });

    console.log(`Demo database created at ${dbPath}`);
    console.log('Logins (password demo-password-123): victim@demo.had, victim2@demo.had, moderator@demo.had, admin@demo.had');
    console.log('Try searching +60 11-1000 2001 (2 published reports) and +60 11-1000 2003 (pending, so nothing public).');
  } catch (e) { console.error(e); process.exitCode = 1; }
  server.close(); app.locals.db.close();
});
