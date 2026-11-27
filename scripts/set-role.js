'use strict';
// Usage: node scripts/set-role.js someone@example.com moderator|admin|user
const { openDb, migrate } = require('../src/db');
const { audit } = require('../src/custody');
const [email, role] = process.argv.slice(2);
if (!email || !['user', 'moderator', 'admin'].includes(role)) { console.error('Usage: node scripts/set-role.js <email> <user|moderator|admin>'); process.exit(1); }
(async () => {
  const db = openDb();
  await migrate(db);
  const r = await db.prepare("UPDATE users SET role = ? WHERE email = ? AND status = 'active'").run(role, email.toLowerCase());
  if (!r.changes) { console.error('No active user with that email.'); process.exitCode = 1; }
  else { await audit(db, null, 'role_change_cli', email.toLowerCase(), { role }); console.log(`${email} is now ${role}.`); }
  await db.close();
})().catch(e => { console.error(e.message); process.exit(1); });
