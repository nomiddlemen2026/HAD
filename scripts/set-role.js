'use strict';
// Usage: node scripts/set-role.js someone@example.com moderator|admin|user
const path = require('path');
const { openDb, migrate } = require('../src/db');
const { audit } = require('../src/custody');
const [email, role] = process.argv.slice(2);
if (!email || !['user', 'moderator', 'admin'].includes(role)) { console.error('Usage: node scripts/set-role.js <email> <user|moderator|admin>'); process.exit(1); }
const db = openDb(process.env.HAD_DB_PATH || path.join(__dirname, '..', 'data', 'had.db'));
migrate(db);
const r = db.prepare("UPDATE users SET role = ? WHERE email = ? AND status = 'active'").run(role, email.toLowerCase());
if (!r.changes) { console.error('No active user with that email.'); process.exit(1); }
audit(db, null, 'role_change_cli', email.toLowerCase(), { role });
console.log(`${email} is now ${role}.`);
