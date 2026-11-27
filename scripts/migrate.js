'use strict';
const { openDb, migrate } = require('../src/db');
(async () => {
  const db = openDb();
  const ran = await migrate(db);
  console.log(ran.length ? `Applied: ${ran.join(', ')}` : 'Database is up to date.', `(schema ${db.schema})`);
  await db.close();
})().catch(e => { console.error(e.message); process.exit(1); });
