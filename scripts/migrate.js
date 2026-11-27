'use strict';
const path = require('path');
const { openDb, migrate } = require('../src/db');
const dbPath = process.env.HAD_DB_PATH || path.join(__dirname, '..', 'data', 'had.db');
const db = openDb(dbPath);
const ran = migrate(db);
console.log(ran.length ? `Applied: ${ran.join(', ')}` : 'Database is up to date.', `(${dbPath})`);
