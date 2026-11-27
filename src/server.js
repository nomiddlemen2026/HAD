'use strict';
const { createApp } = require('./app');
const port = Number(process.env.PORT || 3000);
createApp().then(app => {
  app.listen(port, () => console.log(`H.A.D listening on http://localhost:${port}${process.env.HAD_DEMO_MODE === '1' ? ' (DEMO MODE: synthetic data)' : ''}`));
}).catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
