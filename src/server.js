'use strict';
const { createApp } = require('./app');
const port = Number(process.env.PORT || 3000);
const app = createApp();
app.listen(port, () => console.log(`H.A.D listening on http://localhost:${port}${process.env.HAD_DEMO_MODE === '1' ? ' (DEMO MODE: synthetic data)' : ''}`));
