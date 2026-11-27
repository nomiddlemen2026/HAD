'use strict';
const test = require('node:test');
const assert = require('node:assert');
const request = require('supertest');
const { makeApp, newUser, newCase } = require('./helpers');

async function setup() {
  const app = makeApp();
  const v = await newUser(app); const other = await newUser(app); const mod = await newUser(app, 'moderator');
  const kase = await newCase(v);
  const add = async (body) => (await v.post(`/api/cases/${kase.id}/locations`).send({ sourceReference: 'Victim statement', country: 'MY', ...body })).body.location;
  const L = {
    business: await add({ category: 'public_business_address', label: 'Kedai Pinjaman XYZ', addressText: 'Jalan Example 1', lat: 3.1478, lng: 101.6953, precision: 'exact', sourceReliability: 'high', sourceReference: 'Public newspaper advert' }),
    incident: await add({ category: 'incident_location', label: 'Car park where I was confronted', lat: 3.123456, lng: 101.654321, precision: 'exact', sourceReliability: 'medium' }),
    home: await add({ category: 'incident_location', label: 'My home', lat: 3.0733, lng: 101.5185, precision: 'exact', isPrivateResidence: true, isVictimLocation: true, sourceReliability: 'high' }),
    threat: await add({ category: 'location_mentioned_in_threat', label: 'My mum\'s shop', lat: 3.2, lng: 101.6, precision: 'approximate', sourceReliability: 'high' }),
    ip: await add({ category: 'approximate_network_location', label: 'IP lookup', lat: 3.139, lng: 101.687, precision: 'exact', sourceReliability: 'high' }),
    noCoords: await add({ category: 'public_business_address', label: 'Office without coordinates', addressText: 'Somewhere', sourceReliability: 'high' }),
  };
  return { app, v, other, mod, kase, L };
}

test('map config and Leaflet assets are served; CSP allows tile host', async () => {
  const app = makeApp();
  const cfg = await request(app).get('/api/map/config');
  assert.match(cfg.body.tiles.url, /openstreetmap/);
  const js = await request(app).get('/vendor/leaflet/leaflet.js');
  assert.equal(js.status, 200);
  assert.match(js.headers['content-security-policy'], /img-src[^;]*https:\/\/tile\.openstreetmap\.org/);
});

test('"mine" scope shows only own locations; "all" is staff-only', async () => {
  const { v, other, mod } = await setup();
  assert.equal((await v.get('/api/map/locations?scope=mine')).body.locations.length, 6);
  assert.equal((await other.get('/api/map/locations?scope=mine')).body.locations.length, 0);
  assert.equal((await other.get('/api/map/locations?scope=all')).status, 403);
  assert.equal((await mod.get('/api/map/locations?scope=all')).body.locations.length, 6);
  assert.equal((await request(require('./helpers').makeApp()).get('/api/map/locations?scope=community')).status, 401);
});

test('community map: only verified/corroborated AND moderator-approved; incidents blurred to ~1 km; private categories refused', async () => {
  const { other, mod, L } = await setup();
  const community = async () => (await other.get('/api/map/locations?scope=community')).body.locations;
  assert.equal((await community()).length, 0, 'nothing by default');
  // verified but not approved -> still hidden
  assert.equal((await mod.post(`/api/mod/locations/${L.business.id}/verify`).send({ verificationStatus: 'verified' })).status, 200);
  assert.equal((await community()).length, 0);
  // approved -> visible with source
  await mod.post(`/api/mod/locations/${L.business.id}/verify`).send({ verificationStatus: 'verified', communityVisible: true });
  let c = await community();
  assert.equal(c.length, 1);
  assert.equal(c[0].sourceReference, 'Public newspaper advert');
  assert.equal(c[0].lat, 3.1478);
  assert.ok(!('caseId' in c[0]));
  // incident: corroborated + approved -> shown as area, rounded, generic label, no address, no private source
  assert.equal((await mod.post(`/api/mod/locations/${L.incident.id}/verify`).send({ verificationStatus: 'corroborated', communityVisible: true })).status, 200);
  c = await community();
  const inc = c.find(x => x.id === L.incident.id);
  assert.equal(inc.lat, 3.12); assert.equal(inc.lng, 101.65); assert.equal(inc.precision, 'area');
  assert.equal(inc.label, 'Reported incident area');
  assert.ok(!/Victim statement/.test(inc.sourceReference));
  // ineligible ones refused
  for (const k of ['home', 'threat', 'ip', 'noCoords']) {
    const status = k === 'ip' ? 'corroborated' : 'verified';
    const r = await mod.post(`/api/mod/locations/${L[k].id}/verify`).send({ verificationStatus: status, communityVisible: true });
    assert.equal(r.status, 400, k + ' must be refused');
  }
  assert.equal((await community()).length, 2);
  // Un-verifying removes it from the map automatically
  await mod.post(`/api/mod/locations/${L.business.id}/verify`).send({ verificationStatus: 'disputed' });
  c = await community();
  assert.equal(c.length, 1);
  assert.ok(!c.some(x => x.id === L.business.id));
});

test('regular users cannot approve locations for the map', async () => {
  const { v, L } = await setup();
  assert.equal((await v.post(`/api/mod/locations/${L.business.id}/verify`).send({ verificationStatus: 'verified', communityVisible: true })).status, 403);
  assert.equal((await v.get('/api/mod/locations')).status, 403);
});
