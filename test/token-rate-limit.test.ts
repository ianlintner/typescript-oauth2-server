import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const GT = 'urn:ietf:params:oauth:grant-type:token-exchange';

async function setup(tokenRateLimit?: { max: number; windowSeconds: number }, trustProxy?: boolean | string) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const server = buildServer({
    store, signer, clock: { now: () => 1_000_000 }, random: cryptoRandom, issuer: 'http://localhost:8080',
    authenticate: async () => 'u', ...(tokenRateLimit ? { tokenRateLimit } : {}),
    // These tests isolate the route-level request budget from the store-backed failure throttle.
    throttle: false,
    ...(trustProxy !== undefined ? { trustProxy } : {}),
  });
  const post = (grant: string, opts: { peer?: string; xff?: string } = {}) => server.inject({
    method: 'POST', url: '/oauth/token',
    ...(opts.peer ? { remoteAddress: opts.peer } : {}),
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...(opts.xff ? { 'x-forwarded-for': opts.xff } : {}) },
    payload: new URLSearchParams({ grant_type: grant, subject_token: 'x', subject_token_type: 'urn:ietf:params:oauth:token-type:access_token' }).toString(),
  });
  return { post };
}

test('token endpoint, including token-exchange, answers 429 once the per-client-address budget is spent', async () => {
  const c = await setup({ max: 3, windowSeconds: 60 });
  for (let i = 0; i < 3; i++) assert.equal((await c.post(GT)).statusCode, 401); // unauthenticated, but counted
  const res = await c.post(GT);
  assert.equal(res.statusCode, 429);
  assert.equal(res.json().error, 'temporarily_unavailable');
  assert.ok(Number(res.headers['retry-after']) > 0);
  assert.equal(res.headers['cache-control'], 'no-store');
});

test('the default budget does not throttle ordinary traffic', async () => {
  const c = await setup();
  for (let i = 0; i < 40; i++) assert.equal((await c.post(GT)).statusCode, 401);
});

test('behind a trusted proxy, distinct forwarded clients get separate budgets', async () => {
  const c = await setup({ max: 2, windowSeconds: 60 }, '10.0.0.1');
  for (let i = 0; i < 2; i++) assert.equal((await c.post(GT, { peer: '10.0.0.1', xff: '198.51.100.1' })).statusCode, 401);
  assert.equal((await c.post(GT, { peer: '10.0.0.1', xff: '198.51.100.1' })).statusCode, 429);
  assert.equal((await c.post(GT, { peer: '10.0.0.1', xff: '198.51.100.2' })).statusCode, 401);
});

test('forwarding headers from an untrusted peer are ignored (cannot dodge the limit)', async () => {
  const c = await setup({ max: 2, windowSeconds: 60 }, '10.0.0.1');
  for (let i = 0; i < 2; i++) assert.equal((await c.post(GT, { peer: '203.0.113.9', xff: `198.51.100.${i}` })).statusCode, 401);
  assert.equal((await c.post(GT, { peer: '203.0.113.9', xff: '198.51.100.77' })).statusCode, 429);
});

test('without trustProxy, forwarding headers are never trusted', async () => {
  const c = await setup({ max: 2, windowSeconds: 60 });
  for (let i = 0; i < 2; i++) assert.equal((await c.post(GT, { peer: '10.0.0.1', xff: `198.51.100.${i}` })).statusCode, 401);
  assert.equal((await c.post(GT, { peer: '10.0.0.1', xff: '198.51.100.50' })).statusCode, 429);
});
