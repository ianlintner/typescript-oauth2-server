import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const GT = 'urn:ietf:params:oauth:grant-type:token-exchange';

async function setup(tokenRateLimit?: { max: number; windowSeconds: number }) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const server = buildServer({
    store, signer, clock: { now: () => 1_000_000 }, random: cryptoRandom, issuer: 'http://localhost:8080',
    authenticate: async () => 'u', ...(tokenRateLimit ? { tokenRateLimit } : {}),
  });
  const post = (grant: string) => server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
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
