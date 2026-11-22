import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';

async function setup(opts: { rateLimit?: boolean | number } = {}) {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(pair.privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  await store.saveClient({
    clientId: 'conf', clientSecretHash: await hashClientSecret('confidential-client-secret-value'), redirectUris: [CB],
    grantTypes: ['authorization_code'], scopes: ['openid'], enabled: true,
  });
  const server = buildServer({
    store, signer, clock: { now: () => 1_700_000_000 }, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'alice',
    rateLimit: opts.rateLimit,
  });
  return { server };
}

const userinfo = (s: Awaited<ReturnType<typeof setup>>, address = '198.51.100.10') =>
  s.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: { authorization: 'Bearer not-a-token' }, remoteAddress: address });

test('userinfo is refused with 429 after the configured number of requests from one source', async () => {
  const s = await setup({ rateLimit: 3 });
  for (let i = 0; i < 3; i += 1) assert.equal((await userinfo(s)).statusCode, 401);
  const refused = await userinfo(s);
  assert.equal(refused.statusCode, 429);
  assert.equal((refused.json() as { error: string }).error, 'temporarily_unavailable');
  // A different source has its own budget.
  assert.equal((await userinfo(s, '198.51.100.11')).statusCode, 401);
});

test('logout is bounded independently of userinfo', async () => {
  const s = await setup({ rateLimit: 3 });
  for (let i = 0; i < 3; i += 1) assert.equal((await userinfo(s)).statusCode, 401);
  // Spending the userinfo budget must not refuse logout.
  const logout = await s.server.inject({ method: 'GET', url: '/oauth/logout', remoteAddress: '198.51.100.10' });
  assert.equal(logout.statusCode, 400); // no hint: the hardening rejects it
  for (let i = 0; i < 3; i += 1) {
    await s.server.inject({ method: 'GET', url: '/oauth/logout', remoteAddress: '198.51.100.10' });
  }
  const refused = await s.server.inject({ method: 'GET', url: '/oauth/logout', remoteAddress: '198.51.100.10' });
  assert.equal(refused.statusCode, 429);
  assert.equal((refused.json() as { error: string }).error, 'temporarily_unavailable');
  // Routes without a bound are unaffected.
  for (let i = 0; i < 8; i += 1) {
    assert.equal((await s.server.inject({ method: 'GET', url: '/health' })).statusCode, 200);
  }
});

test('unbounded routes and the disabled limiter are never refused', async () => {
  const unbounded = await setup({ rateLimit: 3 });
  for (let i = 0; i < 8; i += 1) {
    assert.equal((await unbounded.server.inject({ method: 'GET', url: '/.well-known/openid-configuration' })).statusCode, 200);
  }
  const disabled = await setup({ rateLimit: false });
  for (let i = 0; i < 8; i += 1) assert.equal((await userinfo(disabled)).statusCode, 401);
});
