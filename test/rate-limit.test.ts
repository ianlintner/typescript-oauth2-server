import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { Clock } from '../src/ports.js';
import { BOUNDED_REQUESTS_PER_SOURCE, BOUNDED_WINDOW_SECONDS } from '../src/rate-limit.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';

async function setup(opts: { rateLimit?: boolean } = {}) {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(pair.privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  await store.saveClient({
    clientId: 'conf', clientSecretHash: await hashClientSecret('confidential-client-secret-value'), redirectUris: [CB],
    grantTypes: ['authorization_code'], scopes: ['openid'], enabled: true,
  });
  let now = 1_700_000_000; // on a window boundary
  const clock: Clock = { now: () => now };
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'alice',
    rateLimit: opts.rateLimit,
  });
  return { server, advance: (s: number) => { now += s; } };
}

const userinfo = (s: Awaited<ReturnType<typeof setup>>, address?: string) =>
  s.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: { authorization: 'Bearer not-a-token' }, ...(address ? { remoteAddress: address } : {}) });

test(`userinfo is refused with 429 and Retry-After after ${BOUNDED_REQUESTS_PER_SOURCE} requests from one source`, async () => {
  const s = await setup();
  for (let i = 0; i < BOUNDED_REQUESTS_PER_SOURCE; i += 1) assert.equal((await userinfo(s)).statusCode, 401);
  const refused = await userinfo(s);
  assert.equal(refused.statusCode, 429);
  assert.equal((refused.json() as { error: string }).error, 'temporarily_unavailable');
  const retryAfter = Number(refused.headers['retry-after']);
  assert.ok(retryAfter > 0 && retryAfter <= BOUNDED_WINDOW_SECONDS, `retry-after ${retryAfter}`);
  // A different source has its own budget.
  assert.equal((await userinfo(s, '203.0.113.9')).statusCode, 401);
  // The next window starts fresh.
  s.advance(retryAfter);
  assert.equal((await userinfo(s)).statusCode, 401);
});

test('logout is bounded independently of userinfo', async () => {
  const s = await setup();
  for (let i = 0; i < BOUNDED_REQUESTS_PER_SOURCE; i += 1) assert.equal((await userinfo(s)).statusCode, 401);
  // Spending the userinfo budget must not refuse logout.
  const logout = await s.server.inject({ method: 'GET', url: '/oauth/logout' });
  assert.equal(logout.statusCode, 400);
  for (let i = 0; i < BOUNDED_REQUESTS_PER_SOURCE; i += 1) await s.server.inject({ method: 'GET', url: '/oauth/logout' });
  const refused = await s.server.inject({ method: 'GET', url: '/oauth/logout' });
  assert.equal(refused.statusCode, 429);
  assert.equal((refused.json() as { error: string }).error, 'temporarily_unavailable');
  // Routes sharing the server that are not bounded are unaffected.
  for (let i = 0; i < BOUNDED_REQUESTS_PER_SOURCE * 2; i += 1) {
    assert.equal((await s.server.inject({ method: 'GET', url: '/health' })).statusCode, 200);
  }
});

test('unbounded routes and the disabled limiter are never refused', async () => {
  const unbounded = await setup();
  for (let i = 0; i < BOUNDED_REQUESTS_PER_SOURCE * 2; i += 1) {
    assert.equal((await unbounded.server.inject({ method: 'GET', url: '/.well-known/openid-configuration' })).statusCode, 200);
  }
  const disabled = await setup({ rateLimit: false });
  for (let i = 0; i < BOUNDED_REQUESTS_PER_SOURCE * 2; i += 1) assert.equal((await userinfo(disabled)).statusCode, 401);
});
