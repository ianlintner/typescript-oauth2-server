import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const ISSUER = 'http://localhost:8080';
const GOOD = 's3cret-value-long-enough';
const LIMIT = { maxFailures: 3, windowSeconds: 60 };

async function setup(store?: SqliteStore, state = { v: 1_000_000 }) {
  const key = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(key.privateKey), 'k1');
  const s = store ?? new SqliteStore(':memory:');
  await s.init();
  const base = { redirectUris: [], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true };
  await s.saveClient({ ...base, clientId: 'a', clientSecretHash: await hashClientSecret(GOOD) });
  await s.saveClient({ ...base, clientId: 'b', clientSecretHash: await hashClientSecret(GOOD) });
  const clock: Clock = { now: () => state.v };
  const server = buildServer({ store: s, signer, clock, random: cryptoRandom, issuer: ISSUER, clientAuthLimit: LIMIT });
  const token = (id: string, secret: string) => server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ grant_type: 'client_credentials', client_id: id, client_secret: secret }).toString(),
  });
  return { store: s, server, state, token, signer, clock };
}

test('store window counter: counts, keeps window end, expires and restarts', async () => {
  const s = new SqliteStore(':memory:'); await s.init();
  assert.equal(await s.rateLimitCount('k', 100), 0);
  assert.equal(await s.rateLimitHit('k', 60, 100), 1);
  assert.equal(await s.rateLimitHit('k', 60, 130), 2); // does not extend the window
  assert.equal(await s.rateLimitCount('k', 159), 2);
  assert.equal(await s.rateLimitCount('k', 160), 0); // window ended at 160
  assert.equal(await s.rateLimitHit('k', 60, 160), 1);
  assert.equal(await s.rateLimitCount('other', 160), 0);
  await s.close();
});

test('repeated invalid_client locks out that client with 429 + Retry-After, even for correct credentials', async () => {
  const c = await setup();
  for (let i = 0; i < LIMIT.maxFailures; i++) assert.equal((await c.token('a', 'wrong')).statusCode, 401);
  const locked = await c.token('a', GOOD);
  assert.equal(locked.statusCode, 429);
  assert.equal(locked.headers['retry-after'], String(LIMIT.windowSeconds));
  assert.equal(locked.json().error, 'temporarily_unavailable');
  // another client is unaffected
  assert.equal((await c.token('b', GOOD)).statusCode, 200);
  // lockout lifts once the window elapses
  c.state.v += LIMIT.windowSeconds;
  assert.equal((await c.token('a', GOOD)).statusCode, 200);
});

test('successful authentications are not counted', async () => {
  const c = await setup();
  for (let i = 0; i < LIMIT.maxFailures * 3; i++) assert.equal((await c.token('a', GOOD)).statusCode, 200);
  assert.equal(await c.store.rateLimitCount(`cauth:${(await import('node:crypto')).createHash('sha256').update('a').digest('base64url')}`, c.state.v), 0);
});

test('unknown client ids are limited too, so existence is not probeable by volume', async () => {
  const c = await setup();
  for (let i = 0; i < LIMIT.maxFailures; i++) assert.equal((await c.token('ghost', 'x')).statusCode, 401);
  assert.equal((await c.token('ghost', 'x')).statusCode, 429);
});

test('limit is store-backed: a second server instance on the same database sees the lockout', async () => {
  const c1 = await setup();
  for (let i = 0; i < LIMIT.maxFailures; i++) await c1.token('a', 'wrong');
  const second = buildServer({ store: c1.store, signer: c1.signer, clock: c1.clock, random: cryptoRandom, issuer: ISSUER, clientAuthLimit: LIMIT });
  const res = await second.inject({
    method: 'POST', url: '/oauth/token', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'a', client_secret: GOOD }).toString(),
  });
  assert.equal(res.statusCode, 429);
});

test('Basic-header credentials are keyed to the same client counter', async () => {
  const c = await setup();
  const basic = (id: string, secret: string) => c.server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` },
    payload: 'grant_type=client_credentials',
  });
  for (let i = 0; i < LIMIT.maxFailures; i++) assert.equal((await basic('a', 'wrong')).statusCode, 401);
  assert.equal((await c.token('a', GOOD)).statusCode, 429);
});

test('authorize redirects carry no-referrer and no-store (RFC 9700 §4.2.4)', async () => {
  const c = await setup();
  await c.store.saveClient({ clientId: 'web', clientSecretHash: null, redirectUris: ['https://app.example/cb'], grantTypes: ['authorization_code'], scopes: ['read'], enabled: true });
  const res = await c.server.inject({ method: 'GET', url: '/oauth/authorize?client_id=web&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=token&state=s' });
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers['referrer-policy'], 'no-referrer');
  assert.equal(res.headers['cache-control'], 'no-store');
});
