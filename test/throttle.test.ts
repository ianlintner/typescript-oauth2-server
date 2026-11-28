import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { ClientRecord, Clock, Store } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer, type Deps } from '../src/server.js';
import { startSweeper } from '../src/sweep.js';
import { DEVICE_GRANT_TYPE } from '../src/device-grant.js';

const SECRET = 'confidential-client-secret-value';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const PAR = {
  response_type: 'code', redirect_uri: 'https://app.example/cb',
  code_challenge: 'c'.repeat(43), code_challenge_method: 'S256',
};

async function setup(extra: Partial<Deps> = {}) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base = { redirectUris: ['https://app.example/cb'], scopes: ['openid'], enabled: true };
  const grantTypes = ['authorization_code', 'client_credentials', DEVICE_GRANT_TYPE];
  await store.saveClient({ ...base, grantTypes, clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET) } satisfies ClientRecord);
  await store.saveClient({ ...base, grantTypes, clientId: 'pub', clientSecretHash: null } satisfies ClientRecord);
  let now = 1_000_000;
  const clock: Clock = { now: () => now };
  const server = buildServer({ store, signer, clock, random: cryptoRandom, issuer: 'http://localhost:8080', ...extra });
  return { server, store, advance: (s: number) => { now += s; }, now: () => now,
    async close() { await server.close(); await store.close(); } };
}
const post = (s: Awaited<ReturnType<typeof setup>>, url: string, form: Record<string, string>, headers: Record<string, string> = {}) =>
  s.server.inject({ method: 'POST', url, headers: { ...FORM, ...headers }, payload: new URLSearchParams(form).toString() });
const badToken = (s: Awaited<ReturnType<typeof setup>>, clientId = 'conf') =>
  post(s, '/oauth/token', { grant_type: 'client_credentials', client_id: clientId, client_secret: 'wrong' });

test('store: window counter counts, resets after the window and never mutates on peek', async () => {
  const store = new SqliteStore(':memory:');
  await store.init();
  assert.equal(await store.peekWindow('k', 100), null);
  assert.deepEqual(await store.recordWindowHit('k', 60, 100), { count: 1, resetAt: 160 });
  assert.deepEqual(await store.recordWindowHit('k', 60, 130), { count: 2, resetAt: 160 });
  assert.deepEqual(await store.peekWindow('k', 140), { count: 2, resetAt: 160 });
  assert.deepEqual(await store.peekWindow('k', 140), { count: 2, resetAt: 160 });
  assert.equal(await store.peekWindow('k', 160), null);
  assert.deepEqual(await store.recordWindowHit('k', 60, 160), { count: 1, resetAt: 220 });
  await store.close();
});

test('failed client authentication is bounded per client and answers 429 with Retry-After', async () => {
  const s = await setup({ throttle: { maxFailuresPerClient: 3, maxFailuresPerSource: 1000 } });
  for (let i = 0; i < 3; i += 1) assert.equal((await badToken(s)).statusCode, 401);
  const blocked = await badToken(s);
  assert.equal(blocked.statusCode, 429);
  assert.equal(blocked.headers['retry-after'], '60');
  // Even the correct secret is refused until the window ends: no credential work runs while throttled.
  const correct = await post(s, '/oauth/token', { grant_type: 'client_credentials', client_id: 'conf', client_secret: SECRET });
  assert.equal(correct.statusCode, 429);
  // Another client is unaffected.
  assert.notEqual((await post(s, '/oauth/token', { grant_type: 'client_credentials', client_id: 'pub' })).statusCode, 429);
  s.advance(61);
  const after = await post(s, '/oauth/token', { grant_type: 'client_credentials', client_id: 'conf', client_secret: SECRET });
  assert.equal(after.statusCode, 200);
  await s.close();
});

test('failed authentication is bounded per source across client ids, and Basic credentials count', async () => {
  const s = await setup({ throttle: { maxFailuresPerSource: 4, maxFailuresPerClient: 1000 } });
  const basic = (id: string) => ({ authorization: `Basic ${Buffer.from(`${id}:nope`).toString('base64')}` });
  assert.equal((await post(s, '/oauth/introspect', { token: 'x' }, basic('conf'))).statusCode, 401);
  assert.equal((await post(s, '/oauth/revoke', { token: 'x' }, basic('conf'))).statusCode, 401);
  assert.equal((await badToken(s, 'unknown-1')).statusCode, 401);
  assert.equal((await badToken(s, 'unknown-2')).statusCode, 401);
  const blocked = await badToken(s, 'unknown-3');
  assert.equal(blocked.statusCode, 429);
  assert.equal(blocked.json().error, 'temporarily_unavailable');
  await s.close();
});

test('unregistered client ids do not create per-client counters', async () => {
  const s = await setup();
  for (let i = 0; i < 5; i += 1) await badToken(s, `ghost-${i}`);
  const { failureKey } = await import('../src/throttle.js');
  for (let i = 0; i < 5; i += 1) assert.equal(await s.store.peekWindow(failureKey.client(`ghost-${i}`), s.now()), null);
  await badToken(s, 'conf');
  assert.equal((await s.store.peekWindow(failureKey.client('conf'), s.now()))?.count, 1);
  await s.close();
});

test('successful authentication does not consume the failure budget', async () => {
  const s = await setup({ throttle: { maxFailuresPerClient: 2, maxFailuresPerSource: 2 } });
  for (let i = 0; i < 6; i += 1) {
    assert.equal((await post(s, '/oauth/token', { grant_type: 'client_credentials', client_id: 'conf', client_secret: SECRET })).statusCode, 200);
  }
  await s.close();
});

test('throttle: false disables the failure bound', async () => {
  const s = await setup({ throttle: false });
  for (let i = 0; i < 15; i += 1) assert.equal((await badToken(s)).statusCode, 401);
  await s.close();
});

test('device authorization and PAR creation are bounded per source and by live-record caps', async () => {
  const s = await setup({ throttle: { maxCreationsPerSource: 3, maxLiveRecordsPerClient: 1000, maxLiveRecords: 1000 } });
  for (let i = 0; i < 3; i += 1) assert.equal((await post(s, '/oauth/device_authorization', { client_id: 'pub' })).statusCode, 200);
  const limited = await post(s, '/oauth/device_authorization', { client_id: 'pub' });
  assert.equal(limited.statusCode, 429);
  assert.ok(Number(limited.headers['retry-after']) >= 1);
  // PAR has its own source counter.
  assert.equal((await post(s, '/oauth/par', { ...PAR, client_id: 'pub' })).statusCode, 201);
  await s.close();

  const capped = await setup({ throttle: { maxLiveRecordsPerClient: 2, maxLiveRecords: 3, maxCreationsPerSource: 1000 } });
  for (let i = 0; i < 2; i += 1) assert.equal((await post(capped, '/oauth/par', { ...PAR, client_id: 'pub' })).statusCode, 201);
  assert.equal((await post(capped, '/oauth/par', { ...PAR, client_id: 'pub' })).statusCode, 429);
  assert.equal(await capped.store.countLiveRecords('par', capped.now(), 'pub'), 2);
  // Another client still has room under the global cap, until it is reached.
  assert.equal((await post(capped, '/oauth/par', { ...PAR, client_id: 'conf', client_secret: SECRET })).statusCode, 201);
  assert.equal((await post(capped, '/oauth/par', { ...PAR, client_id: 'conf', client_secret: SECRET })).statusCode, 429);
  // Expiry frees capacity.
  capped.advance(61);
  assert.equal((await post(capped, '/oauth/par', { ...PAR, client_id: 'pub' })).statusCode, 201);
  await capped.close();
});

test('request bodies above the configured limit are rejected', async () => {
  const s = await setup({ bodyLimit: 1024 });
  const res = await post(s, '/oauth/par', { client_id: 'pub', junk: 'x'.repeat(4096) });
  assert.equal(res.statusCode, 413);
  const dflt = await setup();
  assert.equal((await post(dflt, '/oauth/par', { client_id: 'pub', junk: 'x'.repeat(100_000) })).statusCode, 413);
  await s.close(); await dflt.close();
});

async function seedExpiring(store: Store) {
  await store.saveClient({ clientId: 'c', clientSecretHash: null, redirectUris: [], grantTypes: [], scopes: [], enabled: true });
  const base = { clientId: 'c', subject: 'u', scope: 'x' };
  await store.saveAuthorizationCode({ ...base, codeHash: 'old-c', redirectUri: 'r', codeChallenge: 'x', expiresAt: 100, consumedAt: null, nonce: null, authTime: null });
  await store.saveAuthorizationCode({ ...base, codeHash: 'new-c', redirectUri: 'r', codeChallenge: 'x', expiresAt: 900, consumedAt: null, nonce: null, authTime: null });
  await store.saveAccessToken({ ...base, jti: 'old-a', expiresAt: 100, revokedAt: null, tokenHash: null });
  await store.saveAccessToken({ ...base, jti: 'new-a', expiresAt: 900, revokedAt: null, tokenHash: null });
  const rt = { ...base, family: 'f', parentJti: null, revokedAt: null, revokedByReplayAt: null };
  await store.saveRefreshToken({ ...rt, jti: 'old-r', expiresAt: 100 });
  await store.saveRefreshToken({ ...rt, jti: 'new-r', expiresAt: 900 });
  const dev = { clientId: 'c', scope: 'x', interval: 5, lastPolledAt: null, status: 'pending' as const, subject: null };
  await store.saveDeviceCode({ ...dev, deviceCodeHash: 'old-d', userCodeHash: 'old-u', expiresAt: 100 });
  await store.saveDeviceCode({ ...dev, deviceCodeHash: 'new-d', userCodeHash: 'new-u', expiresAt: 900 });
  await store.savePar({ requestUriHash: 'old-p', clientId: 'c', params: {}, expiresAt: 100, consumedAt: null });
  await store.savePar({ requestUriHash: 'new-p', clientId: 'c', params: {}, expiresAt: 900, consumedAt: null });
  await store.consumeDpopJti('old-j', 100, 50);
  await store.consumeDpopJti('new-j', 900, 50);
  await store.recordWindowHit('old-w', 60, 40);
  await store.recordWindowHit('new-w', 900, 40);
}

test('sweepExpired removes only expired records, is idempotent and keeps live ones usable', async () => {
  const store = new SqliteStore(':memory:');
  await store.init();
  await seedExpiring(store);
  assert.equal(await store.sweepExpired(500), 7);
  assert.equal(await store.sweepExpired(500), 0);
  assert.equal(await store.getAccessToken('new-a', 500) !== null, true);
  assert.equal(await store.getAccessToken('old-a', 50), null);
  assert.equal(await store.getRefreshToken('new-r', 500) !== null, true);
  assert.equal(await store.getDeviceCode('old-d'), null);
  assert.equal(await store.getDeviceCode('new-d') !== null, true);
  assert.equal(await store.getPar('new-p', 500) !== null, true);
  assert.equal(await store.consumeAuthorizationCode('new-c', 500) !== null, true);
  assert.equal(await store.consumeDpopJti('new-j', 900, 500), false);
  assert.equal(await store.consumeDpopJti('old-j', 900, 500), true);
  assert.equal((await store.peekWindow('new-w', 500))?.count, 1);
  await store.close();
});

test('startSweeper sweeps immediately, reports failures, and stops cleanly', async () => {
  const calls: number[] = [];
  const errors: unknown[] = [];
  const failing = { sweepExpired: async (now: number) => { calls.push(now); throw new Error('boom'); } } as unknown as Store;
  const sweeper = startSweeper(failing, { now: () => 42 }, 3600, (e) => errors.push(e));
  await sweeper.stop();
  assert.deepEqual(calls, [42]);
  assert.equal(errors.length, 1);
  const off = startSweeper(failing, { now: () => 43 }, 0);
  await off.stop();
  assert.deepEqual(calls, [42]);
});
