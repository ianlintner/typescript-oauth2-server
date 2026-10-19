import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { decodeJwt, exportPKCS8, generateKeyPair, SignJWT } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { Clock } from '../src/ports.js';
import { claimsForScope } from '../src/oauth.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';
const VERIFIER = 'v'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const SECRET = 'confidential-client-secret-value';

async function setup(opts: { authTime?: number | null } = {}) {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(pair.privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  await store.saveClient({
    clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET), redirectUris: [CB],
    grantTypes: ['authorization_code', 'client_credentials'], scopes: ['openid', 'email', 'profile'], enabled: true,
  });
  let now = 1_000_000;
  const clock: Clock = { now: () => now };
  let ended = 0;
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'alice',
    authTime: () => (opts.authTime === undefined ? now : opts.authTime),
    userClaims: () => ({ email: 'alice@example.com', preferred_username: 'alice' }),
    endSession: () => { ended += 1; },
  });
  return { server, signer, pair, advance: (s: number) => { now += s; }, ended: () => ended };
}

const basic = { authorization: `Basic ${Buffer.from(`conf:${SECRET}`).toString('base64')}` };

function authorize(s: Awaited<ReturnType<typeof setup>>, extra: Record<string, string>) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: 'conf', redirect_uri: CB, code_challenge: CHALLENGE,
    code_challenge_method: 'S256', state: 'st', scope: 'openid', ...extra,
  });
  return s.server.inject({ method: 'GET', url: `/oauth/authorize?${q}` });
}

async function exchange(s: Awaited<ReturnType<typeof setup>>, extra: Record<string, string>) {
  const res = await authorize(s, extra);
  assert.equal(res.statusCode, 302);
  const code = new URL(res.headers.location as string).searchParams.get('code');
  assert.ok(code);
  const tok = await s.server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...basic },
    payload: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: CB, code_verifier: VERIFIER }).toString(),
  });
  assert.equal(tok.statusCode, 200);
  return tok.json() as { access_token: string; id_token?: string };
}

test('id_token echoes nonce and omits auth_time unless max_age was requested', async () => {
  const s = await setup();
  const body = await exchange(s, { nonce: 'n-123' });
  const claims = decodeJwt(body.id_token!);
  assert.equal(claims.nonce, 'n-123');
  assert.equal(claims.aud, 'conf');
  assert.equal(claims.auth_time, undefined);
});

test('max_age adds auth_time to the id_token', async () => {
  const s = await setup();
  const body = await exchange(s, { max_age: '300' });
  assert.equal(decodeJwt(body.id_token!).auth_time, 1_000_000);
});

test('max_age with a stale session re-authenticates; prompt=none yields login_required', async () => {
  const s = await setup({ authTime: 1_000_000 - 600 });
  const stale = await authorize(s, { max_age: '60' });
  assert.equal(stale.statusCode, 302);
  assert.equal(new URL(stale.headers.location as string).searchParams.get('error'), 'access_denied');
  const none = await authorize(s, { max_age: '60', prompt: 'none' });
  const loc = new URL(none.headers.location as string);
  assert.equal(loc.searchParams.get('error'), 'login_required');
  assert.equal(loc.searchParams.get('state'), 'st');
});

test('prompt=login forces re-authentication of an old session; a fresh login is accepted', async () => {
  const old = await setup({ authTime: 1_000_000 - 100 });
  assert.equal(new URL((await authorize(old, { prompt: 'login' })).headers.location as string).searchParams.get('error'), 'access_denied');
  const fresh = await setup();
  assert.ok(new URL((await authorize(fresh, { prompt: 'login' })).headers.location as string).searchParams.get('code'));
});

test('prompt=none combined with another value and a malformed max_age are invalid_request', async () => {
  const s = await setup();
  for (const extra of [{ prompt: 'none login' }, { max_age: '-1' }, { max_age: 'abc' }]) {
    assert.equal(new URL((await authorize(s, extra)).headers.location as string).searchParams.get('error'), 'invalid_request');
  }
});

test('prompt=none with an active session issues a code', async () => {
  const s = await setup();
  assert.ok(new URL((await authorize(s, { prompt: 'none' })).headers.location as string).searchParams.get('code'));
});

test('UserInfo releases claims only for granted scopes', async () => {
  const s = await setup();
  const all = await exchange(s, { scope: 'openid email profile' });
  const res = await s.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: { authorization: `Bearer ${all.access_token}` } });
  assert.deepEqual(res.json(), { sub: 'alice', email: 'alice@example.com', preferred_username: 'alice' });
  const bare = await exchange(s, { scope: 'openid' });
  const res2 = await s.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: { authorization: `Bearer ${bare.access_token}` } });
  assert.deepEqual(res2.json(), { sub: 'alice' });
});

test('claimsForScope discloses nothing without a user record', () => {
  assert.deepEqual(claimsForScope('openid email profile', null), {});
});

test('UserInfo rejects a client_credentials token', async () => {
  const s = await setup();
  const tok = await s.server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...basic },
    payload: 'grant_type=client_credentials',
  });
  const at = (tok.json() as { access_token: string }).access_token;
  const res = await s.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: { authorization: `Bearer ${at}` } });
  assert.equal(res.statusCode, 401);
  assert.equal((res.json() as { error: string }).error, 'invalid_token');
});

async function signedIdToken(s: Awaited<ReturnType<typeof setup>>, aud: string, exp: number) {
  // Sign with the server's own signer so only the audience differs.
  return s.signer.sign({ iss: ISSUER, sub: 'alice', aud, iat: exp - 10, exp });
}

test('logout accepts our id_token_hint (even expired) and ends the session', async () => {
  const s = await setup();
  const body = await exchange(s, {});
  s.advance(100_000);
  const res = await s.server.inject({ method: 'GET', url: `/oauth/logout?id_token_hint=${body.id_token}` });
  assert.equal(res.statusCode, 200);
  assert.equal(s.ended(), 1);
});

test('logout rejects a hint whose audience is not a registered client, or that is not ours', async () => {
  const s = await setup();
  const foreign = await signedIdToken(s, 'unknown-client', 2_000_000);
  const res = await s.server.inject({ method: 'GET', url: `/oauth/logout?id_token_hint=${foreign}` });
  assert.equal(res.statusCode, 400);
  assert.equal((res.json() as { error: string }).error, 'invalid_request');
  const other = await generateKeyPair('ES256');
  const forged = await new SignJWT({ iss: ISSUER, aud: 'conf' }).setProtectedHeader({ alg: 'ES256' }).sign(other.privateKey);
  const res2 = await s.server.inject({ method: 'GET', url: `/oauth/logout?id_token_hint=${forged}` });
  assert.equal(res2.statusCode, 400);
  assert.equal(s.ended(), 0);
});

test('logout without a hint still ends the session', async () => {
  const s = await setup();
  assert.equal((await s.server.inject({ method: 'GET', url: '/oauth/logout' })).statusCode, 200);
  assert.equal(s.ended(), 1);
});
