import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { decodeJwt, exportPKCS8, generateKeyPair, SignJWT } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { InMemorySessionParticipation } from '../src/session.js';
import type { LogoutContext, SessionParticipation } from '../src/session.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';
import {
  createTestRegistry, makeTestAuthenticate, makeTestAuthTime, makeTestEndSession,
  makeTestSessionId, registerTestLoginRoutes, SESSION_COOKIE,
} from '../src/sut/routes.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';
const VERIFIER = 'v'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const SECRET = 'confidential-client-secret-value';
const basic = { authorization: `Basic ${Buffer.from(`conf:${SECRET}`).toString('base64')}` };

async function setup(opts: { participation?: SessionParticipation } = {}) {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(pair.privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  await store.saveClient({
    clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET), redirectUris: [CB],
    grantTypes: ['authorization_code', 'refresh_token'], scopes: ['openid'], enabled: true,
  });
  const clock: Clock = { now: () => 1_000_000 };
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'alice',
    sessionId: () => 'sid-abc',
    sessionParticipation: opts.participation,
  });
  return { server, store };
}

type Sut = Awaited<ReturnType<typeof setup>>;

async function setupConformance(opts: { onLogout?: (ctx: LogoutContext) => void } = {}) {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(pair.privateKey), 'k2');
  const store = new SqliteStore(':memory:');
  await store.init();
  await store.saveClient({
    clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET), redirectUris: [CB],
    grantTypes: ['authorization_code', 'refresh_token'], scopes: ['openid'], enabled: true,
  });
  const clock: Clock = { now: () => 1_000_000 };
  const registry = createTestRegistry([{ username: 'alice', password: 'pw', autoApproveClients: ['conf'] }], clock);
  const participation = new InMemorySessionParticipation();
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: makeTestAuthenticate(registry),
    authTime: makeTestAuthTime(registry),
    endSession: makeTestEndSession(registry),
    sessionId: makeTestSessionId(registry),
    sessionParticipation: participation,
    onLogout: opts.onLogout,
  });
  registerTestLoginRoutes(server, registry);
  return { server, store, registry, participation };
}

async function login(s: Awaited<ReturnType<typeof setupConformance>>) {
  const res = await s.server.inject({
    method: 'POST', url: '/auth/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ username: 'alice', password: 'pw' }).toString(),
  });
  assert.equal(res.statusCode, 302);
  const setCookie = res.headers['set-cookie'] as string | string[] | undefined;
  const value = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  assert.ok(value);
  const cookie = value.split(';')[0] as string;
  assert.ok(cookie.startsWith(`${SESSION_COOKIE}=`));
  return cookie;
}

function logoutUrl(idToken: string) {
  return `/oauth/logout?id_token_hint=${encodeURIComponent(idToken)}`;
}

function authorize(s: Sut, extra: Record<string, string> = {}, headers: Record<string, string> = {}) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: 'conf', redirect_uri: CB, code_challenge: CHALLENGE,
    code_challenge_method: 'S256', state: 'st', scope: 'openid', ...extra,
  });
  return s.server.inject({ method: 'GET', url: `/oauth/authorize?${q}`, headers });
}

async function exchange(s: Sut, extra: Record<string, string> = {}, headers: Record<string, string> = {}) {
  const res = await authorize(s, extra, headers);
  assert.equal(res.statusCode, 302);
  const code = new URL(res.headers.location as string).searchParams.get('code');
  assert.ok(code);
  const tok = await s.server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...basic },
    payload: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: CB, code_verifier: VERIFIER }).toString(),
  });
  assert.equal(tok.statusCode, 200);
  return tok.json() as { access_token: string; refresh_token?: string; id_token?: string };
}

test('a client is recorded as a session participant when it receives an ID token with sid', async () => {
  const participation = new InMemorySessionParticipation();
  const s = await setup({ participation });
  await exchange(s);
  assert.deepEqual(participation.clientsFor('sid-abc'), ['conf']);
});

test('logout ends the OP session: prompt=none afterwards returns login_required', async () => {
  const s = await setupConformance();
  const cookie = await login(s);
  const tokens = await exchange(s, {}, { cookie });
  const out = await s.server.inject({ method: 'GET', url: logoutUrl(tokens.id_token!), headers: { cookie } });
  assert.equal(out.statusCode, 200);
  const none = await authorize(s, { prompt: 'none' }, { cookie });
  assert.equal(new URL(none.headers.location as string).searchParams.get('error'), 'login_required');
});

test('logout exposes sid, sub and participating clients to the internal hook and clears participation', async () => {
  const contexts: LogoutContext[] = [];
  const s = await setupConformance({ onLogout: (ctx) => { contexts.push(ctx); } });
  const cookie = await login(s);
  const sid = s.registry.sessionIdFor(cookie.split('=')[1] ?? null);
  assert.ok(sid);
  const tokens = await exchange(s, {}, { cookie });
  await s.server.inject({ method: 'GET', url: logoutUrl(tokens.id_token!), headers: { cookie } });
  assert.deepEqual(contexts, [{ sid, sub: 'alice', clients: ['conf'] }]);
  assert.deepEqual(s.participation.clientsFor(sid), []);
});

test('logout reports the live session sid (not a stale hint sid) and ends that session only', async () => {
  const contexts: LogoutContext[] = [];
  const s = await setupConformance({ onLogout: (ctx) => { contexts.push(ctx); } });

  // Session 1 yields an ID token that will later be reused as a stale id_token_hint.
  const cookie1 = await login(s);
  const sid1 = s.registry.sessionIdFor(cookie1.split('=')[1] ?? null);
  assert.ok(sid1);
  const stale = await exchange(s, {}, { cookie: cookie1 });
  assert.equal(decodeJwt(stale.id_token!).sid, sid1);

  // Session 2 is the browser's *live* session at logout time.
  const cookie2 = await login(s);
  const sid2 = s.registry.sessionIdFor(cookie2.split('=')[1] ?? null);
  assert.ok(sid2);
  assert.notEqual(sid2, sid1);
  await exchange(s, {}, { cookie: cookie2 });

  assert.deepEqual(s.participation.clientsFor(sid1), ['conf']);
  assert.deepEqual(s.participation.clientsFor(sid2), ['conf']);

  // The RP presents the stale session-1 hint, but the browser is in session 2.
  const out = await s.server.inject({
    method: 'GET', url: logoutUrl(stale.id_token!), headers: { cookie: cookie2 },
  });
  assert.equal(out.statusCode, 200);

  assert.equal(contexts.length, 1);
  assert.equal(contexts[0]!.sid, sid2, 'the ending live session sid must reach the hook, not the stale hint sid');
  assert.equal(contexts[0]!.sub, 'alice');
  assert.deepEqual(contexts[0]!.clients, ['conf']);
  assert.deepEqual(s.participation.clientsFor(sid2), [], 'the ended live session participation is cleared');
  assert.deepEqual(s.participation.clientsFor(sid1), ['conf'], 'the stale hint session is not ended');
});

test('a throwing notification hook does not break logout or skip participation cleanup', async () => {
  const s = await setupConformance({
    onLogout: () => { throw new Error('downstream notification failed'); },
  });
  const cookie = await login(s);
  const sid = s.registry.sessionIdFor(cookie.split('=')[1] ?? null);
  assert.ok(sid);
  const tokens = await exchange(s, {}, { cookie });
  const out = await s.server.inject({ method: 'GET', url: logoutUrl(tokens.id_token!), headers: { cookie } });
  assert.equal(out.statusCode, 200, 'logout still succeeds when the notification hook throws');
  assert.deepEqual(s.participation.clientsFor(sid), [], 'participation is cleared even when the hook throws');
});

test('conformance session hook returns an opaque sid, distinct from the cookie and stable until logout', () => {
  const clock: Clock = { now: () => 1_000_000 };
  const registry = createTestRegistry([{ username: 'alice', password: 'pw', autoApproveClients: ['conf'] }], clock);
  const cookie = registry.login('alice', 'pw');
  assert.ok(cookie);
  const sid = registry.sessionIdFor(cookie);
  assert.ok(sid);
  assert.notEqual(sid, cookie);
  assert.equal(registry.sessionIdFor(cookie), sid);
  assert.equal(registry.sessionIdFor('unknown-session'), null);
  registry.end(cookie);
  assert.equal(registry.sessionIdFor(cookie), null);
});

test('logout resolves sid from the hint when no live session hook is available', async () => {
  const contexts: LogoutContext[] = [];
  const pair = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(pair.privateKey), 'k3');
  const store = new SqliteStore(':memory:');
  await store.init();
  await store.saveClient({
    clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET), redirectUris: [CB],
    grantTypes: ['authorization_code'], scopes: ['openid'], enabled: true,
  });
  const clock: Clock = { now: () => 1_000_000 };
  const hint = await new SignJWT({ sub: 'alice', sid: 'sid-from-hint', aud: 'conf' })
    .setProtectedHeader({ alg: 'ES256', kid: 'k3' })
    .setIssuer(ISSUER).setIssuedAt(1_000_000).setExpirationTime(1_000_000 + 3600)
    .sign(pair.privateKey);
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    sessionParticipation: new InMemorySessionParticipation(),
    onLogout: (ctx) => { contexts.push(ctx); },
  });
  const out = await server.inject({ method: 'GET', url: logoutUrl(hint) });
  assert.equal(out.statusCode, 200);
  assert.deepEqual(contexts, [{ sid: 'sid-from-hint', sub: 'alice', clients: [] }]);
});

test('code grant and refresh grant ID tokens carry the same session sid', async () => {
  const s = await setup();
  const first = await exchange(s);
  assert.equal(decodeJwt(first.id_token!).sid, 'sid-abc');
  assert.ok(first.refresh_token);
  const refreshed = await s.server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...basic },
    payload: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: first.refresh_token! }).toString(),
  });
  assert.equal(refreshed.statusCode, 200);
  assert.equal(decodeJwt((refreshed.json() as { id_token: string }).id_token).sid, 'sid-abc');
});
