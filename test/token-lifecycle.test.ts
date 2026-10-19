import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { FastifyInstance } from 'fastify';
import { exportPKCS8, generateKeyPair, decodeJwt } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { ClientRecord, Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';
const VERIFIER = 'v'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const SECRET = 'confidential-client-secret-value';

// Test helper: verify a JWT without checking exp/iat against real time.
async function verifyJwt(token: string, signer: Awaited<ReturnType<typeof createJoseSigner>>, issuer: string, audience: string) {
  const { jwtVerify, createLocalJWKSet } = await import('jose');
  const jwks = createLocalJWKSet(await signer.publicJwks() as Parameters<typeof createLocalJWKSet>[0]);
  return jwtVerify(token, jwks, {
    issuer,
    audience,
    currentDate: new Date(0), // accept any timestamp (tests use fake clocks)
  });
}

async function setup(opts: { user?: string | null; refreshTokenTtl?: number } = {}) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base: Omit<ClientRecord, 'clientId' | 'clientSecretHash'> = {
    redirectUris: [CB],
    grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    scopes: ['openid', 'read', 'write'],
    enabled: true,
  };
  await store.saveClient({ ...base, clientId: 'pub', clientSecretHash: null });
  await store.saveClient({ ...base, clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET) });
  // Internal RS (resource server) for introspection
  await store.saveClient({ ...base, clientId: 'rs-1', clientSecretHash: await hashClientSecret('rs-secret'), grantTypes: [] });
  let now = 1_000_000;
  const clock: Clock = { now: () => now };
  const user = opts.user === undefined ? 'user-1' : opts.user;
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => user,
    refreshTokenTtl: opts.refreshTokenTtl ?? 86_400,
  });
  return { server, store, signer, advance: (s: number) => { now += s; } };
}

function token(server: FastifyInstance, form: Record<string, string>, headers: Record<string, string> = {}) {
  return server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    payload: new URLSearchParams(form).toString(),
  });
}

async function done(s: Awaited<ReturnType<typeof setup>>) {
  await s.server.close();
  await s.store.close();
}

// -- Client Credentials --

test('client_credentials grant issues an access token for a confidential client', async () => {
  const s = await setup();
  const res = await token(s.server, {
    grant_type: 'client_credentials',
    client_id: 'conf',
    client_secret: SECRET,
    scope: 'read',
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.token_type, 'Bearer');
  assert.ok(body.access_token);
  assert.equal(body.scope, 'read');
  const { payload } = await verifyJwt(body.access_token, s.signer, ISSUER, 'conf');
  assert.equal(payload.sub, 'conf'); // sub is the client
  assert.equal(payload.client_id, 'conf');
  assert.equal(payload.scope, 'read');
  await done(s);
});

test('client_credentials rejects a public client', async () => {
  const s = await setup();
  const res = await token(s.server, { grant_type: 'client_credentials', client_id: 'pub', scope: 'read' });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
  await done(s);
});

test('client_credentials with wrong secret returns invalid_client', async () => {
  const s = await setup();
  const res = await token(s.server, { grant_type: 'client_credentials', client_id: 'conf', client_secret: 'wrong', scope: 'read' });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
  await done(s);
});

test('client_credentials requesting unauthorized scope gets standard error', async () => {
  const s = await setup();
  const res = await token(s.server, { grant_type: 'client_credentials', client_id: 'conf', client_secret: SECRET, scope: 'admin' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_scope');
  await done(s);
});

test('client_credentials issues no refresh token', async () => {
  const s = await setup();
  const res = await token(s.server, { grant_type: 'client_credentials', client_id: 'conf', client_secret: SECRET, scope: 'read' });
  assert.equal(res.json().refresh_token, undefined);
  await done(s);
});

// -- Authorization Code + Refresh Token --

async function exchangeCode(server: FastifyInstance, params: Record<string, string> = {}, extraToken: Record<string, string> = {}) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: params.client_id ?? 'pub', redirect_uri: CB,
    code_challenge: CHALLENGE, code_challenge_method: 'S256', state: 'st-1',
    ...Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined)),
  });
  const authzRes = await server.inject({ method: 'GET', url: `/oauth/authorize?${q.toString()}` });
  assert.equal(authzRes.statusCode, 302);
  const code = new URL(authzRes.headers.location as string).searchParams.get('code');
  assert.ok(code);
  const form: Record<string, string> = {
    grant_type: 'authorization_code', code: code!, redirect_uri: CB,
    client_id: params.client_id ?? 'pub', code_verifier: VERIFIER, ...extraToken,
  };
  return server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(form).toString(),
  });
}

test('authorization_code does not issue refresh token when client lacks refresh_token grant', async () => {
  const s = await setup();
  await s.store.saveClient({
    clientId: 'pub-no-refresh',
    clientSecretHash: null,
    redirectUris: [CB],
    grantTypes: ['authorization_code'],
    scopes: ['openid', 'read'],
    enabled: true,
  });
  const res = await exchangeCode(s.server, { client_id: 'pub-no-refresh', scope: 'read' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().refresh_token, undefined);
  await done(s);
});

test('authorization_code issues a refresh token for a capable client', async () => {
  const s = await setup();
  const res = await exchangeCode(s.server, { scope: 'read' });
  assert.equal(res.statusCode, 200);
  assert.ok(res.json().access_token);
  assert.ok(res.json().refresh_token);
  await done(s);
});

// -- Refresh Token Grant --

test('refresh_token grant rotates tokens: old refresh consumed, new pair issued', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const firstRt = first.json().refresh_token;
  assert.ok(firstRt);
  const firstAt = first.json().access_token;

  const rot = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: firstRt,
    client_id: 'conf',
    client_secret: SECRET,
  });
  assert.equal(rot.statusCode, 200);
  assert.ok(rot.json().access_token);
  assert.ok(rot.json().refresh_token);
  assert.notEqual(rot.json().access_token, firstAt);
  assert.notEqual(rot.json().refresh_token, firstRt);

  // Old refresh is consumed
  const replay = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: firstRt,
    client_id: 'conf',
    client_secret: SECRET,
  });
  assert.equal(replay.statusCode, 400);
  assert.equal(replay.json().error, 'invalid_grant');
  await done(s);
});

test('refresh_token rotation replay revokes the token family', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const rt1 = first.json().refresh_token;

  // Normal rotation: rt1 consumed, rt2 issued
  const rot = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: rt1,
    client_id: 'conf',
    client_secret: SECRET,
  });
  assert.equal(rot.statusCode, 200);
  const rt2 = rot.json().refresh_token;

  // Attacker replays rt1 (already consumed) — must revoke family
  const replay = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: rt1,
    client_id: 'conf',
    client_secret: SECRET,
  });
  assert.equal(replay.statusCode, 400);
  assert.equal(replay.json().error, 'invalid_grant');

  // rt2 should also be revoked (family killed)
  const killed = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: rt2,
    client_id: 'conf',
    client_secret: SECRET,
  });
  assert.equal(killed.statusCode, 400);
  assert.equal(killed.json().error, 'invalid_grant');
  await done(s);
});

test('refresh_token cannot escalate scope', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const rt = first.json().refresh_token;

  const rot = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: rt,
    client_id: 'conf',
    client_secret: SECRET,
    scope: 'write',
  });
  assert.equal(rot.statusCode, 400);
  assert.equal(rot.json().error, 'invalid_scope');
  await done(s);
});

test('refresh_token can narrow scope', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read write' },
    { client_id: 'conf', client_secret: SECRET });
  const rt = first.json().refresh_token;

  const rot = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: rt,
    client_id: 'conf',
    client_secret: SECRET,
    scope: 'read',
  });
  assert.equal(rot.statusCode, 200);
  assert.equal(rot.json().scope, 'read');
  await done(s);
});

test('refresh_token bound to client: another client cannot use it', async () => {
  const s = await setup();
  await s.store.saveClient({
    clientId: 'conf-2',
    clientSecretHash: await hashClientSecret('second-secret'),
    redirectUris: [CB],
    grantTypes: ['authorization_code', 'refresh_token'],
    scopes: ['read'],
    enabled: true,
  });
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const rt = first.json().refresh_token;

  // Wrong client should NOT consume/burn the token
  const rot = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: rt,
    client_id: 'conf-2',
    client_secret: 'second-secret',
  });
  assert.equal(rot.statusCode, 400);
  assert.equal(rot.json().error, 'invalid_grant');

  // Own client can still use it (not consumed by the wrong attempt)
  const ok = await token(s.server, {
    grant_type: 'refresh_token',
    refresh_token: rt,
    client_id: 'conf',
    client_secret: SECRET,
  });
  assert.equal(ok.statusCode, 200);
  await done(s);
});

// -- Revocation --

function revoke(server: FastifyInstance, token: string, tokenTypeHint: string, auth: Record<string, string>) {
  return server.inject({
    method: 'POST', url: '/oauth/revoke',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ token, token_type_hint: tokenTypeHint, ...auth }).toString(),
  });
}

test('revocation without client authentication returns 401', async () => {
  const s = await setup();
  const res = await revoke(s.server, 'anything', 'access_token', {});
  assert.equal(res.statusCode, 401);
  await done(s);
});

test('revocation of an access token makes it unusable', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const at = first.json().access_token;

  const decoded = decodeJwt(at);
  const jti = decoded.jti as string;

  await revoke(s.server, at, 'access_token', { client_id: 'conf', client_secret: SECRET });
  const stored = await s.store.getAccessToken(jti, 1_000_000);
  assert.equal(stored, null);
  await done(s);
});

test('revocation with client authentication uses the tokens client binding', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const at = first.json().access_token;
  const decoded = decodeJwt(at);

  await revoke(s.server, at, 'access_token', { client_id: 'conf', client_secret: SECRET });
  const stored = await s.store.getAccessToken(decoded.jti as string, 1_000_000);
  assert.equal(stored, null);
  await done(s);
});

// -- JWKS Endpoint --

test('GET /.well-known/jwks.json returns public keys with kid and no private material', async () => {
  const s = await setup();
  const res = await s.server.inject({ method: 'GET', url: '/.well-known/jwks.json' });
  assert.equal(res.statusCode, 200);
  assert.match(String(res.headers['content-type']), /json/);
  const body = res.json();
  assert.ok(Array.isArray(body.keys));
  assert.ok(body.keys.length > 0);
  for (const k of body.keys) {
    assert.ok(k.kid);
    assert.equal('d' in k, false, 'private key must not be published');
  }
  await done(s);
});

// -- Discovery --

test('GET /.well-known/openid-configuration returns discovery document', async () => {
  const s = await setup();
  const res = await s.server.inject({ method: 'GET', url: '/.well-known/openid-configuration' });
  assert.equal(res.statusCode, 200);
  const doc = res.json();
  assert.equal(doc.issuer, ISSUER);
  assert.equal(doc.authorization_endpoint, `${ISSUER}/oauth/authorize`);
  assert.equal(doc.token_endpoint, `${ISSUER}/oauth/token`);
  assert.equal(doc.jwks_uri, `${ISSUER}/.well-known/jwks.json`);
  assert.equal(doc.userinfo_endpoint, `${ISSUER}/oauth/userinfo`);
  assert.ok(doc.scopes_supported.includes('openid'));
  assert.ok(doc.response_types_supported.includes('code'));
  await done(s);
});

// -- ID Token --

test('authorization_code with openid scope issues an id_token', async () => {
  const s = await setup();
  const res = await exchangeCode(s.server, { scope: 'openid' });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.ok(body.id_token);
  const { payload } = await verifyJwt(body.id_token, s.signer, ISSUER, 'pub');
  assert.equal(payload.sub, 'user-1');
  assert.equal(payload.aud, 'pub');
  await done(s);
});

test('authorization_code without openid scope issues no id_token', async () => {
  const s = await setup();
  const res = await exchangeCode(s.server, { scope: 'read' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().id_token, undefined);
  await done(s);
});

// -- UserInfo --

test('GET /oauth/userinfo with valid token returns claims', async () => {
  const s = await setup();
  const res = await exchangeCode(s.server, { scope: 'openid' });
  const at = res.json().access_token;

  const ui = await s.server.inject({
    method: 'GET', url: '/oauth/userinfo',
    headers: { authorization: `Bearer ${at}` },
  });
  assert.equal(ui.statusCode, 200);
  assert.match(String(ui.headers['content-type']), /json/);
  const claims = ui.json();
  assert.equal(claims.sub, 'user-1');
  await done(s);
});

test('GET /oauth/userinfo with missing token returns 401 WWW-Authenticate', async () => {
  const s = await setup();
  const res = await s.server.inject({ method: 'GET', url: '/oauth/userinfo' });
  assert.equal(res.statusCode, 401);
  assert.match(String(res.headers['www-authenticate'] ?? ''), /Bearer/);
  await done(s);
});

test('GET /oauth/userinfo with invalid token returns 401', async () => {
  const s = await setup();
  const res = await s.server.inject({
    method: 'GET', url: '/oauth/userinfo',
    headers: { authorization: 'Bearer invalid-token' },
  });
  assert.equal(res.statusCode, 401);
  await done(s);
});

// -- Introspection --

function introspect(server: FastifyInstance, token: string, tokenTypeHint: string, auth: Record<string, string> = {}) {
  return server.inject({
    method: 'POST', url: '/oauth/introspect',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ token, token_type_hint: tokenTypeHint, ...auth }).toString(),
  });
}

test('introspection of an active access token returns active=true with metadata', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const at = first.json().access_token;

  const res = await introspect(s.server, at, 'access_token', { client_id: 'conf', client_secret: SECRET });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.active, true);
  assert.equal(body.client_id, 'conf');
  assert.equal(body.scope, 'read');
  assert.equal(body.token_type, 'Bearer');
  await done(s);
});

test('introspection of an unknown token returns active=false', async () => {
  const s = await setup();
  const res = await introspect(s.server, 'unknown-token', 'access_token', { client_id: 'rs-1', client_secret: 'rs-secret' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().active, false);
  await done(s);
});

test('introspection requires caller authentication', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const at = first.json().access_token;

  const res = await introspect(s.server, at, 'access_token', {});
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
  await done(s);
});

test('introspection of another clients token does not leak details', async () => {
  const s = await setup();
  await s.store.saveClient({
    clientId: 'rs-2',
    clientSecretHash: await hashClientSecret('rs2-secret'),
    redirectUris: [CB],
    grantTypes: [],
    scopes: ['read'],
    enabled: true,
  });
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const at = first.json().access_token;

  // Cross-client: rs-2 should not see conf's token details
  const res = await introspect(s.server, at, 'access_token', { client_id: 'rs-2', client_secret: 'rs2-secret' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().active, false);
  await done(s);
});

function forgeUnsigned(claims: Record<string, unknown>): string {
  const b = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b({ alg: 'none', typ: 'JWT' })}.${b(claims)}.`;
}

async function seedTwoClients() {
  const s = await setup();
  await s.store.saveClient({
    clientId: 'rs-2', clientSecretHash: await hashClientSecret('rs2-secret'),
    redirectUris: [CB], grantTypes: [], scopes: ['read'], enabled: true,
  });
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const at = first.json().access_token as string;
  const real = decodeJwt(at);
  const forged = forgeUnsigned({ ...real, aud: 'rs-2' });
  return { s, at, real, forged };
}

test('introspection ignores forged unsigned JWT claiming another audience (cross-client)', async () => {
  const { s, forged } = await seedTwoClients();
  const res = await introspect(s.server, forged, 'access_token', { client_id: 'rs-2', client_secret: 'rs2-secret' });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), { active: false });
  await done(s);
});

test('introspection with forged unsigned JWT is inactive even for the owning client', async () => {
  const { s, forged } = await seedTwoClients();
  const res = await introspect(s.server, forged, 'access_token', { client_id: 'conf', client_secret: SECRET });
  assert.deepEqual(res.json(), { active: false });
  await done(s);
});

test('owner can still introspect its own valid token; unknown tokens stay inactive', async () => {
  const { s, at } = await seedTwoClients();
  const own = await introspect(s.server, at, 'access_token', { client_id: 'conf', client_secret: SECRET });
  assert.equal(own.json().active, true);
  const unk = await introspect(s.server, forgeUnsigned({ jti: 'nope', aud: 'rs-2' }), 'access_token', { client_id: 'rs-2', client_secret: 'rs2-secret' });
  assert.deepEqual(unk.json(), { active: false });
  await done(s);
});

test('revocation ignores a forged unsigned JWT carrying a real jti', async () => {
  const { s, at, real } = await seedTwoClients();
  await s.server.inject({
    method: 'POST', url: '/oauth/revoke',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ token: forgeUnsigned({ ...real }), client_id: 'conf', client_secret: SECRET }).toString(),
  });
  const res = await introspect(s.server, at, 'access_token', { client_id: 'conf', client_secret: SECRET });
  assert.equal(res.json().active, true);
  await done(s);
});

// -- Persistence across restart --

test('revoked access token stays revoked after store restart', async () => {
  const dir = (await import('node:fs')).mkdtempSync(
    (await import('node:os')).tmpdir() + '/oauth2-lifecycle-',
  );
  const path = (await import('node:path')).join(dir, 'db.sqlite');
  try {
    let store = new SqliteStore(path);
    await store.init();
    await store.saveClient({
      clientId: 'c0', clientSecretHash: null, redirectUris: [CB],
      grantTypes: ['authorization_code', 'refresh_token'], scopes: ['read'], enabled: true,
    });

    const iat = 1_000_000;
    await store.saveAccessToken({ jti: 'jti-001', clientId: 'c0', subject: 'u1', scope: 'read', expiresAt: iat + 3600, revokedAt: null, tokenHash: null });
    await store.revokeAccessToken('jti-001', 1_000_100);
    await store.close();
    await import('node:timers/promises').then(m => m.setTimeout(50));

    store = new SqliteStore(path);
    await store.init();
    assert.equal(await store.getAccessToken('jti-001', 1_000_200), null);
    await store.close();
  } finally {
    (await import('node:fs')).rmSync(dir, { recursive: true, force: true });
  }
});
// -- v0.2 contract regressions (token-lifecycle.introspection.active-token / revocation.hint-mismatch) --

test('introspection of an active access token includes jti and iat (RFC 7662 §2.2)', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const at = first.json().access_token;
  const claims = decodeJwt(at);

  const res = await introspect(s.server, at, 'access_token', { client_id: 'conf', client_secret: SECRET });
  const body = res.json();
  assert.equal(body.jti, claims.jti);
  assert.ok(typeof body.jti === 'string' && body.jti.length > 0);
  assert.equal(body.iat, claims.iat);
  assert.equal(typeof body.exp, 'number');
  await done(s);
});

test('revoking a refresh token with a wrong access_token hint still revokes it (RFC 7009 §2.1)', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const rt = first.json().refresh_token;
  assert.ok(rt);

  const res = await revoke(s.server, rt, 'access_token', { client_id: 'conf', client_secret: SECRET });
  assert.equal(res.statusCode, 200);
  const redeem = await token(s.server, { grant_type: 'refresh_token', refresh_token: rt, client_id: 'conf', client_secret: SECRET });
  assert.equal(redeem.statusCode, 400);
  assert.equal(redeem.json().error, 'invalid_grant');
  await done(s);
});

test('revoking an access token with a wrong refresh_token hint still revokes it', async () => {
  const s = await setup();
  const first = await exchangeCode(s.server, { client_id: 'conf', scope: 'read' },
    { client_id: 'conf', client_secret: SECRET });
  const at = first.json().access_token;
  await revoke(s.server, at, 'refresh_token', { client_id: 'conf', client_secret: SECRET });
  const res = await introspect(s.server, at, 'access_token', { client_id: 'conf', client_secret: SECRET });
  assert.equal(res.json().active, false);
  await done(s);
});
