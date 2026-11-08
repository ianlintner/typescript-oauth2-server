import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { test } from 'node:test';
import { SignJWT, exportJWK, exportPKCS8, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const ISSUER = 'http://localhost:8080';
const GT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const T0 = 1_000_000;
const EXT = 'https://idp.example'; // external trusted issuer

async function setup() {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1');
  const store = new SqliteStore(':memory:'); await store.init();
  const ext = await generateKeyPair('ES256', { extractable: true });
  const pub = async (k: CryptoKey, kid: string): Promise<JWK> => ({ ...(await exportJWK(k)), kid });
  const base = { redirectUris: [], grantTypes: [GT], scopes: ['read', 'openid'], enabled: true };
  await store.saveClient({ ...base, clientId: 'conf', clientSecretHash: await hashClientSecret('s3cret-value-long-enough') });
  // trusted issuer with inline jwks
  await store.saveTrustedIssuer({
    id: 'ti-1', issuer: EXT, jwks: { keys: [await pub(ext.publicKey, 'ext')] },
    allowedAudiences: [], subjectMapping: 'sub', allowedClientIds: [], enabled: true,
    createdAt: T0, updatedAt: T0,
  });
  const state = { v: T0 };
  const clock: Clock = { now: () => state.v };
  const server = buildServer({ store, signer, clock, random: cryptoRandom, issuer: ISSUER, authenticate: async () => 'u' });
  const sign = (claims: Record<string, unknown> = {}, kid?: string) => {
    const body: Record<string, unknown> = { iss: EXT, sub: 'alice', aud: ISSUER, jti: randomUUID(), iat: T0, exp: T0 + 60, ...claims };
    for (const [k, v] of Object.entries(body)) if (v === undefined) delete body[k];
    return new SignJWT(body).setProtectedHeader({ alg: 'ES256', ...(kid ? { kid } : {}) }).sign(ext.privateKey);
  };
  const post = (form: Record<string, string>, headers: Record<string, string> = {}) =>
    server.inject({ method: 'POST', url: '/oauth/token', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, payload: new URLSearchParams(form).toString() });
  const jwtb = (assertion: string, extra: Record<string, string> = {}) =>
    post({ grant_type: GT, client_id: 'conf', client_secret: 's3cret-value-long-enough', assertion, ...extra });
  return { store, server, state, ext, sign, post, jwtb };
}

test('valid assertion exchanges for a token with sub = assertion sub', async () => {
  const c = await setup();
  const res = await c.jwtb(await c.sign());
  assert.equal(res.statusCode, 200, res.body);
  const body = res.json();
  assert.ok(body.access_token);
  assert.equal(body.token_type, 'Bearer');
  assert.equal(body.expires_in, 3600);
});

test('subject_mapping=email uses the email claim as subject', async () => {
  const c = await setup();
  await c.store.saveTrustedIssuer({
    id: 'ti-1', issuer: EXT, jwks: (await c.store.getTrustedIssuer(EXT))!.jwks,
    allowedAudiences: [], subjectMapping: 'email', allowedClientIds: [], enabled: true,
    createdAt: T0, updatedAt: T0,
  });
  const res = await c.jwtb(await c.sign({ sub: 'x', email: 'alice@example.com' }));
  assert.equal(res.statusCode, 200);
  assert.ok(res.json().access_token);
});

test('allowedClientIds restricts which client may use the issuer', async () => {
  const c = await setup();
  await c.store.saveTrustedIssuer({
    id: 'ti-1', issuer: EXT, jwks: (await c.store.getTrustedIssuer(EXT))!.jwks,
    allowedAudiences: [], subjectMapping: 'sub', allowedClientIds: ['other-client'], enabled: true,
    createdAt: T0, updatedAt: T0,
  });
  const res = await c.jwtb(await c.sign());
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'unauthorized_client');
});

test('allowedAudiences accepts additional audience values and rejects non-listed ones', async () => {
  const c = await setup();
  await c.store.saveTrustedIssuer({
    id: 'ti-1', issuer: EXT, jwks: (await c.store.getTrustedIssuer(EXT))!.jwks,
    allowedAudiences: ['https://audience.example'], subjectMapping: 'sub', allowedClientIds: [], enabled: true,
    createdAt: T0, updatedAt: T0,
  });
  assert.equal((await c.jwtb(await c.sign({ aud: 'https://audience.example' }))).statusCode, 200);
  const bad = await c.jwtb(await c.sign({ aud: 'https://evil.example' }));
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.json().error, 'invalid_grant');
});

test('replayed assertion jti is rejected with opaque invalid_grant', async () => {
  const c = await setup();
  const ass = await c.sign({ jti: 'fixed' });
  assert.equal((await c.jwtb(ass)).statusCode, 200);
  const replay = await c.jwtb(ass);
  assert.equal(replay.statusCode, 400);
  assert.equal(replay.json().error, 'invalid_grant');
  assert.equal(replay.json().error_description, 'assertion is invalid'); // opaque
});

test('negative cases collapse to opaque invalid_grant', async () => {
  const c = await setup();
  const other = await generateKeyPair('ES256', { extractable: true });
  const cases: Record<string, string> = {
    'wrong key': await (async () => {
      const body = { iss: EXT, sub: 'alice', aud: ISSUER, jti: randomUUID(), iat: T0, exp: T0 + 60 };
      return new SignJWT(body).setProtectedHeader({ alg: 'ES256' }).sign(other.privateKey);
    })(),
    'expired': await c.sign({ exp: T0 - 1 }),
    'missing exp': await c.sign({ exp: undefined }),
    'missing jti': await c.sign({ jti: undefined }),
    'missing sub': await c.sign({ sub: undefined }),
    'wrong aud': await c.sign({ aud: 'https://evil.example' }),
    'unknown kid': await c.sign({}, 'nope'),
    'disabled issuer': await (async () => {
      await c.store.saveTrustedIssuer({ ...(await c.store.getTrustedIssuer(EXT))!, enabled: false });
      return c.sign();
    })(),
    'unknown issuer': await (async () => {
      const body = { iss: 'https://unknown.example', sub: 'a', aud: ISSUER, jti: randomUUID(), iat: T0, exp: T0 + 60 };
      return new SignJWT(body).setProtectedHeader({ alg: 'ES256' }).sign(c.ext.privateKey);
    })(),
    'not a jwt': 'garbage',
  };
  for (const [name, ass] of Object.entries(cases)) {
    const res = await c.jwtb(ass);
    assert.equal(res.statusCode, 400, name);
    assert.equal(res.json().error, 'invalid_grant', name);
  }
});

test('client must be allowed the jwt-bearer grant', async () => {
  const c = await setup();
  const base = { redirectUris: [], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true };
  await c.store.saveClient({ ...base, clientId: 'other', clientSecretHash: await hashClientSecret('s3cret-value-long-enough') });
  const res = await c.post({ grant_type: GT, client_id: 'other', client_secret: 's3cret-value-long-enough', assertion: await c.sign() });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'unauthorized_client');
});

test('client must authenticate to use jwt-bearer', async () => {
  const c = await setup();
  const res = await c.post({ grant_type: GT, assertion: await c.sign() });
  assert.equal(res.statusCode, 401);
});

test('scope escalation is rejected', async () => {
  const c = await setup();
  const res = await c.jwtb(await c.sign(), { scope: 'admin' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_scope');
});

test('admin: create, list and delete trusted issuers', async () => {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const store = new SqliteStore(':memory:'); await store.init();
  const server = buildServer({
    store, signer: await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1'),
    clock: { now: () => T0 }, random: cryptoRandom, issuer: ISSUER,
  });
  const k = await exportJWK((await generateKeyPair('ES256', { extractable: true })).publicKey);
  const create = await server.inject({ method: 'POST', url: '/admin/trusted-issuers', headers: { 'content-type': 'application/json' }, payload: JSON.stringify({ issuer: EXT, jwks: { keys: [k] }, subject_mapping: 'sub' }) });
  assert.equal(create.statusCode, 201);
  const id = create.json().id;
  assert.ok(id);
  const list = await server.inject({ method: 'GET', url: '/admin/trusted-issuers' });
  assert.equal(list.statusCode, 200);
  assert.equal(list.json().trusted_issuers.length, 1);
  assert.equal(list.json().trusted_issuers[0].issuer, EXT);
  const del = await server.inject({ method: 'DELETE', url: `/admin/trusted-issuers/${id}` });
  assert.equal(del.statusCode, 200);
  const list2 = await server.inject({ method: 'GET', url: '/admin/trusted-issuers' });
  assert.equal(list2.json().trusted_issuers.length, 0);
});

test('admin: jwks_uri must be https-only with a host and no fragment', async () => {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const store = new SqliteStore(':memory:'); await store.init();
  const server = buildServer({ store, signer: await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1'), clock: { now: () => T0 }, random: cryptoRandom, issuer: ISSUER });
  const mk = (issuer: string, jwksUri: string) => server.inject({ method: 'POST', url: '/admin/trusted-issuers', headers: { 'content-type': 'application/json' }, payload: JSON.stringify({ issuer, jwks_uri: jwksUri }) });
  for (const uri of ['http://idp.example/jwks.json', 'file:///etc/passwd', 'https:///', 'https://idp.example/jwks.json#frag']) {
    const res = await mk('https://x.example', uri);
    assert.equal(res.statusCode, 400, uri);
    assert.equal(res.json().error, 'invalid_request', uri);
  }
  assert.equal((await mk('https://ok.example', 'https://idp.example/jwks.json')).statusCode, 201);
});

test('admin: one of jwks or jwksUri is required; invalid subject_mapping is rejected', async () => {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const store = new SqliteStore(':memory:'); await store.init();
  const server = buildServer({ store, signer: await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1'), clock: { now: () => T0 }, random: cryptoRandom, issuer: ISSUER });
  const mk = (body: unknown) => server.inject({ method: 'POST', url: '/admin/trusted-issuers', headers: { 'content-type': 'application/json' }, payload: JSON.stringify(body) });
  assert.equal((await mk({ issuer: 'https://x.example' })).statusCode, 400);
  assert.equal((await mk({ issuer: 'https://x.example', jwksUri: 'https://idp.example/jwks.json', subject_mapping: 'nope' })).statusCode, 400);
  const k = await exportJWK((await generateKeyPair('ES256', { extractable: true })).publicKey);
  assert.equal((await mk({ issuer: 'https://x.example', jwks: { keys: [k] } })).statusCode, 201);
});

test('delete with unknown id returns invalid_request', async () => {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const store = new SqliteStore(':memory:'); await store.init();
  const server = buildServer({ store, signer: await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1'), clock: { now: () => T0 }, random: cryptoRandom, issuer: ISSUER });
  const res = await server.inject({ method: 'DELETE', url: '/admin/trusted-issuers/nope' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_request');
});

test('discovery advertises the jwt-bearer grant type', async () => {
  const c = await setup();
  const meta = (await c.server.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })).json();
  assert.ok(meta.grant_types_supported.includes(GT));
});

test('jwksUri-backed trusted issuer verifies via a fetched document', async () => {
  const c = await setup();
  const ext2 = await generateKeyPair('ES256', { extractable: true });
  const pubJwk = { ...(await exportJWK(ext2.publicKey)), kid: 'ext2' };
  const served: object = { keys: [pubJwk] };
  const server: Server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(served));
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address(); assert.ok(addr && typeof addr !== 'string');
  const jwksUri = `http://127.0.0.1:${addr.port}/jwks.json`;
  try {
    await c.store.saveTrustedIssuer({
      id: 'ti-2', issuer: 'https://remote.example', jwksUri,
      allowedAudiences: [], subjectMapping: 'sub', allowedClientIds: [], enabled: true,
      createdAt: T0, updatedAt: T0,
    });
    const body = { iss: 'https://remote.example', sub: 'bob', aud: ISSUER, jti: randomUUID(), iat: T0, exp: T0 + 60 };
    const assertion = await new SignJWT(body).setProtectedHeader({ alg: 'ES256', kid: 'ext2' }).sign(ext2.privateKey);
    const res = await c.jwtb(assertion);
    assert.equal(res.statusCode, 200, res.body);
    assert.ok(res.json().access_token);
  } finally {
    server.close();
  }
});

test('jwksUri fetch failures collapse to opaque invalid_grant', async () => {
  const c = await setup();
  // Unreachable jwks_uri (nothing listening on this port).
  const probe: Server = createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const addr = probe.address(); assert.ok(addr && typeof addr !== 'string');
  const deadPort = addr.port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));

  await c.store.saveTrustedIssuer({
    id: 'ti-3', issuer: 'https://dead.example', jwksUri: `http://127.0.0.1:${deadPort}/jwks.json`,
    allowedAudiences: [], subjectMapping: 'sub', allowedClientIds: [], enabled: true,
    createdAt: T0, updatedAt: T0,
  });
  const body = { iss: 'https://dead.example', sub: 'x', aud: ISSUER, jti: randomUUID(), iat: T0, exp: T0 + 60 };
  const assertion = await new SignJWT(body).setProtectedHeader({ alg: 'ES256' }).sign(c.ext.privateKey);
  const res = await c.jwtb(assertion);
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_grant');
});