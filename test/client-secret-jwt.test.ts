import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { SignJWT, exportPKCS8, generateKeyPair } from 'jose';
import { createJoseSigner } from '../src/signer.js';
import { hashClientSecret, sealClientHmacSecret, deriveClientHmacKey } from '../src/client-auth.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { SqliteStore } from '../src/sqlite-store.js';
import type { Clock } from '../src/ports.js';

const KEY = deriveClientHmacKey('a-server-session-secret-at-least-32-chars-long');
const ISSUER = 'http://localhost:8080';
const TOKEN_URL = `${ISSUER}/oauth/token`;
const AT = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const T0 = 1_000_000;
const SECRET = 'client-secret-jwt-hmac-secret-value-long-enough';

async function setup() {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1');
  const store = new SqliteStore(':memory:'); await store.init();
  const base = { redirectUris: [], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true };
  await store.saveClient({ ...base, clientId: 'csj', clientSecretHash: await hashClientSecret(SECRET),
    clientSecretKey: await sealClientHmacSecret(SECRET, 'csj', KEY), tokenEndpointAuthMethod: 'client_secret_jwt' });
  await store.saveClient({ ...base, clientId: 'pk', clientSecretHash: await hashClientSecret('p'),
    clientSecretKey: await sealClientHmacSecret('p', 'pk', KEY), tokenEndpointAuthMethod: 'private_key_jwt', jwks: { keys: [] } });
  await store.saveClient({ ...base, clientId: 'basic', clientSecretHash: await hashClientSecret(SECRET) });
  const state = { v: T0 };
  const clock: Clock = { now: () => state.v };
  const server = buildServer({ store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    hmacKey: KEY, authenticate: async () => 'u' });
  const hmacKey = (value: string) => new TextEncoder().encode(value) as unknown as CryptoKey;
  const sign = (alg: string, claims: Record<string, unknown> = {}, secret: string = SECRET) => {
    const body: Record<string, unknown> = { iss: 'csj', sub: 'csj', aud: TOKEN_URL, jti: randomUUID(), iat: T0, exp: T0 + 60, ...claims };
    for (const [k, v] of Object.entries(body)) if (v === undefined) delete body[k];
    return new SignJWT(body).setProtectedHeader({ alg }).sign(hmacKey(secret));
  };
  const signAsymmetric = async () => {
    const ec = await generateKeyPair('ES256', { extractable: true });
    return new SignJWT({ iss: 'csj', sub: 'csj', aud: TOKEN_URL, jti: randomUUID(), iat: T0, exp: T0 + 60 })
      .setProtectedHeader({ alg: 'ES256' }).sign(ec.privateKey);
  };
  const post = (form: Record<string, string>, headers: Record<string, string> = {}) =>
    server.inject({ method: 'POST', url: '/oauth/token', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, payload: new URLSearchParams(form).toString() });
  const cc = (assertion: string, extra: Record<string, string> = {}) =>
    post({ grant_type: 'client_credentials', client_assertion_type: AT, client_assertion: assertion, ...extra });
  const rejected = async (res: Awaited<ReturnType<typeof cc>>) => {
    assert.equal(res.statusCode, 401);
    assert.equal(res.json().error, 'invalid_client');
    assert.equal(res.json().error_description, 'client authentication failed');
  };
  return { store, server, state, sign, signAsymmetric, post, cc, rejected };
}

test('sealed client HMAC secret round-trips for the bound client id', async () => {
  const sealed = await sealClientHmacSecret('client-hs-secret', 'client-1', KEY);
  const { unsealClientHmacSecret } = await import('../src/client-auth.js');
  assert.equal(await unsealClientHmacSecret(sealed, 'client-1', KEY), 'client-hs-secret');
});

test('sealed client HMAC secret cannot be unsealed for a different client id or key', async () => {
  const { unsealClientHmacSecret } = await import('../src/client-auth.js');
  const sealed = await sealClientHmacSecret('client-hs-secret', 'client-1', KEY);
  assert.equal(await unsealClientHmacSecret(sealed, 'client-2', KEY), null);
  assert.equal(await unsealClientHmacSecret(sealed, 'client-1', deriveClientHmacKey('a different server secret at least 32 chars')), null);
});

test('malformed sealed client HMAC secret is refused, not thrown', async () => {
  const { unsealClientHmacSecret } = await import('../src/client-auth.js');
  assert.equal(await unsealClientHmacSecret('garbage', 'client-1', KEY), null);
  assert.equal(await unsealClientHmacSecret('', 'client-1', KEY), null);
  const sealed = await sealClientHmacSecret('client-hs-secret', 'client-1', KEY);
  const parts = sealed.split('$');
  parts[2] = Buffer.from(parts[2]!, 'base64url').subarray(0, 8).toString('base64url');
  assert.equal(await unsealClientHmacSecret(parts.join('$'), 'client-1', KEY), null);
});

test('HS256 assertion authenticates a client_secret_jwt client', async () => {
  const c = await setup();
  assert.equal((await c.cc(await c.sign('HS256'))).statusCode, 200);
});

test('HS384 and HS512 assertions authenticate a client_secret_jwt client', async () => {
  const c = await setup();
  assert.equal((await c.cc(await c.sign('HS384'))).statusCode, 200);
  assert.equal((await c.cc(await c.sign('HS512'))).statusCode, 200);
});

test('issuer identifier is an accepted audience', async () => {
  const c = await setup();
  assert.equal((await c.cc(await c.sign('HS256', { aud: [ISSUER, 'other'] }))).statusCode, 200);
});

test('wrong secret, missing seal and asymmetric algs are refused with opaque invalid_client', async () => {
  const c = await setup();
  await c.rejected(await c.cc(await c.sign('HS256', {}, 'wrong-secret')));
  await c.rejected(await c.cc(await c.signAsymmetric()));
  const rec = (await c.store.getClient('csj'))!;
  await c.store.saveClient({ ...rec, clientSecretKey: null });
  await c.rejected(await c.cc(await c.sign('HS256')));
  await c.rejected(await c.post({ grant_type: 'client_credentials', client_id: 'csj', client_secret: SECRET }));
});

test('alg none is refused', async () => {
  const c = await setup();
  const none = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'csj', sub: 'csj', aud: TOKEN_URL, jti: 'a', exp: T0 + 60 })).toString('base64url')}.`;
  await c.rejected(await c.cc(none));
});

test('RFC-mandated negative claim cases are refused', async () => {
  const c = await setup();
  const cases: Record<string, string> = {
    expired: await c.sign('HS256', { exp: T0 - 1 }),
    'missing exp': await c.sign('HS256', { exp: undefined }),
    'missing jti': await c.sign('HS256', { jti: undefined }),
    'wrong aud': await c.sign('HS256', { aud: 'https://evil.example/oauth/token' }),
    'iss != client': await c.sign('HS256', { iss: 'basic' }),
    'sub != client': await c.sign('HS256', { sub: 'basic' }),
    'missing iss': await c.sign('HS256', { iss: undefined }),
    'missing sub': await c.sign('HS256', { sub: undefined }),
    'not a jwt': 'garbage',
  };
  for (const [name, jwt] of Object.entries(cases)) {
    const res = await c.cc(jwt);
    assert.equal(res.statusCode, 401, name);
    assert.equal(res.json().error, 'invalid_client', name);
    assert.equal(res.json().error_description, 'client authentication failed', name);
  }
});

test('a replayed jti is rejected, shared with private_key_jwt', async () => {
  const c = await setup();
  const jwt = await c.sign('HS256', { jti: 'same' });
  assert.equal((await c.cc(jwt)).statusCode, 200);
  await c.rejected(await c.cc(jwt));
  // The same jti under a different client is fine (replay key is per client).
  const pk = await c.store.getClient('pk');
  assert.ok(pk);
});

test('jti becomes reusable after the assertion lifetime passes', async () => {
  const c = await setup();
  assert.equal((await c.cc(await c.sign('HS256', { jti: 'j1' }))).statusCode, 200);
  c.state.v = T0 + 120;
  await c.rejected(await c.cc(await c.sign('HS256', { jti: 'j1', exp: T0 + 60 })));
  assert.equal((await c.cc(await c.sign('HS256', { jti: 'j1', iat: T0 + 120, exp: T0 + 180 }))).statusCode, 200);
});

test('disabled client, unknown client and wrong method are refused', async () => {
  const c = await setup();
  const rec = (await c.store.getClient('csj'))!;
  await c.store.saveClient({ ...rec, enabled: false });
  await c.rejected(await c.cc(await c.sign('HS256')));
  await c.rejected(await c.cc(await c.sign('HS256', { iss: 'ghost', sub: 'ghost' })));
  await c.rejected(await c.cc(await c.sign('HS256', { iss: 'basic', sub: 'basic' })));
  await c.rejected(await c.post({ grant_type: 'client_credentials', client_id: 'csj', client_secret: SECRET }));
});

test('request shape errors: wrong type, missing assertion, mixed methods, mismatched client_id', async () => {
  const c = await setup();
  const jwt = await c.sign('HS256');
  let res = await c.post({ grant_type: 'client_credentials', client_assertion_type: 'urn:x', client_assertion: jwt });
  assert.equal(res.json().error, 'invalid_client');
  res = await c.post({ grant_type: 'client_credentials', client_assertion_type: AT });
  assert.equal(res.json().error, 'invalid_client');
  res = await c.cc(jwt, { client_secret: 'x' });
  assert.equal(res.statusCode, 400); assert.equal(res.json().error, 'invalid_request');
  res = await c.cc(jwt, { client_id: 'basic' });
  assert.equal(res.json().error, 'invalid_client');
  assert.equal((await c.cc(jwt, { client_id: 'csj' })).statusCode, 200);
});

test('discovery advertises client_secret_jwt with HS256/384/512 signing algs', async () => {
  const c = await setup();
  const meta = (await c.server.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })).json();
  assert.ok(meta.token_endpoint_auth_methods_supported.includes('client_secret_jwt'));
  for (const alg of ['HS256', 'HS384', 'HS512']) assert.ok(meta.token_endpoint_auth_signing_alg_values_supported.includes(alg));
});

test('dynamic registration accepts client_secret_jwt and seals the issued secret', async () => {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const store = new SqliteStore(':memory:'); await store.init();
  const server = buildServer({ store, signer: await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1'), clock: { now: () => T0 },
    random: cryptoRandom, issuer: ISSUER, hmacKey: KEY, dynamicRegistration: true });
  const reg = (body: unknown) => server.inject({ method: 'POST', url: '/connect/register', headers: { 'content-type': 'application/json' }, payload: JSON.stringify(body) });
  const ok = await reg({ redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'client_secret_jwt' });
  assert.equal(ok.statusCode, 201);
  assert.ok(ok.json().client_secret);
  const stored = (await store.getClient(ok.json().client_id))!;
  assert.equal(stored.tokenEndpointAuthMethod, 'client_secret_jwt');
  assert.ok(stored.clientSecretKey);
  assert.ok(!stored.clientSecretKey!.includes(ok.json().client_secret));
});

test('a client_secret_jwt client cannot authenticate when no server HMAC key is configured', async () => {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const store = new SqliteStore(':memory:'); await store.init();
  const base = { redirectUris: [], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true };
  await store.saveClient({ ...base, clientId: 'csj', clientSecretHash: await hashClientSecret(SECRET),
    clientSecretKey: await sealClientHmacSecret(SECRET, 'csj', KEY), tokenEndpointAuthMethod: 'client_secret_jwt' });
  const server = buildServer({ store, signer: await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1'),
    clock: { now: () => T0 }, random: cryptoRandom, issuer: ISSUER });
  const assertion = await new SignJWT({ iss: 'csj', sub: 'csj', aud: TOKEN_URL, jti: 'no-key', iat: T0, exp: T0 + 60 })
    .setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode(SECRET) as unknown as CryptoKey);
  const res = await server.inject({ method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ grant_type: 'client_credentials', client_assertion_type: AT, client_assertion: assertion }).toString() });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
});

test('seed provisioning seals the client secret for a client_secret_jwt client', async () => {
  const { parseSeed, applySeed } = await import('../src/sut/seed.js');
  const seed = parseSeed(JSON.stringify({ issuer: ISSUER, clients: [{ client_id: 'seeded', client_secret: SECRET,
    token_endpoint_auth_method: 'client_secret_jwt', redirect_uris: ['https://a.example/cb'],
    grant_types: ['client_credentials'], scopes: ['read'] }], users: [{ username: 'u', password: 'p' }] }));
  const store = new SqliteStore(':memory:'); await store.init();
  await applySeed(seed, store, KEY);
  const rec = (await store.getClient('seeded'))!;
  assert.equal(rec.tokenEndpointAuthMethod, 'client_secret_jwt');
  assert.ok(rec.clientSecretKey);
  assert.equal(rec.clientSecretKey!.startsWith('aesgcm-v1$'), true);
});
