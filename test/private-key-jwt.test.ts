import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { SignJWT, exportJWK, exportPKCS8, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const ISSUER = 'http://localhost:8080';
const TOKEN_URL = `${ISSUER}/oauth/token`;
const AT = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const T0 = 1_000_000;

async function setup() {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1');
  const store = new SqliteStore(':memory:'); await store.init();
  const es = await generateKeyPair('ES256', { extractable: true });
  const rs = await generateKeyPair('RS256', { extractable: true });
  const other = await generateKeyPair('ES256', { extractable: true });
  const pub = async (k: CryptoKey, kid: string): Promise<JWK> => ({ ...(await exportJWK(k)), kid });
  const base = { redirectUris: [], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true };
  await store.saveClient({ ...base, clientId: 'pk', clientSecretHash: null, tokenEndpointAuthMethod: 'private_key_jwt',
    jwks: { keys: [await pub(es.publicKey, 'es'), await pub(rs.publicKey, 'rs')] } });
  await store.saveClient({ ...base, clientId: 'sec', clientSecretHash: await hashClientSecret('s3cret-value-long-enough') });
  const state = { v: T0 };
  const clock: Clock = { now: () => state.v };
  const server = buildServer({ store, signer, clock, random: cryptoRandom, issuer: ISSUER, authenticate: async () => 'u' });
  const sign = (key: CryptoKey, alg: string, claims: Record<string, unknown> = {}, kid?: string) => {
    const body: Record<string, unknown> = { iss: 'pk', sub: 'pk', aud: TOKEN_URL, jti: randomUUID(), iat: T0, exp: T0 + 60, ...claims };
    for (const [k, v] of Object.entries(body)) if (v === undefined) delete body[k];
    return new SignJWT(body).setProtectedHeader({ alg, ...(kid ? { kid } : {}) }).sign(key);
  };
  const post = (form: Record<string, string>, headers: Record<string, string> = {}) =>
    server.inject({ method: 'POST', url: '/oauth/token', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, payload: new URLSearchParams(form).toString() });
  const cc = (assertion: string, extra: Record<string, string> = {}) =>
    post({ grant_type: 'client_credentials', client_assertion_type: AT, client_assertion: assertion, ...extra });
  return { store, server, state, es, rs, other, sign, post, cc };
}

test('ES256 and RS256 assertions authenticate a private_key_jwt client', async () => {
  const c = await setup();
  assert.equal((await c.cc(await c.sign(c.es.privateKey, 'ES256', {}, 'es'))).statusCode, 200);
  assert.equal((await c.cc(await c.sign(c.rs.privateKey, 'RS256', {}, 'rs'))).statusCode, 200);
});

test('kid may be omitted and issuer identifier is an accepted audience', async () => {
  const c = await setup();
  assert.equal((await c.cc(await c.sign(c.es.privateKey, 'ES256'))).statusCode, 200);
  assert.equal((await c.cc(await c.sign(c.es.privateKey, 'ES256', { aud: [ISSUER, 'other'] }))).statusCode, 200);
});

async function rejected(c: Awaited<ReturnType<typeof setup>>, res: Awaited<ReturnType<typeof c.cc>>) {
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
  assert.equal(res.json().error_description, 'client authentication failed'); // opaque: no oracle
}

test('replayed jti is rejected, but the same jti is fine after a different client', async () => {
  const c = await setup();
  const jwt = await c.sign(c.es.privateKey, 'ES256', { jti: 'fixed' });
  assert.equal((await c.cc(jwt)).statusCode, 200);
  await rejected(c, await c.cc(jwt));
});

test('negative cases all fail with the opaque invalid_client', async () => {
  const c = await setup();
  const es = c.es.privateKey;
  const cases: Record<string, string> = {
    'wrong key': await c.sign(c.other.privateKey, 'ES256'),
    expired: await c.sign(es, 'ES256', { exp: T0 - 1 }),
    'missing exp': await c.sign(es, 'ES256', { exp: undefined }),
    'missing jti': await c.sign(es, 'ES256', { jti: undefined }),
    'wrong aud': await c.sign(es, 'ES256', { aud: 'https://evil.example/oauth/token' }),
    'iss != client': await c.sign(es, 'ES256', { iss: 'sec' }),
    'sub != client': await c.sign(es, 'ES256', { sub: 'sec' }),
    'unknown kid': await c.sign(es, 'ES256', {}, 'nope'),
    'unsupported alg': await c.sign(new TextEncoder().encode('k'.repeat(32)) as unknown as CryptoKey, 'HS256'),
    'not a jwt': 'garbage',
  };
  for (const [name, jwt] of Object.entries(cases)) {
    const res = await c.cc(jwt);
    assert.equal(res.statusCode, 401, name);
    assert.equal(res.json().error, 'invalid_client', name);
    assert.equal(res.json().error_description, 'client authentication failed', name);
  }
});

test('alg none and algorithm/key-type mismatch are refused', async () => {
  const c = await setup();
  const none = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'pk', sub: 'pk', aud: TOKEN_URL, jti: 'a', exp: T0 + 60 })).toString('base64url')}.`;
  await rejected(c, await c.cc(none));
  // RS256 claimed with an EC-only kid: no RSA key carries that kid.
  await rejected(c, await c.cc(await c.sign(c.rs.privateKey, 'RS256', {}, 'es')));
});

test('a client that is not private_key_jwt cannot use an assertion; assertion client cannot use a secret', async () => {
  const c = await setup();
  await rejected(c, await c.cc(await c.sign(c.es.privateKey, 'ES256', { iss: 'sec', sub: 'sec' })));
  const res = await c.post({ grant_type: 'client_credentials', client_id: 'pk', client_secret: 'x' });
  assert.equal(res.statusCode, 401);
});

test('disabled client and unknown client are refused', async () => {
  const c = await setup();
  const rec = (await c.store.getClient('pk'))!;
  await c.store.saveClient({ ...rec, enabled: false });
  await rejected(c, await c.cc(await c.sign(c.es.privateKey, 'ES256')));
  await rejected(c, await c.cc(await c.sign(c.es.privateKey, 'ES256', { iss: 'ghost', sub: 'ghost' })));
});

test('request-shape errors: wrong assertion type, missing assertion, mixed methods, mismatched client_id', async () => {
  const c = await setup();
  const jwt = await c.sign(c.es.privateKey, 'ES256');
  let res = await c.post({ grant_type: 'client_credentials', client_assertion_type: 'urn:x', client_assertion: jwt });
  assert.equal(res.json().error, 'invalid_client');
  res = await c.post({ grant_type: 'client_credentials', client_assertion_type: AT });
  assert.equal(res.json().error, 'invalid_client');
  res = await c.cc(jwt, { client_secret: 'x' });
  assert.equal(res.statusCode, 400); assert.equal(res.json().error, 'invalid_request');
  res = await c.post({ grant_type: 'client_credentials', client_assertion_type: AT, client_assertion: jwt },
    { authorization: `Basic ${Buffer.from('pk:x').toString('base64')}` });
  assert.equal(res.json().error, 'invalid_request');
  res = await c.cc(await c.sign(c.es.privateKey, 'ES256'), { client_id: 'sec' });
  assert.equal(res.json().error, 'invalid_client');
  assert.equal((await c.cc(await c.sign(c.es.privateKey, 'ES256'), { client_id: 'pk' })).statusCode, 200);
});

test('jti is accepted again once the assertion lifetime has passed (store reaps), yet expired assertions never pass', async () => {
  const c = await setup();
  assert.equal((await c.cc(await c.sign(c.es.privateKey, 'ES256', { jti: 'j1' }))).statusCode, 200);
  c.state.v = T0 + 120;
  await rejected(c, await c.cc(await c.sign(c.es.privateKey, 'ES256', { jti: 'j1', exp: T0 + 60 })));
  assert.equal((await c.cc(await c.sign(c.es.privateKey, 'ES256', { jti: 'j1', iat: T0 + 120, exp: T0 + 180 }))).statusCode, 200);
});

test('discovery advertises private_key_jwt with exactly the implemented algs', async () => {
  const c = await setup();
  const meta = (await c.server.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })).json();
  assert.ok(meta.token_endpoint_auth_methods_supported.includes('private_key_jwt'));
  assert.deepEqual(meta.token_endpoint_auth_signing_alg_values_supported, ['RS256', 'ES256']);
});

test('dynamic registration: private_key_jwt requires inline public jwks and issues no secret', async () => {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const store = new SqliteStore(':memory:'); await store.init();
  const server = buildServer({ store, signer: await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1'), clock: { now: () => T0 },
    random: cryptoRandom, issuer: ISSUER, dynamicRegistration: true });
  const reg = (body: unknown) => server.inject({ method: 'POST', url: '/connect/register', headers: { 'content-type': 'application/json' }, payload: JSON.stringify(body) });
  const k = await exportJWK((await generateKeyPair('ES256', { extractable: true })).publicKey);
  const ok = await reg({ redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'], jwks: { keys: [k] } });
  assert.equal(ok.statusCode, 201);
  assert.equal(ok.json().client_secret, undefined);
  const stored = (await store.getClient(ok.json().client_id))!;
  assert.equal(stored.tokenEndpointAuthMethod, 'private_key_jwt');
  assert.equal(stored.jwks?.keys.length, 1);
  assert.equal((await reg({ redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'private_key_jwt' })).statusCode, 400);
  assert.equal((await reg({ redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [{ ...k, d: 'x' }] } })).statusCode, 400);
});

async function regSetup() {
  const sigKey = await generateKeyPair('ES256', { extractable: true });
  const store = new SqliteStore(':memory:'); await store.init();
  const server = buildServer({ store, signer: await createJoseSigner(await exportPKCS8(sigKey.privateKey), 'k1'), clock: { now: () => T0 },
    random: cryptoRandom, issuer: ISSUER, dynamicRegistration: true });
  const reg = (body: unknown) => server.inject({ method: 'POST', url: '/connect/register', headers: { 'content-type': 'application/json' }, payload: JSON.stringify(body) });
  const put = (id: string, token: string, body: unknown) => server.inject({ method: 'PUT', url: `/connect/register/${id}`,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, payload: JSON.stringify(body) });
  const k = await exportJWK((await generateKeyPair('ES256', { extractable: true })).publicKey);
  return { store, reg, put, k };
}

test('RFC 7592 PUT: unchanged private_key_jwt update succeeds; transitions to/from private_key_jwt are rejected', async () => {
  const { reg, put, k } = await regSetup();
  const cb = ['https://a.example/cb'];
  const pk = (await reg({ redirect_uris: cb, token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'], jwks: { keys: [k] } })).json();
  const same = await put(pk.client_id, pk.registration_access_token, { redirect_uris: ['https://b.example/cb'], token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'] });
  assert.equal(same.statusCode, 200);
  const toSecret = await put(pk.client_id, pk.registration_access_token, { redirect_uris: cb, token_endpoint_auth_method: 'client_secret_basic' });
  assert.equal(toSecret.statusCode, 400);
  assert.equal(toSecret.json().error, 'invalid_client_metadata');
  const sec = (await reg({ redirect_uris: cb })).json();
  const toKey = await put(sec.client_id, sec.registration_access_token, { redirect_uris: cb, token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [k] } });
  assert.equal(toKey.statusCode, 400);
  assert.equal(toKey.json().error, 'invalid_client_metadata');
});

test('registration rejects jwks with no usable RS256/ES256 verification key', async () => {
  const { reg, k } = await regSetup();
  const cb = ['https://a.example/cb'];
  const base = { redirect_uris: cb, token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'] };
  for (const bad of [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }, { kty: 'RSA', n: 'AQAB', e: 'AQAB' }, { ...k, alg: 'RS256' }, { ...k, use: 'enc' }]) {
    const r = await reg({ ...base, jwks: { keys: [bad] } });
    assert.equal(r.statusCode, 400, JSON.stringify(bad));
    assert.equal(r.json().error, 'invalid_client_metadata');
  }
  assert.equal((await reg({ ...base, jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }, k] } })).statusCode, 201);
});

test('replay key is unambiguous across (client_id, jti) pairs containing colons', async () => {
  const c = await setup();
  const base = { redirectUris: [], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true, clientSecretHash: null, tokenEndpointAuthMethod: 'private_key_jwt' };
  const jwks = (await c.store.getClient('pk'))!.jwks;
  await c.store.saveClient({ ...base, clientId: 'a:b', jwks });
  await c.store.saveClient({ ...base, clientId: 'a', jwks });
  assert.equal((await c.cc(await c.sign(c.es.privateKey, 'ES256', { iss: 'a:b', sub: 'a:b', jti: 'c' }))).statusCode, 200);
  assert.equal((await c.cc(await c.sign(c.es.privateKey, 'ES256', { iss: 'a', sub: 'a', jti: 'b:c' }))).statusCode, 200);
});

test('registration rejects RSA jwks entries carrying private `oth` prime info', async () => {
  const { reg, k } = await regSetup();
  const rsa = await exportJWK((await generateKeyPair('RS256', { extractable: true, modulusLength: 2048 })).publicKey);
  const r = await reg({ redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'],
    jwks: { keys: [k, { ...rsa, oth: [{ r: 'AQAB', d: 'AQAB', t: 'AQAB' }] }] } });
  assert.equal(r.statusCode, 400);
  assert.equal(r.json().error, 'invalid_client_metadata');
});

test('RFC 7592 PUT: same-method update replaces stored and echoed jwks (key rotation); invalid replacement is rejected; omitted jwks keeps keys', async () => {
  const { store, reg, put, k } = await regSetup();
  const cb = ['https://a.example/cb'];
  const base = { redirect_uris: cb, token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'] };
  const pk = (await reg({ ...base, jwks: { keys: [k] } })).json();
  const k2 = await exportJWK((await generateKeyPair('ES256', { extractable: true })).publicKey);

  const keep = await put(pk.client_id, pk.registration_access_token, base);
  assert.equal(keep.statusCode, 200);
  assert.deepEqual((await store.getClient(pk.client_id))!.jwks, { keys: [k] });

  const rsa = await exportJWK((await generateKeyPair('RS256', { extractable: true, modulusLength: 2048 })).publicKey);
  for (const bad of [{ keys: [] }, { keys: [{ ...k2, d: 'x' }] }, { keys: [k2, { ...rsa, oth: [{ r: 'AQAB', d: 'AQAB', t: 'AQAB' }] }] }]) {
    const r = await put(pk.client_id, pk.registration_access_token, { ...base, jwks: bad });
    assert.equal(r.statusCode, 400);
    assert.equal(r.json().error, 'invalid_client_metadata');
  }
  assert.deepEqual((await store.getClient(pk.client_id))!.jwks, { keys: [k] });

  const rotated = await put(pk.client_id, pk.registration_access_token, { ...base, jwks: { keys: [k2] } });
  assert.equal(rotated.statusCode, 200);
  assert.deepEqual(rotated.json().jwks, { keys: [k2] });
  const stored = (await store.getClient(pk.client_id))!;
  assert.deepEqual(stored.jwks, { keys: [k2] });
  assert.deepEqual(stored.registration!.metadata.jwks, { keys: [k2] });
});

test('registration requires supplied key_ops to include verify before a key counts as usable', async () => {
  const { reg, k } = await regSetup();
  const base = { redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'] };
  // key_ops: [] imports but yields a CryptoKey without verify usage: it must not count as usable.
  const empty = await reg({ ...base, jwks: { keys: [{ ...k, key_ops: [] }] } });
  assert.equal(empty.statusCode, 400, 'key_ops: [] must not satisfy the usable-key requirement');
  assert.equal(empty.json().error, 'invalid_client_metadata');
  // key_ops that omits verify is likewise unusable.
  assert.equal((await reg({ ...base, jwks: { keys: [{ ...k, key_ops: ['sign'] }] } })).statusCode, 400);
  // A usable key alongside an unusable one still registers.
  assert.equal((await reg({ ...base, jwks: { keys: [{ ...k, key_ops: [] }, k] } })).statusCode, 201);
  // key_ops containing verify is accepted, and omission stays valid.
  assert.equal((await reg({ ...base, jwks: { keys: [{ ...k, key_ops: ['verify'] }] } })).statusCode, 201);
  assert.equal((await reg({ ...base, jwks: { keys: [k] } })).statusCode, 201);
});

test('RFC 7592 PUT: rotation to a key without verify usage is rejected and keeps working keys', async () => {
  const { store, reg, put, k } = await regSetup();
  const base = { redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'] };
  const pk = (await reg({ ...base, jwks: { keys: [k] } })).json();
  const k2 = await exportJWK((await generateKeyPair('ES256', { extractable: true })).publicKey);
  const r = await put(pk.client_id, pk.registration_access_token, { ...base, jwks: { keys: [{ ...k2, key_ops: [] }] } });
  assert.equal(r.statusCode, 400);
  assert.equal(r.json().error, 'invalid_client_metadata');
  assert.deepEqual((await store.getClient(pk.client_id))!.jwks, { keys: [k] }); // working keys preserved
});
