import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { FastifyInstance } from 'fastify';
import { SignJWT, exportPKCS8, generateKeyPair, type JWK } from 'jose';
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

interface SetupOpts {
  authMethod?: string;
  jwks?: ClientRecord['jwks'];
  requireSignedRequestObject?: boolean;
  clientRequireSignedRequestObject?: boolean;
  authorizationDetailsTypesSupported?: string[];
}
async function setup(opts: SetupOpts = {}) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base: Omit<ClientRecord, 'clientId' | 'clientSecretHash'> = {
    redirectUris: [CB], grantTypes: ['authorization_code', 'refresh_token'], scopes: ['read', 'write'], enabled: true,
  };
  await store.saveClient({ ...base, clientId: 'pub', clientSecretHash: null,
    requireSignedRequestObject: opts.clientRequireSignedRequestObject });
  await store.saveClient({ ...base, clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET),
    tokenEndpointAuthMethod: opts.authMethod ?? 'client_secret_basic', jwks: opts.jwks,
    requireSignedRequestObject: opts.clientRequireSignedRequestObject });
  let now = 1_000_000;
  const clock: Clock = { now: () => now };
  const server = buildServer({ store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'user-1',
    authorizationDetailsTypesSupported: opts.authorizationDetailsTypesSupported,
    requireSignedRequestObject: opts.requireSignedRequestObject });
  return { server, store, advance: (s: number) => { now += s; } };
}

function authorize(server: FastifyInstance, extra: Record<string, string> = {}) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: 'pub', redirect_uri: CB,
    code_challenge: CHALLENGE, code_challenge_method: 'S256', state: 'outer-state', ...extra,
  });
  return server.inject({ method: 'GET', url: `/oauth/authorize?${q}` });
}

async function codeFrom(res: { statusCode: number; headers: Record<string, unknown>; body: string }): Promise<string> {
  assert.equal(res.statusCode, 302, res.body);
  const code = new URL(res.headers.location as string).searchParams.get('code');
  assert.ok(code);
  return code;
}

async function unsignedJar(claims: Record<string, unknown>): Promise<string> {
  const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  return `${enc({ alg: 'none' })}.${enc(claims)}.`;
}

async function hsJar(claims: Record<string, unknown>, secret = SECRET): Promise<string> {
  return new SignJWT(claims).setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt().setExpirationTime('5m').setIssuer('conf').setAudience(`${ISSUER}/oauth/authorize`)
    .sign(new TextEncoder().encode(secret));
}

async function esJar(claims: Record<string, unknown>, kid: string, key: Parameters<SignJWT['sign']>[0]): Promise<string> {
  return new SignJWT(claims).setProtectedHeader({ alg: 'ES256', kid })
    .setIssuedAt().setExpirationTime('5m').setIssuer('conf').setAudience(`${ISSUER}/oauth/authorize`)
    .sign(key);
}

async function rsJar(claims: Record<string, unknown>, kid: string, key: Parameters<SignJWT['sign']>[0]): Promise<string> {
  return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt().setExpirationTime('5m').setIssuer('conf').setAudience(`${ISSUER}/oauth/authorize`)
    .sign(key);
}

async function done(s: Awaited<ReturnType<typeof setup>>) {
  await s.server.close();
  await s.store.close();
}

const RAR = [{ type: 'payment', actions: ['read'], locations: ['https://bank.example'] }];

test('JAR unsigned request object from public client overrides query claims', async () => {
  const s = await setup();
  const jar = await unsignedJar({ iss: 'pub', aud: `${ISSUER}/oauth/authorize`, exp: 2_000_000,
    response_type: 'code', client_id: 'pub', redirect_uri: CB, state: 'jar-state', scope: 'read',
    code_challenge: CHALLENGE, code_challenge_method: 'S256' });
  const res = await authorize(s.server, { request: jar });
  const loc = new URL(res.headers.location as string);
  assert.equal(res.statusCode, 302, res.body);
  assert.equal(loc.searchParams.get('state'), 'jar-state');
  await done(s);
});

test('JAR request object is the sole source of authorization parameters (RFC 9101 §6.3)', async () => {
  const s = await setup({ authorizationDetailsTypesSupported: ['payment'] });
  const jar = await unsignedJar({ iss: 'pub', aud: `${ISSUER}/oauth/authorize`, exp: 2_000_000,
    response_type: 'code', client_id: 'pub', redirect_uri: CB, state: 'jar-state', scope: 'read',
    code_challenge: CHALLENGE, code_challenge_method: 'S256',
    authorization_details: JSON.stringify(RAR) });
  // The outer URL keeps the trusted client_id/redirect_uri needed to select the
  // client, but every authorization parameter below comes only from the query.
  // A signed JAR must not inherit them: otherwise anyone who can edit the URL
  // can substitute PKCE, escalate scope or inject authorization_details.
  const res = await authorize(s.server, {
    request: jar, state: 'query-state', scope: 'write',
    code_challenge: createHash('sha256').update('x'.repeat(43)).digest('base64url'),
    code_challenge_method: 'S256',
    authorization_details: JSON.stringify([{ type: 'payment', actions: ['write'] }]),
    nonce: 'query-nonce', login_hint: 'attacker@example.test',
  });
  assert.equal(res.statusCode, 302, res.body);
  const loc = new URL(res.headers.location as string);
  assert.equal(loc.searchParams.get('state'), 'jar-state', 'unsigned state must not override the JAR');
  const code = loc.searchParams.get('code');
  assert.ok(code);
  const record = await s.store.consumeAuthorizationCode(
    createHash('sha256').update(code).digest('hex'), 1_000_000 + 1);
  assert.equal(record?.scope, 'read', 'unsigned query scope must not be merged');
  assert.equal(record?.nonce, null, 'unsigned query nonce must not be merged');
  assert.deepEqual(record?.authorizationDetails, RAR, 'unsigned query RAR must not be merged');
  await done(s);
});

test('JAR signed request object still succeeds when query adds unsigned extras', async () => {
  const s = await setup({ authorizationDetailsTypesSupported: ['payment'] });
  const jar = await unsignedJar({ iss: 'pub', aud: `${ISSUER}/oauth/authorize`, exp: 2_000_000,
    response_type: 'code', client_id: 'pub', redirect_uri: CB, state: 'jar-state', scope: 'read',
    code_challenge: CHALLENGE, code_challenge_method: 'S256',
    authorization_details: JSON.stringify(RAR), nonce: 'jar-nonce' });
  const res = await authorize(s.server, { request: jar, prompt: 'login', max_age: '0',
    login_hint: 'attacker@example.test' });
  assert.equal(res.statusCode, 302, res.body);
  const loc = new URL(res.headers.location as string);
  assert.equal(loc.searchParams.get('state'), 'jar-state');
  const code = loc.searchParams.get('code');
  assert.ok(code);
  const record = await s.store.consumeAuthorizationCode(
    createHash('sha256').update(code).digest('hex'), 1_000_000 + 1);
  assert.deepEqual(record?.authorizationDetails, RAR);
  assert.equal(record?.nonce, 'jar-nonce');
  await done(s);
});

test('RAR authorization_details are returned in the token response and survive refresh', async () => {
  const s = await setup({ authorizationDetailsTypesSupported: ['payment'] });
  const res = await authorize(s.server, { client_id: 'conf', scope: 'read', authorization_details: JSON.stringify(RAR) });
  const code = await codeFrom(res);
  const basic = `Basic ${Buffer.from(`conf:${SECRET}`).toString('base64')}`;
  const exchanged = await s.server.inject({ method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic },
    payload: new URLSearchParams({ grant_type: 'authorization_code', code,
      redirect_uri: CB, code_verifier: VERIFIER }).toString() });
  assert.equal(exchanged.statusCode, 200, exchanged.body);
  assert.deepEqual(exchanged.json().authorization_details, RAR);
  const refresh = await s.server.inject({ method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic },
    payload: new URLSearchParams({ grant_type: 'refresh_token',
      refresh_token: exchanged.json().refresh_token }).toString() });
  assert.equal(refresh.statusCode, 200, refresh.body);
  assert.deepEqual(refresh.json().authorization_details, RAR);
  await done(s);
});

test('JAR rejects tampered unsigned request object and wrong client issuer', async () => {
  const s = await setup();
  const bad = await unsignedJar({ iss: 'pub', aud: `${ISSUER}/oauth/authorize`, exp: 2_000_000, response_type: 'code', redirect_uri: CB });
  const tampered = bad.replace(/.$/, 'A');
  const res = await authorize(s.server, { request: tampered });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
  const wrong = await unsignedJar({ iss: 'attacker', exp: 2_000_000, response_type: 'code', redirect_uri: CB });
  const res2 = await authorize(s.server, { request: wrong });
  assert.equal(res2.statusCode, 400, res2.body);
  await done(s);
});

test('JAR HS256 is rejected for secret clients because this port stores no plaintext verification key', async () => {
  const s = await setup();
  const jar = await hsJar({ response_type: 'code', redirect_uri: CB, state: 'hs', scope: 'read',
    code_challenge: CHALLENGE, code_challenge_method: 'S256' });
  const rejected = await s.server.inject({ method: 'GET', url: `/oauth/authorize?${new URLSearchParams({
    response_type: 'code', client_id: 'conf', redirect_uri: CB, code_challenge: CHALLENGE,
    code_challenge_method: 'S256', request: jar })}` });
  assert.equal(rejected.statusCode, 400, rejected.body);
  assert.equal(rejected.json().error, 'invalid_request');
  await done(s);
});

test('JAR RS256 verifies against registered client JWKS using kid', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJwkPublic(publicKey);
  const kid = 'client-key-1';
  const s = await setup({ authMethod: 'private_key_jwt', jwks: { keys: [{ ...jwk, kid, use: 'sig' }] } });
  const jar = await rsJar({ response_type: 'code', redirect_uri: CB, state: 'rs', scope: 'read',
    code_challenge: CHALLENGE, code_challenge_method: 'S256' }, kid, privateKey);
  const res = await s.server.inject({ method: 'GET', url: `/oauth/authorize?${new URLSearchParams({
    response_type: 'code', client_id: 'conf', redirect_uri: CB, code_challenge: CHALLENGE,
    code_challenge_method: 'S256', request: jar })}` });
  assert.equal(res.statusCode, 302, res.body);
  assert.equal(new URL(res.headers.location as string).searchParams.get('state'), 'rs');
  await done(s);
});

test('require_signed_request_object rejects requests without a signed JAR', async () => {
  const s = await setup({ requireSignedRequestObject: true });
  const plain = await authorize(s.server);
  assert.equal(plain.statusCode, 400, plain.body);
  assert.equal(plain.json().error, 'invalid_request');
  const unsigned = await unsignedJar({ iss: 'pub', response_type: 'code', redirect_uri: CB,
    code_challenge: CHALLENGE, code_challenge_method: 'S256' });
  const unprotected = await authorize(s.server, { request: unsigned });
  assert.equal(unprotected.statusCode, 400, unprotected.body);
  await done(s);
});

test('RAR authorization_details survive authorize to tokens and introspection', async () => {
  const s = await setup({ authorizationDetailsTypesSupported: ['payment'] });
  const res = await authorize(s.server, { client_id: 'conf', authorization_details: JSON.stringify(RAR) });
  const code = await codeFrom(res);
  const basic = `Basic ${Buffer.from(`conf:${SECRET}`).toString('base64')}`;
  const exchanged = await s.server.inject({ method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic },
    payload: new URLSearchParams({ grant_type: 'authorization_code', code,
      redirect_uri: CB, code_verifier: VERIFIER }).toString() });
  assert.equal(exchanged.statusCode, 200, exchanged.body);
  const body = exchanged.json();
  const encoded = String(body.access_token).split('.')[1] ?? '';
  const claims = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  assert.deepEqual(claims.authorization_details, RAR);
  const intro = await s.server.inject({ method: 'POST', url: '/oauth/introspect',
    headers: { 'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`conf:${SECRET}`).toString('base64')}` },
    payload: new URLSearchParams({ token: body.access_token }).toString() });
  assert.equal(intro.statusCode, 200, intro.body);
  assert.deepEqual(intro.json().authorization_details, RAR);
  await done(s);
});

test('RAR rejects unknown type, malformed JSON and non-array details at authorize by redirect', async () => {
  const s = await setup({ authorizationDetailsTypesSupported: ['payment'] });
  for (const value of [JSON.stringify([{ type: 'unknown' }]), 'not-json', '{}', JSON.stringify([{ actions: ['read'] }])]) {
    const res = await authorize(s.server, { authorization_details: value });
    assert.equal(res.statusCode, 302, `${value} ${res.body}`);
    assert.equal(new URL(res.headers.location as string).searchParams.get('error'), 'invalid_authorization_details');
  }
  await done(s);
});

test('RAR is validated at PAR and rejected with invalid_authorization_details', async () => {
  const s = await setup({ authorizationDetailsTypesSupported: ['payment'] });
  const res = await s.server.inject({ method: 'POST', url: '/oauth/par',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ client_id: 'pub', response_type: 'code', redirect_uri: CB,
      authorization_details: JSON.stringify([{ type: 'unknown' }]) }).toString() });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_authorization_details');
  await done(s);
});

test('JAR rejects expired request objects', async () => {
  const s = await setup();
  const jar = await unsignedJar({ iss: 'pub', aud: `${ISSUER}/oauth/authorize`, exp: 999_999,
    response_type: 'code', client_id: 'pub', redirect_uri: CB });
  const res = await authorize(s.server, { request: jar });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
  await done(s);
});

test('JAR rejects a signature whose kid is not registered for the client', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJwkPublic(publicKey);
  const s = await setup({ authMethod: 'private_key_jwt', jwks: { keys: [{ ...jwk, kid: 'known-key', use: 'sig' }] } });
  const jar = await rsJar({ response_type: 'code', redirect_uri: CB }, 'unknown-key', privateKey);
  const res = await authorize(s.server, { client_id: 'conf', request: jar });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
  await done(s);
});

test('client-level require_signed_request_object rejects unsigned JARs', async () => {
  const s = await setup({ clientRequireSignedRequestObject: true });
  const jar = await unsignedJar({ iss: 'pub', exp: 2_000_000, response_type: 'code', redirect_uri: CB });
  const res = await authorize(s.server, { request: jar });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
  await done(s);
});

test('RAR authorization_details survive a PAR request_uri at the authorization endpoint', async () => {
  const s = await setup({ authorizationDetailsTypesSupported: ['payment'] });
  const pushed = await s.server.inject({ method: 'POST', url: '/oauth/par',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ client_id: 'pub', response_type: 'code', redirect_uri: CB,
      code_challenge: CHALLENGE, code_challenge_method: 'S256',
      authorization_details: JSON.stringify(RAR) }).toString() });
  assert.equal(pushed.statusCode, 201, pushed.body);
  const requestUri = pushed.json().request_uri as string;
  const res = await authorize(s.server, { client_id: 'pub', request_uri: requestUri });
  assert.equal(res.statusCode, 302, res.body);
  await done(s);
});

test('discovery advertises JAR and RAR metadata', async () => {
  const s = await setup({ authorizationDetailsTypesSupported: ['payment'] });
  const res = await s.server.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' });
  assert.equal(res.statusCode, 200);
  const meta = res.json();
  assert.deepEqual(meta.request_object_signing_alg_values_supported, ['RS256', 'ES256']);
  assert.ok(meta.authorization_details_types_supported.includes('payment'));
  assert.equal(meta.require_signed_request_object, false);
  await done(s);
});

async function exportJwkPublic(key: unknown): Promise<JWK> {
  const { exportJWK } = await import('jose');
  return exportJWK(key as Parameters<typeof exportJWK>[0]) as Promise<JWK>;
}

test('JAR accepts an ES256 signed request object with a registered EC key', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJwkPublic(publicKey);
  const s = await setup({ authMethod: 'private_key_jwt', jwks: { keys: [{ ...jwk, kid: 'ec-1', use: 'sig' }] } });
  const jar = await esJar({ response_type: 'code', redirect_uri: CB, state: 'es' }, 'ec-1', privateKey);
  const res = await authorize(s.server, { client_id: 'conf', request: jar });
  assert.equal(res.statusCode, 302, res.body);
  assert.equal(new URL(res.headers.location as string).searchParams.get('state'), 'es');
  await done(s);
});

test('JAR rejects a signed request object with a client_id mismatch', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJwkPublic(publicKey);
  const s = await setup({ authMethod: 'private_key_jwt', jwks: { keys: [{ ...jwk, kid: 'rs-1', use: 'sig' }] } });
  const jar = await rsJar({ response_type: 'code', redirect_uri: CB, client_id: 'pub', state: 'x' }, 'rs-1', privateKey);
  const res = await authorize(s.server, { client_id: 'conf', request: jar });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
  await done(s);
});

test('JAR rejects a signed request object with an unregistered redirect_uri', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJwkPublic(publicKey);
  const s = await setup({ authMethod: 'private_key_jwt', jwks: { keys: [{ ...jwk, kid: 'rs-1', use: 'sig' }] } });
  const jar = await rsJar({ response_type: 'code', redirect_uri: 'https://attacker.example/cb' }, 'rs-1', privateKey);
  const res = await authorize(s.server, { client_id: 'conf', request: jar });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
  await done(s);
});

test('JAR rejects a signed request object addressed to another audience', async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJwkPublic(publicKey);
  const s = await setup({ authMethod: 'private_key_jwt', jwks: { keys: [{ ...jwk, kid: 'rs-1', use: 'sig' }] } });
  const jar = await new SignJWT({ response_type: 'code', redirect_uri: CB })
    .setProtectedHeader({ alg: 'RS256', kid: 'rs-1' }).setIssuedAt().setExpirationTime('5m')
    .setIssuer('conf').setAudience(`${ISSUER}/oauth/token`).sign(privateKey);
  const res = await authorize(s.server, { client_id: 'conf', request: jar });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
  await done(s);
});

test('JAR rejects an unsigned request object with the wrong audience', async () => {
  const s = await setup();
  const jar = await unsignedJar({ iss: 'pub', aud: `${ISSUER}/oauth/token`, exp: 2_000_000,
    response_type: 'code', client_id: 'pub', redirect_uri: CB });
  const res = await authorize(s.server, { request: jar });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
  await done(s);
});
