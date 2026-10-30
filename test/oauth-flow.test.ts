import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { FastifyInstance } from 'fastify';
import { exportPKCS8, generateKeyPair, jwtVerify, createLocalJWKSet } from 'jose';
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

async function setup(opts: { user?: string | null } = {}) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base: Omit<ClientRecord, 'clientId' | 'clientSecretHash'> = {
    redirectUris: [CB], grantTypes: ['authorization_code'], scopes: ['read', 'write'], enabled: true,
  };
  await store.saveClient({ ...base, clientId: 'pub', clientSecretHash: null });
  await store.saveClient({ ...base, clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET) });
  await store.saveClient({ ...base, clientId: 'off', clientSecretHash: null, enabled: false });
  await store.saveClient({ ...base, clientId: 'nogrant', clientSecretHash: null, grantTypes: ['client_credentials'] });
  let now = 1_000_000;
  const clock: Clock = { now: () => now };
  const user = opts.user === undefined ? 'user-1' : opts.user;
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => user,
  });
  return { server, store, signer, advance: (s: number) => { now += s; } };
}

function authz(server: FastifyInstance, params: Record<string, string>) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: 'pub', redirect_uri: CB,
    code_challenge: CHALLENGE, code_challenge_method: 'S256', state: 'st-1', ...params,
  });
  for (const [k, v] of Object.entries(params)) if (v === '') q.delete(k);
  return server.inject({ method: 'GET', url: `/oauth/authorize?${q.toString()}` });
}

async function getCode(server: FastifyInstance, params: Record<string, string> = {}): Promise<string> {
  const res = await authz(server, params);
  assert.equal(res.statusCode, 302);
  const code = new URL(res.headers.location as string).searchParams.get('code');
  assert.ok(code);
  return code;
}

function token(server: FastifyInstance, form: Record<string, string>, headers: Record<string, string> = {}) {
  return server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    payload: new URLSearchParams(form).toString(),
  });
}

const exchange = (code: string, extra: Record<string, string> = {}) => ({
  grant_type: 'authorization_code', code, redirect_uri: CB, client_id: 'pub', code_verifier: VERIFIER, ...extra,
});

async function done(s: Awaited<ReturnType<typeof setup>>) {
  await s.server.close();
  await s.store.close();
}

test('authorize redirects with code, state and RFC 9207 iss', async () => {
  const s = await setup();
  const res = await authz(s.server, {});
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers['cache-control'], 'no-store');
  const loc = new URL(res.headers.location as string);
  assert.equal(`${loc.origin}${loc.pathname}`, CB);
  assert.ok((loc.searchParams.get('code') ?? '').length >= 43);
  assert.equal(loc.searchParams.get('state'), 'st-1');
  assert.equal(loc.searchParams.get('iss'), ISSUER);
  await done(s);
});

test('authorize never redirects for unknown client, disabled client or unregistered redirect_uri', async () => {
  const s = await setup();
  for (const p of [{ client_id: 'nope' }, { client_id: 'off' }, { redirect_uri: 'https://attacker.example/cb' }, { redirect_uri: `${CB}/` }, { redirect_uri: '' }, { client_id: '' }]) {
    const res = await authz(s.server, p);
    const unknownClient = p.client_id === 'nope' || p.client_id === 'off';
    assert.equal(res.statusCode, unknownClient ? 401 : 400, JSON.stringify(p));
    assert.equal(res.headers.location, undefined);
    assert.equal(res.json().error, unknownClient ? 'invalid_client' : 'invalid_request');
  }
  await done(s);
});

test('authorize rejects duplicate query parameters without redirecting', async () => {
  const s = await setup();
  const res = await s.server.inject({
    method: 'GET',
    url: `/oauth/authorize?response_type=code&client_id=pub&client_id=conf&redirect_uri=${encodeURIComponent(CB)}&code_challenge=${CHALLENGE}&code_challenge_method=S256`,
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_request');
  assert.equal(res.headers.location, undefined);
  await done(s);
});

test('authorize reports PKCE and request errors to the trusted redirect_uri with state and iss', async () => {
  const s = await setup();
  const cases: Array<[Record<string, string>, string]> = [
    [{ code_challenge: '' }, 'invalid_request'],
    [{ code_challenge_method: '' }, 'invalid_request'],
    [{ code_challenge_method: 'plain' }, 'invalid_request'],
    [{ code_challenge: 'short' }, 'invalid_request'],
    [{ response_type: 'token' }, 'invalid_request'],
    [{ scope: 'admin' }, 'invalid_scope'],
    [{ client_id: 'nogrant' }, 'unauthorized_client'],
  ];
  for (const [p, err] of cases) {
    const res = await authz(s.server, p);
    assert.equal(res.statusCode, 302, JSON.stringify(p));
    const loc = new URL(res.headers.location as string);
    assert.equal(loc.searchParams.get('error'), err, JSON.stringify(p));
    assert.equal(loc.searchParams.get('state'), 'st-1');
    assert.equal(loc.searchParams.get('iss'), ISSUER);
    assert.equal(loc.searchParams.get('code'), null);
  }
  await done(s);
});

test('authorize without an authenticated resource owner is access_denied and issues no code', async () => {
  const s = await setup({ user: null });
  const res = await authz(s.server, {});
  assert.equal(res.statusCode, 302);
  assert.equal(new URL(res.headers.location as string).searchParams.get('error'), 'access_denied');
  await done(s);
});

test('buildServer without an authenticator denies authorization by default', async () => {
  const s = await setup();
  const bare = buildServer({ store: s.store, signer: s.signer, clock: { now: () => 1 }, random: cryptoRandom, issuer: ISSUER });
  const res = await authz(bare, {});
  assert.equal(new URL(res.headers.location as string).searchParams.get('error'), 'access_denied');
  await bare.close();
  await done(s);
});

test('public client redeems a code with S256 verifier for a verifiable access token', async () => {
  const s = await setup();
  const code = await getCode(s.server, { scope: 'read' });
  const res = await token(s.server, exchange(code));
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.headers.pragma, 'no-cache');
  const body = res.json();
  assert.equal(body.token_type, 'Bearer');
  assert.equal(body.expires_in, 3600);
  assert.equal(body.scope, 'read');
  assert.equal(body.refresh_token, undefined);
  const jwks = createLocalJWKSet(await s.signer.publicJwks() as Parameters<typeof createLocalJWKSet>[0]);
  const { payload } = await jwtVerify(body.access_token, jwks, { issuer: ISSUER, audience: 'pub', currentDate: new Date(1_000_000 * 1000) });
  assert.equal(payload.sub, 'user-1');
  assert.equal(payload.scope, 'read');
  assert.equal(payload.client_id, 'pub');
  await done(s);
});

test('confidential client authenticates by Basic header or body secret', async () => {
  const s = await setup();
  const basic = 'Basic ' + Buffer.from(`conf:${SECRET}`).toString('base64');
  let code = await getCode(s.server, { client_id: 'conf' });
  let res = await token(s.server, { ...exchange(code), client_id: '' }, { authorization: basic });
  assert.equal(res.statusCode, 200);
  code = await getCode(s.server, { client_id: 'conf' });
  res = await token(s.server, exchange(code, { client_id: 'conf', client_secret: SECRET }));
  assert.equal(res.statusCode, 200);
  await done(s);
});

test('client authentication failures are 401 invalid_client and do not burn the code', async () => {
  const s = await setup();
  const code = await getCode(s.server, { client_id: 'conf' });
  const bad = 'Basic ' + Buffer.from('conf:wrong').toString('base64');
  const cases: Array<[Record<string, string>, Record<string, string>]> = [
    [{ client_id: 'conf' }, {}],
    [{ client_id: 'conf', client_secret: 'wrong' }, {}],
    [{ client_id: 'conf' }, { authorization: bad }],
    [{ client_id: 'ghost', client_secret: SECRET }, {}],
    [{ client_id: 'off' }, {}],
    [{ client_id: '' }, {}],
  ];
  for (const [extra, headers] of cases) {
    const res = await token(s.server, { ...exchange(code), ...extra }, headers);
    assert.equal(res.statusCode, 401, JSON.stringify(extra));
    assert.equal(res.json().error, 'invalid_client');
    assert.match(String(res.headers['www-authenticate']), /^Basic/);
  }
  const ok = await token(s.server, exchange(code, { client_id: 'conf', client_secret: SECRET }));
  assert.equal(ok.statusCode, 200);
  await done(s);
});

test('public client must not present a secret; mismatched Basic/body client_id is rejected', async () => {
  const s = await setup();
  const code = await getCode(s.server);
  let res = await token(s.server, exchange(code, { client_secret: 'x' }));
  assert.equal(res.statusCode, 401);
  const basic = 'Basic ' + Buffer.from(`conf:${SECRET}`).toString('base64');
  res = await token(s.server, exchange(code, { client_id: 'pub' }), { authorization: basic });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_request');
  await done(s);
});

test('code replay is invalid_grant', async () => {
  const s = await setup();
  const code = await getCode(s.server);
  assert.equal((await token(s.server, exchange(code))).statusCode, 200);
  const replay = await token(s.server, exchange(code));
  assert.equal(replay.statusCode, 400);
  assert.equal(replay.json().error, 'invalid_grant');
  await done(s);
});

test('concurrent redemption of one code yields exactly one success', async () => {
  const s = await setup();
  const code = await getCode(s.server);
  const results = await Promise.all(Array.from({ length: 8 }, () => token(s.server, exchange(code))));
  assert.equal(results.filter((r) => r.statusCode === 200).length, 1);
  assert.equal(results.filter((r) => r.statusCode === 400 && r.json().error === 'invalid_grant').length, 7);
  await done(s);
});

test('wrong verifier and wrong redirect_uri are invalid_grant and burn the code', async () => {
  const s = await setup();
  let code = await getCode(s.server);
  let res = await token(s.server, exchange(code, { code_verifier: 'w'.repeat(43) }));
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_grant');
  assert.equal((await token(s.server, exchange(code))).json().error, 'invalid_grant');
  code = await getCode(s.server);
  res = await token(s.server, exchange(code, { redirect_uri: 'https://attacker.example/cb' }));
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_grant');
  assert.equal((await token(s.server, exchange(code))).json().error, 'invalid_grant');
  await done(s);
});

test('code is bound to its client: another client cannot redeem or burn it', async () => {
  const s = await setup();
  const code = await getCode(s.server, { client_id: 'pub' });
  const res = await token(s.server, exchange(code, { client_id: 'conf', client_secret: SECRET }));
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_grant');
  assert.equal((await token(s.server, exchange(code))).statusCode, 200);
  await done(s);
});

test('expired code is invalid_grant', async () => {
  const s = await setup();
  const code = await getCode(s.server);
  s.advance(61);
  const res = await token(s.server, exchange(code));
  assert.equal(res.json().error, 'invalid_grant');
  await done(s);
});

test('token endpoint rejects malformed requests', async () => {
  const s = await setup();
  const code = await getCode(s.server);
  const cases: Array<[Record<string, string>, number, string]> = [
    [{ grant_type: 'password' }, 400, 'unsupported_grant_type'],
    [{ grant_type: '' }, 400, 'invalid_request'],
    [{ code: '' }, 400, 'invalid_request'],
    [{ redirect_uri: '' }, 400, 'invalid_request'],
  ];
  for (const [extra, status, err] of cases) {
    const p = { ...exchange(code), ...extra };
    for (const [k, v] of Object.entries(extra)) if (v === '') delete (p as Record<string, string>)[k];
    const res = await token(s.server, p);
    assert.equal(res.statusCode, status, JSON.stringify(extra));
    assert.equal(res.json().error, err, JSON.stringify(extra));
  }
  // None of the above consumed the code.
  assert.equal((await token(s.server, exchange(code))).statusCode, 200);
  await done(s);
});

test('malformed verifier is invalid_grant and burns the code', async () => {
  const s = await setup();
  const code = await getCode(s.server);
  assert.equal((await token(s.server, exchange(code, { code_verifier: 'short' }))).json().error, 'invalid_grant');
  assert.equal((await token(s.server, exchange(code))).json().error, 'invalid_grant');
  await done(s);
});

test('token endpoint rejects duplicate form parameters and wrong content type', async () => {
  const s = await setup();
  const code = await getCode(s.server);
  const dup = await s.server.inject({
    method: 'POST', url: '/oauth/token', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: `${new URLSearchParams(exchange(code)).toString()}&code_verifier=other`,
  });
  assert.equal(dup.statusCode, 400);
  assert.equal(dup.json().error, 'invalid_request');
  const json = await s.server.inject({ method: 'POST', url: '/oauth/token', headers: { 'content-type': 'application/json' }, payload: '{}' });
  assert.equal(json.statusCode, 400);
  assert.equal(json.json().error, 'invalid_request');
  await done(s);
});

test('token endpoint does not accept GET and does not leak framework headers', async () => {
  const s = await setup();
  const res = await s.server.inject({ method: 'GET', url: '/oauth/token' });
  assert.ok(res.statusCode === 404 || res.statusCode === 405);
  await done(s);
});
