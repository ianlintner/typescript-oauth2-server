import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { FastifyInstance } from 'fastify';
import { SignJWT, calculateJwkThumbprint, decodeJwt, exportJWK, exportPKCS8, generateKeyPair, type JWK } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { ClientRecord, Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const ISSUER = 'http://localhost:8080';
const TOKEN_URL = `${ISSUER}/oauth/token`;
const USERINFO_URL = `${ISSUER}/oauth/userinfo`;
const CB = 'https://app.example/cb';
const VERIFIER = 'v'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const SECRET = 'confidential-client-secret-value';
const BASIC = `Basic ${Buffer.from(`conf:${SECRET}`).toString('base64')}`;
const T0 = 1_000_000;

interface Prover {
  jwk: JWK;
  jkt: string;
  proof(claims?: Record<string, unknown>, header?: Record<string, unknown>): Promise<string>;
}

async function prover(clock: Clock, htm: string, htu: string): Promise<Prover> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  return {
    jwk, jkt,
    proof: (claims = {}, header = {}) => {
      const body: Record<string, unknown> = { jti: randomUUID(), htm, htu, iat: clock.now(), ...claims };
      for (const [k, v] of Object.entries(body)) if (v === undefined) delete body[k];
      return new SignJWT(body).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk, ...header }).sign(privateKey);
    },
  };
}

interface Ctx { server: FastifyInstance; store: SqliteStore; clock: Clock; advance(s: number): void }

async function setup(opts: { path?: string; now?: { v: number }; store?: SqliteStore } = {}): Promise<Ctx> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  // Same key for every process sharing a DB: derive from a fixed PEM passed in via opts is unnecessary; each server verifies only its own tokens.
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = opts.store ?? new SqliteStore(opts.path ?? ':memory:');
  if (!opts.store) await store.init();
  const base: Omit<ClientRecord, 'clientId' | 'clientSecretHash'> = {
    redirectUris: [CB], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'], scopes: ['openid', 'read'], enabled: true,
  };
  await store.saveClient({ ...base, clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET) });
  await store.saveClient({ ...base, clientId: 'pub', clientSecretHash: null });
  const state = opts.now ?? { v: T0 };
  const clock: Clock = { now: () => state.v };
  const server = buildServer({ store, signer, clock, random: cryptoRandom, issuer: ISSUER, authenticate: async () => 'user-1' });
  return { server, store, clock, advance: (s) => { state.v += s; } };
}

const post = (c: Ctx, form: Record<string, string>, headers: Record<string, string>) =>
  c.server.inject({ method: 'POST', url: '/oauth/token', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, payload: new URLSearchParams(form).toString() });

const cc = (c: Ctx, proof?: string) => post(c, { grant_type: 'client_credentials' }, { authorization: BASIC, ...(proof ? { dpop: proof } : {}) });

async function userToken(c: Ctx, p: Prover, client: 'conf' | 'pub' = 'conf', scope = 'openid') {
  const auth = await c.server.inject({
    method: 'GET',
    url: `/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: client, redirect_uri: CB, scope, state: 's', code_challenge: CHALLENGE, code_challenge_method: 'S256' })}`,
  });
  const code = new URL(String(auth.headers.location)).searchParams.get('code')!;
  return post(c, { grant_type: 'authorization_code', code, redirect_uri: CB, code_verifier: VERIFIER, ...(client === 'pub' ? { client_id: 'pub' } : {}) },
    { ...(client === 'conf' ? { authorization: BASIC } : {}), dpop: await p.proof() });
}

const ath = (t: string) => createHash('sha256').update(t).digest('base64url');

// -- issuance --

test('a valid DPoP proof yields a DPoP-typed token bound by cnf.jkt', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  const res = await cc(c, await p.proof());
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().token_type, 'DPoP');
  assert.deepEqual(decodeJwt(res.json().access_token).cnf, { jkt: p.jkt });
});

test('no DPoP header keeps issuing unbound Bearer tokens', async () => {
  const c = await setup();
  const res = await cc(c);
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().token_type, 'Bearer');
  assert.equal(decodeJwt(res.json().access_token).cnf, undefined);
});

test('htu ignores query and fragment but a different path is rejected', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', `${TOKEN_URL}?x=1#frag`);
  assert.equal((await cc(c, await p.proof())).statusCode, 200);
  const q = await prover(c.clock, 'POST', `${ISSUER}/oauth/other`);
  const bad = await cc(c, await q.proof());
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.json().error, 'invalid_dpop_proof');
});

// -- negative proof validation --

const negatives: Array<[string, Record<string, unknown>, Record<string, unknown>]> = [
  ['wrong typ', {}, { typ: 'JWT' }],
  ['missing jti', { jti: undefined }, {}],
  ['wrong htm', { htm: 'GET' }, {}],
  ['wrong htu', { htu: `${ISSUER}/elsewhere` }, {}],
  ['missing iat', { iat: undefined }, {}],
  ['stale iat', { iat: T0 - 301 }, {}],
  ['future iat', { iat: T0 + 61 }, {}],
  ['missing jwk', {}, { jwk: undefined }],
];
for (const [name, claims, header] of negatives) {
  test(`proof rejected: ${name}`, async () => {
    const c = await setup();
    const p = await prover(c.clock, 'POST', TOKEN_URL);
    const res = await cc(c, await p.proof(claims, header));
    assert.equal(res.statusCode, 400);
    assert.equal(res.json().error, 'invalid_dpop_proof');
  });
}

test('proof rejected: private key material in jwk', async () => {
  const c = await setup();
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(privateKey);
  const body = await new SignJWT({ jti: 'j', htm: 'POST', htu: TOKEN_URL, iat: T0 })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk }).sign(privateKey);
  const res = await cc(c, body);
  assert.equal(res.json().error, 'invalid_dpop_proof');
});

test('proof rejected: symmetric alg and alg none', async () => {
  const c = await setup();
  const hs = await new SignJWT({ jti: 'j', htm: 'POST', htu: TOKEN_URL, iat: T0 })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'HS256', jwk: { kty: 'oct', k: 'c2VjcmV0' } as unknown as JWK }).sign(new TextEncoder().encode('secret'));
  assert.equal((await cc(c, hs)).json().error, 'invalid_dpop_proof');
  const none = `${Buffer.from('{"typ":"dpop+jwt","alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify({ jti: 'j', htm: 'POST', htu: TOKEN_URL, iat: T0 })).toString('base64url')}.`;
  assert.equal((await cc(c, none)).json().error, 'invalid_dpop_proof');
});

test('proof rejected: signature made by a different key than the embedded jwk', async () => {
  const c = await setup();
  const a = await prover(c.clock, 'POST', TOKEN_URL);
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const forged = await new SignJWT({ jti: 'j', htm: 'POST', htu: TOKEN_URL, iat: T0 })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: a.jwk }).sign(privateKey);
  assert.equal((await cc(c, forged)).json().error, 'invalid_dpop_proof');
});

test('proof rejected: garbage and multiple DPoP headers', async () => {
  const c = await setup();
  assert.equal((await cc(c, 'not-a-jwt')).statusCode, 400);
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  const res = await c.server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: BASIC, dpop: [await p.proof(), await p.proof()] },
    payload: 'grant_type=client_credentials',
  });
  assert.equal(res.json().error, 'invalid_dpop_proof');
});

// -- time skew --

test('iat just inside the window is accepted on both sides', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  assert.equal((await cc(c, await p.proof({ iat: T0 - 300 }))).statusCode, 200);
  assert.equal((await cc(c, await p.proof({ iat: T0 + 60 }))).statusCode, 200);
});

// -- replay --

test('replayed proof (same jti) is rejected, even after the clock moves inside the window', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  const proof = await p.proof();
  assert.equal((await cc(c, proof)).statusCode, 200);
  c.advance(30);
  const again = await cc(c, proof);
  assert.equal(again.statusCode, 400);
  assert.equal(again.json().error, 'invalid_dpop_proof');
});

test('a rejected proof does not burn its jti', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  assert.equal((await cc(c, await p.proof({ jti: 'same', htm: 'GET' }))).statusCode, 400);
  assert.equal((await cc(c, await p.proof({ jti: 'same' }))).statusCode, 200);
});

test('replay is rejected across processes sharing a database and survives restart', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dpop-'));
  const path = join(dir, 'db.sqlite');
  try {
    const a = await setup({ path });
    const b = await setup({ path }); // second "process": independent connection and server
    const p = await prover(a.clock, 'POST', TOKEN_URL);
    const proof = await p.proof();
    assert.equal((await cc(a, proof)).statusCode, 200);
    assert.equal((await cc(b, proof)).json().error, 'invalid_dpop_proof');
    await a.server.close(); await a.store.close();
    await b.server.close(); await b.store.close();
    const restarted = await setup({ path });
    assert.equal((await cc(restarted, proof)).json().error, 'invalid_dpop_proof');
    await restarted.server.close(); await restarted.store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('replay entries expire with the freshness window', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  assert.equal((await cc(c, await p.proof({ jti: 'old' }))).statusCode, 200);
  c.advance(1000);
  // A proof reusing the jti with a fresh iat is a new proof once the old entry has aged out.
  assert.equal((await cc(c, await p.proof({ jti: 'old' }))).statusCode, 200);
});

// -- protected resource: ath / cnf.jkt --

test('userinfo accepts a bound token with a matching proof incl. ath', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  const t = (await userToken(c, p)).json().access_token as string;
  const res = await c.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: { authorization: `DPoP ${t}`, dpop: await p.proof({ htm: 'GET', htu: USERINFO_URL, ath: ath(t) }) } });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().sub, 'user-1');
});

test('userinfo rejects: missing ath, wrong ath, wrong key, no proof, Bearer scheme', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  const t = (await userToken(c, p)).json().access_token as string;
  const get = (headers: Record<string, string>) => c.server.inject({ method: 'GET', url: '/oauth/userinfo', headers });
  const claims = { htm: 'GET', htu: USERINFO_URL };

  const noAth = await get({ authorization: `DPoP ${t}`, dpop: await p.proof(claims) });
  assert.equal(noAth.statusCode, 401);
  assert.match(String(noAth.headers['www-authenticate']), /^DPoP .*invalid_dpop_proof/);

  assert.equal((await get({ authorization: `DPoP ${t}`, dpop: await p.proof({ ...claims, ath: ath('other') }) })).statusCode, 401);

  const other = await prover(c.clock, 'GET', USERINFO_URL);
  const wrongKey = await get({ authorization: `DPoP ${t}`, dpop: await other.proof({ ...claims, ath: ath(t) }) });
  assert.equal(wrongKey.statusCode, 401);
  assert.match(String(wrongKey.headers['www-authenticate']), /invalid_token/);

  assert.equal((await get({ authorization: `DPoP ${t}` })).statusCode, 401);
  const asBearer = await get({ authorization: `Bearer ${t}` });
  assert.equal(asBearer.statusCode, 401);
});

test('userinfo rejects a DPoP-scheme request for an unbound token', async () => {
  const c = await setup();
  const t = (await post(c, { grant_type: 'authorization_code', ...(await codeFor(c)), code_verifier: VERIFIER }, { authorization: BASIC })).json().access_token as string;
  const p = await prover(c.clock, 'GET', USERINFO_URL);
  const res = await c.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: { authorization: `DPoP ${t}`, dpop: await p.proof({ ath: ath(t) }) } });
  assert.equal(res.statusCode, 401);
});

async function codeFor(c: Ctx) {
  const auth = await c.server.inject({ method: 'GET', url: `/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: 'conf', redirect_uri: CB, scope: 'openid', code_challenge: CHALLENGE, code_challenge_method: 'S256' })}` });
  return { code: new URL(String(auth.headers.location)).searchParams.get('code')!, redirect_uri: CB };
}

test('resource proof replay is rejected', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  const t = (await userToken(c, p)).json().access_token as string;
  const proof = await p.proof({ htm: 'GET', htu: USERINFO_URL, ath: ath(t) });
  const h = { authorization: `DPoP ${t}`, dpop: proof };
  assert.equal((await c.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: h })).statusCode, 200);
  assert.equal((await c.server.inject({ method: 'GET', url: '/oauth/userinfo', headers: h })).statusCode, 401);
});

// -- introspection / discovery / refresh --

test('introspection reports token_type DPoP and cnf.jkt for bound tokens', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  const t = (await cc(c, await p.proof())).json().access_token as string;
  const res = await c.server.inject({
    method: 'POST', url: '/oauth/introspect',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: BASIC },
    payload: new URLSearchParams({ token: t }).toString(),
  });
  assert.equal(res.json().active, true);
  assert.equal(res.json().token_type, 'DPoP');
  assert.deepEqual(res.json().cnf, { jkt: p.jkt });
});

test('discovery advertises dpop_signing_alg_values_supported', async () => {
  const c = await setup();
  const res = await c.server.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' });
  assert.deepEqual(res.json().dpop_signing_alg_values_supported, ['ES256']);
});

test('public-client refresh token is bound to the DPoP key; other key or no proof cannot refresh', async () => {
  const c = await setup();
  const p = await prover(c.clock, 'POST', TOKEN_URL);
  const first = (await userToken(c, p, 'pub')).json();
  assert.ok(first.refresh_token);
  const refresh = (proof?: string) => post(c, { grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: 'pub' }, proof ? { dpop: proof } : {});

  const other = await prover(c.clock, 'POST', TOKEN_URL);
  assert.equal((await refresh(await other.proof())).statusCode, 400);
  assert.equal((await refresh()).statusCode, 400);
  // failed attempts must not have consumed the token
  const ok = await refresh(await p.proof());
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.json().token_type, 'DPoP');
  assert.deepEqual(decodeJwt(ok.json().access_token).cnf, { jkt: p.jkt });
});
