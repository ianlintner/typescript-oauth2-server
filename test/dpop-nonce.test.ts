import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import type { FastifyInstance } from 'fastify';
import { SignJWT, calculateJwkThumbprint, decodeJwt, exportJWK, exportPKCS8, generateKeyPair, type JWK } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import { ConfigError, loadConfig } from '../src/config.js';
import {
  DPOP_NONCE_GRACE_SECONDS, DPOP_NONCE_ROTATION_SECONDS, deriveDpopNonceKey, isValidDpopNonce, issueDpopNonce, type DpopNonceConfig,
} from '../src/dpop.js';
import type { Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const ISSUER = 'http://localhost:8080';
const TOKEN_URL = `${ISSUER}/oauth/token`;
const SECRET = 'confidential-client-secret-value';
const basicHeader = { authorization: `Basic ${Buffer.from(`conf:${SECRET}`).toString('base64')}` };
const dpopHeader = (token: string) => ({ authorization: `DPoP ${token}` });
const T0 = 1_000_020; // multiple of 60 so window boundaries are easy to reason about
const KEY = deriveDpopNonceKey('a-very-long-session-secret-for-nonce-tests');
const cfg = (required = true): DpopNonceConfig => ({ key: KEY, required });

interface Ctx { server: FastifyInstance; clock: Clock; advance(s: number): void }

async function setup(nonce: DpopNonceConfig | null = cfg(), store?: SqliteStore, state = { v: T0 }): Promise<Ctx> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const s = store ?? new SqliteStore(':memory:');
  if (!store) await s.init();
  await s.saveClient({ clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET), redirectUris: [], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true });
  const clock: Clock = { now: () => state.v };
  const server = buildServer({ store: s, signer, clock, random: cryptoRandom, issuer: ISSUER, dpopNonce: nonce ?? undefined });
  return { server, clock, advance: (n) => { state.v += n; } };
}

async function prover(clock: Clock) {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk: JWK = await exportJWK(publicKey);
  return {
    jwk, jkt: await calculateJwkThumbprint(jwk),
    proof: (claims: Record<string, unknown> = {}) =>
      new SignJWT({ jti: randomUUID(), htm: 'POST', htu: TOKEN_URL, iat: clock.now(), ...claims })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk }).sign(privateKey),
  };
}

const cc = (c: Ctx, proof: string) => c.server.inject({
  method: 'POST', url: '/oauth/token',
  headers: { 'content-type': 'application/x-www-form-urlencoded', ...basicHeader, dpop: proof },
  payload: 'grant_type=client_credentials',
});

// -- nonce primitive --

test('nonce is valid within its window and the grace period, then stale', () => {
  const n = issueDpopNonce(cfg(), T0 + 5);
  assert.equal(isValidDpopNonce(cfg(), n, T0 + 5), true);
  assert.equal(isValidDpopNonce(cfg(), n, T0 + DPOP_NONCE_ROTATION_SECONDS + DPOP_NONCE_GRACE_SECONDS - 1), true);
  assert.equal(isValidDpopNonce(cfg(), n, T0 + DPOP_NONCE_ROTATION_SECONDS + DPOP_NONCE_GRACE_SECONDS), false);
});

test('nonce from the future or after a clock step back is rejected (time skew)', () => {
  const n = issueDpopNonce(cfg(), T0 + 120);
  assert.equal(isValidDpopNonce(cfg(), n, T0 + 119), false);
});

test('forged, tampered, wrong-key and malformed nonces are rejected', () => {
  const n = issueDpopNonce(cfg(), T0);
  const [ts, mac] = n.split('.') as [string, string];
  const other: DpopNonceConfig = { key: deriveDpopNonceKey('another-secret-another-secret-another'), required: true };
  for (const bad of [
    `${Number(ts) + 60}.${mac}`, // timestamp changed, mac kept
    `${ts}.${mac.slice(0, -1)}${mac.endsWith('A') ? 'B' : 'A'}`,
    issueDpopNonce(other, T0),
    `${Number(ts) + 1}.${mac}`, // off-window timestamp
    ts, '', '.', `${ts}.`, `x.${mac}`, `${ts}.${mac}.extra`, 42, null, undefined, { a: 1 },
  ]) assert.equal(isValidDpopNonce(cfg(), bad, T0), false, String(bad));
});

test('a short nonce key is refused rather than used', () => {
  const weak: DpopNonceConfig = { key: Buffer.from('short'), required: true };
  assert.throws(() => issueDpopNonce(weak, T0));
  assert.equal(isValidDpopNonce(weak, `${T0}.${'A'.repeat(43)}`, T0), false);
});

// -- token endpoint --

test('required mode: proof without nonce gets 400 use_dpop_nonce plus a DPoP-Nonce header; retry with it succeeds', async () => {
  const c = await setup();
  const p = await prover(c.clock);
  const first = await cc(c, await p.proof());
  assert.equal(first.statusCode, 400);
  assert.equal(first.json().error, 'use_dpop_nonce');
  const nonce = String(first.headers['dpop-nonce']);
  assert.equal(nonce, issueDpopNonce(cfg(), T0));
  const retry = await cc(c, await p.proof({ nonce }));
  assert.equal(retry.statusCode, 200);
  assert.equal(retry.json().token_type, 'DPoP');
  assert.deepEqual(decodeJwt(retry.json().access_token).cnf, { jkt: p.jkt });
  assert.equal(typeof retry.headers['dpop-nonce'], 'string'); // §8.2: fresh nonce on success too
});

test('a use_dpop_nonce rejection does not burn the proof jti', async () => {
  const c = await setup();
  const p = await prover(c.clock);
  const jti = randomUUID();
  const first = await cc(c, await p.proof({ jti }));
  assert.equal(first.json().error, 'use_dpop_nonce');
  const ok = await cc(c, await p.proof({ jti, nonce: String(first.headers['dpop-nonce']) }));
  assert.equal(ok.statusCode, 200);
  const replay = await cc(c, await p.proof({ jti, nonce: String(first.headers['dpop-nonce']) }));
  assert.equal(replay.statusCode, 400);
  assert.equal(replay.json().error, 'invalid_dpop_proof');
});

test('forged nonce is rejected with use_dpop_nonce and a fresh nonce is offered', async () => {
  const c = await setup();
  const p = await prover(c.clock);
  const res = await cc(c, await p.proof({ nonce: `${T0}.${'A'.repeat(43)}` }));
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'use_dpop_nonce');
  assert.equal(res.headers['dpop-nonce'], issueDpopNonce(cfg(), T0));
});

test('nonce is accepted across the rotation boundary within grace, rejected once stale', async () => {
  const c = await setup();
  const p = await prover(c.clock);
  const nonce = issueDpopNonce(cfg(), T0);
  c.advance(DPOP_NONCE_ROTATION_SECONDS + 10); // new window, old nonce inside grace
  assert.equal((await cc(c, await p.proof({ nonce }))).statusCode, 200);
  c.advance(DPOP_NONCE_GRACE_SECONDS); // now past window + grace
  const stale = await cc(c, await p.proof({ nonce }));
  assert.equal(stale.statusCode, 400);
  assert.equal(stale.json().error, 'use_dpop_nonce');
  assert.equal(stale.headers['dpop-nonce'], issueDpopNonce(cfg(), c.clock.now()));
});

test('nonce signed by a different server key is rejected (cross-deployment)', async () => {
  const c = await setup();
  const p = await prover(c.clock);
  const foreign = issueDpopNonce({ key: deriveDpopNonceKey('some-other-deployments-secret-value-xx'), required: true }, T0);
  assert.equal((await cc(c, await p.proof({ nonce: foreign }))).json().error, 'use_dpop_nonce');
});

test('nonces are stateless: a second process with the same key accepts them', async () => {
  const a = await setup();
  const b = await setup();
  const p = await prover(a.clock);
  const nonce = String((await cc(a, await p.proof())).headers['dpop-nonce']);
  assert.equal((await cc(b, await p.proof({ nonce }))).statusCode, 200);
});

test('a malformed proof is still invalid_dpop_proof and is not handed a nonce', async () => {
  const c = await setup();
  const p = await prover(c.clock);
  const res = await cc(c, await p.proof({ htm: 'GET' }));
  assert.equal(res.json().error, 'invalid_dpop_proof');
  assert.equal(res.headers['dpop-nonce'], undefined);
});

test('nonces off (default): proofs without nonce work and no DPoP-Nonce header is sent', async () => {
  const c = await setup(null);
  const p = await prover(c.clock);
  const res = await cc(c, await p.proof());
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['dpop-nonce'], undefined);
});

test('optional mode: no nonce accepted, but a presented bad nonce is still rejected', async () => {
  const c = await setup(cfg(false));
  const p = await prover(c.clock);
  assert.equal((await cc(c, await p.proof())).statusCode, 200);
  const bad = await cc(c, await p.proof({ nonce: 'forged' }));
  assert.equal(bad.json().error, 'use_dpop_nonce');
});

test('requests without a DPoP header are unaffected in required mode', async () => {
  const c = await setup();
  const res = await c.server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...basicHeader },
    payload: 'grant_type=client_credentials',
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().token_type, 'Bearer');
  assert.equal(res.headers['dpop-nonce'], undefined);
});

// -- resource (userinfo) --

test('userinfo: required mode answers 401 use_dpop_nonce with DPoP-Nonce for a proof lacking one', async () => {
  const c = await setup();
  const p = await prover(c.clock);
  const tok = (await cc(c, await p.proof({ nonce: issueDpopNonce(cfg(), T0) }))).json().access_token as string;
  const ath = createHash('sha256').update(tok).digest('base64url');
  const get = async (nonce?: string) => c.server.inject({
    method: 'GET', url: '/oauth/userinfo',
    headers: { ...dpopHeader(tok), dpop: await p.proof({ htm: 'GET', htu: `${ISSUER}/oauth/userinfo`, ath, ...(nonce ? { nonce } : {}) }) },
  });
  const res = await get();
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'use_dpop_nonce');
  assert.match(String(res.headers['www-authenticate']), /^DPoP error="use_dpop_nonce"/);
  assert.equal(res.headers['dpop-nonce'], issueDpopNonce(cfg(), T0));
  // Retry with the nonce: a client_credentials token has sub === client_id so userinfo ends invalid_token, past the proof/nonce checks.
  const retry = await get(String(res.headers['dpop-nonce']));
  assert.notEqual(retry.json().error, 'use_dpop_nonce');
  assert.notEqual(retry.json().error, 'invalid_dpop_proof');
});

// -- config --

const baseEnv = {
  OAUTH2_ENV: 'development', OAUTH2_ISSUER: 'http://localhost:8080', OAUTH2_SESSION_SECRET: 'x'.repeat(40),
  OAUTH2_SIGNING_KEY_PEM: 'pem', OAUTH2_SIGNING_KEY_ID: 'k',
};

test('config: OAUTH2_DPOP_NONCE defaults off, accepts required, rejects other values', () => {
  assert.equal(loadConfig(baseEnv).dpopNonce, 'off');
  assert.equal(loadConfig({ ...baseEnv, OAUTH2_DPOP_NONCE: 'required' }).dpopNonce, 'required');
  assert.throws(() => loadConfig({ ...baseEnv, OAUTH2_DPOP_NONCE: 'yes' }), ConfigError);
});
