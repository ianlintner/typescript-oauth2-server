import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { SignJWT, calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, exportJWK, exportPKCS8, generateKeyPair, type JWK } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import { ACCESS_TOKEN_TYP } from '../src/oauth.js';
import type { ClientRecord, Clock, Signer } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const ISSUER = 'http://localhost:8080';
const GT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const AT = 'urn:ietf:params:oauth:token-type:access_token';
const JWT_T = 'urn:ietf:params:oauth:token-type:jwt';
const T0 = 1_000_000;
const SECRET = 'exchange-client-secret-value';
const basic = (id: string) => `Basic ${Buffer.from(`${id}:${SECRET}`).toString('base64')}`;

async function setup(opts: { maxDelegationDepth?: number; clients?: Partial<ClientRecord> & { clientId: string }[] } = {}) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const secretHash = await hashClientSecret(SECRET);
  const base = { redirectUris: [], grantTypes: ['client_credentials', GT], scopes: ['read', 'write'], enabled: true };
  // a: exchanging client. b: another client whose tokens a may or may not exchange.
  await store.saveClient({ ...base, clientId: 'a', clientSecretHash: secretHash });
  await store.saveClient({ ...base, clientId: 'b', clientSecretHash: secretHash });
  await store.saveClient({ ...base, clientId: 'noexch', clientSecretHash: secretHash, grantTypes: ['client_credentials'] });
  await store.saveClient({ ...base, clientId: 'pub', clientSecretHash: null });
  await store.saveClient({ ...base, clientId: 'narrow', clientSecretHash: secretHash, scopes: ['read'] });
  const state = { v: T0 };
  const clock: Clock = { now: () => state.v };
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER, authenticate: async () => 'u',
    ...(opts.maxDelegationDepth !== undefined ? { maxDelegationDepth: opts.maxDelegationDepth } : {}),
  });
  const post = (form: Record<string, string>, headers: Record<string, string> = {}) =>
    server.inject({ method: 'POST', url: '/oauth/token', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, payload: new URLSearchParams(form).toString() });
  /** Real token via client_credentials. */
  const cc = async (client: string, scope = 'read write', headers: Record<string, string> = {}): Promise<string> => {
    const res = await post({ grant_type: 'client_credentials', scope }, { authorization: basic(client), ...headers });
    assert.equal(res.statusCode, 200, res.body);
    return res.json().access_token as string;
  };
  /** A token this server signed and recorded, with arbitrary extra claims (e.g. may_act, act, aud, cnf). */
  const mint = async (claims: Record<string, unknown>, ttl = 3600): Promise<string> => {
    const jti = randomUUID();
    const body = { iss: ISSUER, sub: 'a', aud: 'a', client_id: 'a', scope: 'read write', iat: state.v, exp: state.v + ttl, jti, ...claims };
    const token = await signer.sign(body, { typ: ACCESS_TOKEN_TYP });
    await store.saveAccessToken({
      jti, clientId: String(body.client_id), subject: String(body.sub), scope: String(body.scope ?? ''),
      expiresAt: Number(body.exp), revokedAt: null, tokenHash: null,
    });
    return token;
  };
  const exchange = (client: string, form: Record<string, string>, headers: Record<string, string> = {}) =>
    post({ grant_type: GT, subject_token_type: AT, ...form }, { authorization: basic(client), ...headers });
  return { store, server, signer: signer as Signer, state, post, cc, mint, exchange };
}

test('exchanged access token inherits the subject grant and is revoked by its cascade', async () => {
  const c = await setup();
  const grant = `grant-${randomUUID()}`;
  const jti = `subject-${randomUUID()}`;
  const subjectToken = await c.signer.sign({
    iss: ISSUER, sub: 'a', aud: 'a', client_id: 'a', scope: 'read',
    iat: T0, exp: T0 + 3600, jti,
  }, { typ: ACCESS_TOKEN_TYP });
  await c.store.saveAccessToken({
    jti, clientId: 'a', subject: 'a', scope: 'read',
    expiresAt: T0 + 3600, revokedAt: null, tokenHash: null, grant,
  });
  const res = await c.exchange('a', { subject_token: subjectToken, scope: 'read' });
  assert.equal(res.statusCode, 200, res.body);
  const exchangedJti = String(decodeJwt(res.json().access_token)!.jti);
  const before = await c.store.getAccessToken(exchangedJti, T0);
  assert.ok(before);
  assert.equal(before!.grant, grant);
  await c.store.revokeGrant(grant, T0);
  assert.equal(await c.store.getAccessToken(exchangedJti, T0), null);
  await c.server.close();
  await c.store.close();
});

// ---- positive paths ----

test('same-client exchange narrows scope and returns RFC 8693 response members', async () => {
  const c = await setup();
  const subj = await c.cc('a');
  const res = await c.exchange('a', { subject_token: subj, scope: 'read' });
  assert.equal(res.statusCode, 200, res.body);
  const body = res.json();
  assert.equal(body.issued_token_type, AT);
  assert.equal(body.token_type, 'Bearer');
  assert.equal(body.expires_in, 3600);
  assert.equal(body.scope, 'read');
  assert.notEqual(body.access_token, subj);
  assert.equal(res.headers['cache-control'], 'no-store');
  const claims = decodeJwt(body.access_token);
  assert.equal(claims.iss, ISSUER);
  assert.equal(claims.sub, 'a');
  assert.equal(claims.client_id, 'a');
  assert.equal(claims.aud, 'a');
  assert.equal(claims.scope, 'read');
  assert.equal(claims.act, undefined);
  // the issued token is recorded (usable at userinfo/introspection/revocation, and exchangeable again)
  const again = await c.exchange('a', { subject_token: body.access_token });
  assert.equal(again.statusCode, 200, again.body);
});

test('exchanged access tokens carry typ at+jwt and introspect as active', async () => {
  const c = await setup();
  const subj = await c.cc('a');
  const res = await c.exchange('a', { subject_token: subj, scope: 'read' });
  assert.equal(res.statusCode, 200, res.body);
  const token = res.json().access_token as string;
  assert.equal(decodeProtectedHeader(token).typ, ACCESS_TOKEN_TYP);
  const introspection = await c.server.inject({
    method: 'POST', url: '/oauth/introspect',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic('a') },
    payload: new URLSearchParams({ token, token_type_hint: 'access_token' }).toString(),
  });
  assert.equal(introspection.statusCode, 200, introspection.body);
  assert.equal(introspection.json().active, true);
});

test('a recorded token without typ at+jwt is rejected as a subject token', async () => {
  const c = await setup();
  const jti = randomUUID();
  const body = { iss: ISSUER, sub: 'a', aud: 'a', client_id: 'a', scope: 'read write', iat: c.state.v, exp: c.state.v + 3600, jti };
  const legacy = await c.signer.sign(body); // default typ JWT, still on record
  await c.store.saveAccessToken({
    jti, clientId: 'a', subject: 'a', scope: 'read write', expiresAt: c.state.v + 3600,
    revokedAt: null, tokenHash: null,
  });
  const res = await c.exchange('a', { subject_token: legacy });
  assert.equal(res.statusCode, 400, res.body);
  assert.equal(res.json().error, 'invalid_request');
});

test('omitted scope inherits the subject token scope', async () => {
  const c = await setup();
  const res = await c.exchange('a', { subject_token: await c.cc('a', 'read write') });
  assert.equal(res.statusCode, 200, res.body);
  assert.equal(res.json().scope, 'read write');
});

test('subject_token_type jwt is accepted and requested_token_type jwt is echoed as issued_token_type', async () => {
  const c = await setup();
  const res = await c.exchange('a', { subject_token: await c.cc('a'), subject_token_type: JWT_T, requested_token_type: JWT_T, scope: 'read' });
  assert.equal(res.statusCode, 200, res.body);
  assert.equal(res.json().issued_token_type, JWT_T);
});

test('issued token lifetime never exceeds the subject token lifetime', async () => {
  const c = await setup();
  const subj = await c.mint({}, 600);
  const res = await c.exchange('a', { subject_token: subj });
  assert.equal(res.statusCode, 200, res.body);
  assert.equal(res.json().expires_in, 600);
  assert.equal(decodeJwt(res.json().access_token).exp, T0 + 600);
});

test('client authentication by Basic and by client_secret_post both work', async () => {
  const c = await setup();
  const subj = await c.cc('a');
  const res = await c.post({ grant_type: GT, subject_token: subj, subject_token_type: AT, client_id: 'a', client_secret: SECRET });
  assert.equal(res.statusCode, 200, res.body);
});

// ---- request validation ----

test('missing subject_token or subject_token_type is invalid_request', async () => {
  const c = await setup();
  const r1 = await c.post({ grant_type: GT, subject_token_type: AT }, { authorization: basic('a') });
  assert.equal(r1.statusCode, 400);
  assert.equal(r1.json().error, 'invalid_request');
  const r2 = await c.post({ grant_type: GT, subject_token: await c.cc('a') }, { authorization: basic('a') });
  assert.equal(r2.statusCode, 400);
  assert.equal(r2.json().error, 'invalid_request');
});

test('unsupported subject_token_type, requested_token_type and authorization_details are invalid_request', async () => {
  const c = await setup();
  const subj = await c.cc('a');
  for (const extra of [
    { subject_token_type: 'urn:ietf:params:oauth:token-type:saml2' },
    { subject_token_type: 'urn:ietf:params:oauth:token-type:refresh_token' },
    { requested_token_type: 'urn:ietf:params:oauth:token-type:id_token' },
    { authorization_details: '[{"type":"x"}]' },
  ]) {
    const res = await c.exchange('a', { subject_token: subj, ...extra });
    assert.equal(res.statusCode, 400, JSON.stringify(extra));
    assert.equal(res.json().error, 'invalid_request', JSON.stringify(extra));
  }
});

test('a non-token subject_token is invalid_request (RFC 8693 §2.2.2)', async () => {
  const c = await setup();
  const res = await c.exchange('a', { subject_token: 'not-a-token' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_request');
});

test('actor_token and actor_token_type must appear together', async () => {
  const c = await setup();
  const subj = await c.cc('a');
  const r1 = await c.exchange('a', { subject_token: subj, actor_token: await c.cc('a') });
  assert.equal(r1.json().error, 'invalid_request');
  const r2 = await c.exchange('a', { subject_token: subj, actor_token_type: AT });
  assert.equal(r2.json().error, 'invalid_request');
});

// ---- client policy ----

test('public clients, clients without the grant and bad secrets are refused', async () => {
  const c = await setup();
  const subj = await c.cc('a');
  const pub = await c.post({ grant_type: GT, subject_token: subj, subject_token_type: AT, client_id: 'pub' });
  assert.equal(pub.statusCode, 401);
  assert.equal(pub.json().error, 'invalid_client');
  const noexch = await c.exchange('noexch', { subject_token: subj });
  assert.equal(noexch.statusCode, 400);
  assert.equal(noexch.json().error, 'unauthorized_client');
  const bad = await c.post({ grant_type: GT, subject_token: subj, subject_token_type: AT }, { authorization: `Basic ${Buffer.from('a:wrong').toString('base64')}` });
  assert.equal(bad.statusCode, 401);
  assert.equal(bad.json().error, 'invalid_client');
});

// ---- subject token resolution ----

test('expired, revoked, unrecorded and foreign-issuer subject tokens are rejected', async () => {
  const c = await setup();
  const foreignKey = await generateKeyPair('ES256');
  const expectRejected = async (name: string, token: string) => {
    const res = await c.exchange('a', { subject_token: token });
    assert.equal(res.statusCode, 400, name);
    assert.equal(res.json().error, 'invalid_request', name);
  };
  // Control: a live token exchanges, so each case below varies only its own condition.
  assert.equal((await c.exchange('a', { subject_token: await c.cc('a') })).statusCode, 200);

  // revoked: unexpired, validly signed, recorded, then revoked
  const revoked = await c.cc('a');
  await c.store.revokeAccessToken(decodeJwt(revoked).jti as string, c.state.v);
  await expectRejected('revoked', revoked);

  // validly signed by this server but never recorded (e.g. an ID token): must not resolve
  const unrecorded = await c.signer.sign({ iss: ISSUER, sub: 'a', aud: 'a', client_id: 'a', scope: 'read', iat: T0, exp: T0 + 3600, jti: randomUUID() });
  await expectRejected('unrecorded', unrecorded);

  const foreign = await new SignJWT({ iss: 'https://evil.example', sub: 'a', client_id: 'a', scope: 'read', jti: randomUUID() })
    .setProtectedHeader({ alg: 'ES256' }).setIssuedAt(T0).setExpirationTime(T0 + 3600).sign(foreignKey.privateKey);
  await expectRejected('foreign issuer', foreign);
  const wrongKey = await new SignJWT({ iss: ISSUER, sub: 'a', client_id: 'a', scope: 'read', jti: randomUUID() })
    .setProtectedHeader({ alg: 'ES256' }).setIssuedAt(T0).setExpirationTime(T0 + 3600).sign(foreignKey.privateKey);
  await expectRejected('wrong key', wrongKey);

  // expired: only the clock moves
  const expiring = await c.cc('a');
  c.state.v += 3601;
  await expectRejected('expired', expiring);
});

// ---- scope ----

test('scope beyond the subject token is invalid_scope', async () => {
  const c = await setup();
  const res = await c.exchange('a', { subject_token: await c.cc('a', 'read'), scope: 'read write' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_scope');
});

test('scope within the subject but beyond the exchanging client registration is invalid_scope', async () => {
  const c = await setup();
  // subject (issued to narrow, then granted wider by a signed token) carries write which narrow may not hold
  const subj = await c.mint({ client_id: 'narrow', sub: 'narrow', aud: 'narrow', scope: 'read write' });
  const explicit = await c.exchange('narrow', { subject_token: subj, scope: 'read write' });
  assert.equal(explicit.json().error, 'invalid_scope');
  const inherited = await c.exchange('narrow', { subject_token: subj });
  assert.equal(inherited.json().error, 'invalid_scope');
});

// ---- cross-client exchange ----

test('exchanging a token issued to another client requires that client to list the caller in allowedActors', async () => {
  const c = await setup();
  const bToken = await c.cc('b');
  const denied = await c.exchange('a', { subject_token: bToken });
  assert.equal(denied.statusCode, 400);
  assert.equal(denied.json().error, 'invalid_request');

  const b = (await c.store.getClient('b'))!;
  await c.store.saveClient({ ...b, allowedActors: ['a'] });
  const allowed = await c.exchange('a', { subject_token: bToken, scope: 'read' });
  assert.equal(allowed.statusCode, 200, allowed.body);
  // the new token belongs to the exchanging client, the subject is preserved
  const claims = decodeJwt(allowed.json().access_token);
  assert.equal(claims.client_id, 'a');
  assert.equal(claims.sub, 'b');
});

test('allowedActors round-trips through the store', async () => {
  const c = await setup();
  const b = (await c.store.getClient('b'))!;
  assert.equal(b.allowedActors, undefined);
  await c.store.saveClient({ ...b, allowedActors: ['a', 'x'] });
  assert.deepEqual((await c.store.getClient('b'))!.allowedActors, ['a', 'x']);
});

// ---- delegation ----

test('actor_token with no basis for delegation is refused', async () => {
  const c = await setup();
  const res = await c.exchange('a', { subject_token: await c.cc('a'), actor_token: await c.mint({ sub: 'svc' }), actor_token_type: AT });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_request');
});

test('an actor token issued to a different client is refused', async () => {
  const c = await setup();
  const subj = await c.mint({ may_act: { sub: 'svc' } });
  const actor = await c.mint({ sub: 'svc', client_id: 'b', aud: 'b' });
  const res = await c.exchange('a', { subject_token: subj, actor_token: actor, actor_token_type: AT });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_request');
});

test('may_act on the subject token authorizes delegation and records the act claim', async () => {
  const c = await setup();
  const subj = await c.mint({ sub: 'alice', may_act: { sub: 'svc', iss: ISSUER } });
  const actor = await c.mint({ sub: 'svc' });
  const res = await c.exchange('a', { subject_token: subj, actor_token: actor, actor_token_type: AT, scope: 'read' });
  assert.equal(res.statusCode, 200, res.body);
  assert.equal(res.json().act, undefined, 'RFC 8693 §2.2.1: act is expressed in the token, not alongside it');
  const claims = decodeJwt(res.json().access_token);
  assert.equal(claims.sub, 'alice');
  assert.deepEqual(claims.act, { sub: 'svc', iss: ISSUER, sub_profile: 'service' });
});

test('may_act naming another actor or another issuer does not authorize delegation', async () => {
  const c = await setup();
  const actor = await c.mint({ sub: 'svc' });
  for (const mayAct of [{ sub: 'other' }, { sub: 'svc', iss: 'https://evil.example' }, 'svc', { iss: ISSUER }]) {
    const subj = await c.mint({ sub: 'alice', may_act: mayAct });
    const res = await c.exchange('a', { subject_token: subj, actor_token: actor, actor_token_type: AT });
    assert.equal(res.statusCode, 400, JSON.stringify(mayAct));
    assert.equal(res.json().error, 'invalid_request', JSON.stringify(mayAct));
  }
});

test('the subject client allowedActors registration authorizes delegation without may_act', async () => {
  const c = await setup();
  const a = (await c.store.getClient('a'))!;
  await c.store.saveClient({ ...a, allowedActors: ['a'] });
  const res = await c.exchange('a', { subject_token: await c.cc('a'), actor_token: await c.mint({ sub: 'agent-1' }), actor_token_type: AT, scope: 'read' });
  assert.equal(res.statusCode, 200, res.body);
  assert.deepEqual(decodeJwt(res.json().access_token).act, { sub: 'agent-1', iss: ISSUER, sub_profile: 'service' });
});

test('an existing act chain is nested under the new actor', async () => {
  const c = await setup();
  const inner = { sub: 'first', iss: ISSUER, sub_profile: 'ai_agent' };
  const subj = await c.mint({ sub: 'alice', act: inner, may_act: { sub: 'second' } });
  const res = await c.exchange('a', { subject_token: subj, actor_token: await c.mint({ sub: 'second' }), actor_token_type: AT });
  assert.equal(res.statusCode, 200, res.body);
  assert.deepEqual(decodeJwt(res.json().access_token).act, { sub: 'second', iss: ISSUER, sub_profile: 'service', act: inner });
});

test('without an actor_token the existing act chain is carried over unchanged', async () => {
  const c = await setup();
  const inner = { sub: 'first', iss: ISSUER };
  const res = await c.exchange('a', { subject_token: await c.mint({ act: inner }) });
  assert.equal(res.statusCode, 200, res.body);
  assert.deepEqual(decodeJwt(res.json().access_token).act, inner);
});

test('act chain depth above the maximum is invalid_request; default maximum is 4', async () => {
  const chain = (levels: number): Record<string, unknown> => {
    let act: Record<string, unknown> | undefined;
    for (let i = 0; i < levels; i++) act = { sub: `s${i}`, iss: ISSUER, ...(act ? { act } : {}) };
    return act!;
  };
  const run = async (max: number | undefined, existing: number) => {
    const c = await setup(max === undefined ? {} : { maxDelegationDepth: max });
    const subj = await c.mint({ sub: 'alice', act: chain(existing), may_act: { sub: 'svc' } });
    return c.exchange('a', { subject_token: subj, actor_token: await c.mint({ sub: 'svc' }), actor_token_type: AT });
  };
  assert.equal((await run(undefined, 3)).statusCode, 200); // 3 + new = 4 levels
  const over = await run(undefined, 4); // 5 levels
  assert.equal(over.statusCode, 400);
  assert.equal(over.json().error, 'invalid_request');
  assert.equal((await run(2, 1)).statusCode, 200);
  assert.equal((await run(2, 2)).statusCode, 400);
});

test('a malformed act claim on the subject is invalid_request and never recursed unboundedly', async () => {
  const c = await setup();
  let deep: Record<string, unknown> = { sub: 'x', iss: ISSUER };
  for (let i = 0; i < 500; i++) deep = { sub: 'x', iss: ISSUER, act: deep };
  for (const act of [{ sub: 'x' }, { iss: ISSUER }, 'str', [], { sub: 1, iss: ISSUER }, deep]) {
    const subj = await c.mint({ sub: 'alice', act, may_act: { sub: 'svc' } });
    const res = await c.exchange('a', { subject_token: subj, actor_token: await c.mint({ sub: 'svc' }), actor_token_type: AT });
    assert.equal(res.statusCode, 400);
    assert.equal(res.json().error, 'invalid_request');
  }
});

// ---- audience / resource ----

test('an audience-restricted subject can be narrowed to a subset; omitted target inherits it', async () => {
  const c = await setup();
  const subj = await c.mint({ aud: ['https://r1.example', 'https://r2.example'] });
  const narrowed = await c.exchange('a', { subject_token: subj, audience: 'https://r1.example' });
  assert.equal(narrowed.statusCode, 200, narrowed.body);
  assert.equal(decodeJwt(narrowed.json().access_token).aud, 'https://r1.example');
  const byResource = await c.exchange('a', { subject_token: subj, resource: 'https://r2.example' });
  assert.equal(decodeJwt(byResource.json().access_token).aud, 'https://r2.example');
  const inherited = await c.exchange('a', { subject_token: subj });
  assert.deepEqual(decodeJwt(inherited.json().access_token).aud, ['https://r1.example', 'https://r2.example']);
});

test('a target outside the subject audience, or any target for an unrestricted subject, is invalid_target', async () => {
  const c = await setup();
  const restricted = await c.mint({ aud: ['https://r1.example'] });
  const widen = await c.exchange('a', { subject_token: restricted, audience: 'https://r3.example' });
  assert.equal(widen.statusCode, 400);
  assert.equal(widen.json().error, 'invalid_target');
  const unrestricted = await c.exchange('a', { subject_token: await c.cc('a'), audience: 'https://unknown.example' });
  assert.equal(unrestricted.statusCode, 400);
  assert.equal(unrestricted.json().error, 'invalid_target');
  const notUri = await c.exchange('a', { subject_token: restricted, resource: 'not a uri' });
  assert.equal(notUri.json().error, 'invalid_target');
  const fragment = await c.exchange('a', { subject_token: restricted, resource: 'https://r1.example/#f' });
  assert.equal(fragment.json().error, 'invalid_target');
});

// ---- sender constraint ----

test('a DPoP-bound subject token is exchangeable only with a matching proof, and the result is DPoP-bound', async () => {
  const c = await setup();
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk: JWK = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  const proof = () => new SignJWT({ jti: randomUUID(), htm: 'POST', htu: `${ISSUER}/oauth/token`, iat: T0 })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk }).sign(privateKey);
  const bound = await c.mint({ cnf: { jkt } });

  const noProof = await c.exchange('a', { subject_token: bound });
  assert.equal(noProof.statusCode, 400);
  assert.equal(noProof.json().error, 'invalid_request');

  const other = await generateKeyPair('ES256', { extractable: true });
  const otherJwk = await exportJWK(other.publicKey);
  const wrongProof = await new SignJWT({ jti: randomUUID(), htm: 'POST', htu: `${ISSUER}/oauth/token`, iat: T0 })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: otherJwk }).sign(other.privateKey);
  const wrong = await c.exchange('a', { subject_token: bound }, { dpop: wrongProof });
  assert.equal(wrong.statusCode, 400);
  assert.equal(wrong.json().error, 'invalid_request');

  const ok = await c.exchange('a', { subject_token: bound }, { dpop: await proof() });
  assert.equal(ok.statusCode, 200, ok.body);
  assert.equal(ok.json().token_type, 'DPoP');
  assert.deepEqual(decodeJwt(ok.json().access_token).cnf, { jkt });
});

test('a proof presented at the endpoint binds an unbound subject exchange', async () => {
  const c = await setup();
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk: JWK = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  const proof = await new SignJWT({ jti: randomUUID(), htm: 'POST', htu: `${ISSUER}/oauth/token`, iat: T0 })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk }).sign(privateKey);
  const res = await c.exchange('a', { subject_token: await c.cc('a') }, { dpop: proof });
  assert.equal(res.statusCode, 200, res.body);
  assert.equal(res.json().token_type, 'DPoP');
  assert.deepEqual(decodeJwt(res.json().access_token).cnf, { jkt });
});

test('a DPoP-bound actor token requires a matching proof (missing, mismatched, matching)', async () => {
  const c = await setup();
  const mk = async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const jwk: JWK = await exportJWK(publicKey);
    const jkt = await calculateJwkThumbprint(jwk);
    const proof = () => new SignJWT({ jti: randomUUID(), htm: 'POST', htu: `${ISSUER}/oauth/token`, iat: T0 })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk }).sign(privateKey);
    return { jkt, proof };
  };
  const actorKey = await mk();
  const otherKey = await mk();
  const subj = await c.mint({ sub: 'alice', may_act: { sub: 'svc' } });
  const actor = await c.mint({ sub: 'svc', cnf: { jkt: actorKey.jkt } });
  const form = { subject_token: subj, actor_token: actor, actor_token_type: AT, scope: 'read' };

  const missing = await c.exchange('a', form);
  assert.equal(missing.statusCode, 400);
  assert.equal(missing.json().error, 'invalid_request');
  assert.match(missing.json().error_description, /actor_token/);

  const mismatched = await c.exchange('a', form, { dpop: await otherKey.proof() });
  assert.equal(mismatched.statusCode, 400);
  assert.equal(mismatched.json().error, 'invalid_request');
  assert.match(mismatched.json().error_description, /actor_token/);

  const ok = await c.exchange('a', form, { dpop: await actorKey.proof() });
  assert.equal(ok.statusCode, 200, ok.body);
  assert.notEqual(decodeJwt(ok.json().access_token).act, undefined);
});

// ---- discovery ----

test('discovery advertises the token-exchange grant', async () => {
  const c = await setup();
  const res = await c.server.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' });
  assert.equal(res.statusCode, 200);
  assert.ok(res.json().grant_types_supported.includes(GT));
});
