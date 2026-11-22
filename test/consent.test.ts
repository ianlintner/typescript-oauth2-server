import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { createConsentDecider, type ConsentRequest } from '../src/oauth.js';
import type { ClientRecord, Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { buildServer } from '../src/server.js';
import { SqliteStore } from '../src/sqlite-store.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';
const VERIFIER = 'v'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');

async function setup(consent?: (subject: string, clientId: string, request: ConsentRequest) => boolean) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const client: Omit<ClientRecord, 'clientId' | 'clientSecretHash'> = {
    redirectUris: [CB], grantTypes: ['authorization_code'], scopes: ['read', 'write'], enabled: true,
  };
  await store.saveClient({ ...client, clientId: 'pub', clientSecretHash: null });
  const clock: Clock = { now: () => 1_000_000 };
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'user-1', consent,
  });
  return { server, store };
}

function authorization(params: Record<string, string> = {}) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: 'pub', redirect_uri: CB,
    code_challenge: CHALLENGE, code_challenge_method: 'S256', state: 'st-1', ...params,
  });
  return `/oauth/authorize?${q.toString()}`;
}

async function done(s: Awaited<ReturnType<typeof setup>>) {
  await s.server.close();
  await s.store.close();
}

type AuthzResponse = Awaited<ReturnType<Awaited<ReturnType<typeof setup>>['server']['inject']>>;
function result(res: AuthzResponse) {
  const loc = new URL(res.headers.location as string);
  return { error: loc.searchParams.get('error'), code: loc.searchParams.get('code'), state: loc.searchParams.get('state'), iss: loc.searchParams.get('iss') };
}

test('authorize fails closed when no consent hook is supplied', async () => {
  const s = await setup();
  const res = await s.server.inject({ method: 'GET', url: authorization({ scope: 'read' }) });
  assert.equal(res.statusCode, 302);
  const out = result(res);
  assert.equal(out.error, 'access_denied');
  assert.equal(out.code, null);
  assert.equal(out.state, 'st-1');
  assert.equal(out.iss, ISSUER);
  await done(s);
});

test('consent hook receives the validated scope set and parsed prompt', async () => {
  const seen: ConsentRequest[] = [];
  const s = await setup((_subject, _clientId, request) => { seen.push(request); return true; });
  const res = await s.server.inject({ method: 'GET', url: authorization({ scope: 'read write', prompt: 'consent' }) });
  assert.equal(res.statusCode, 302);
  assert.ok(result(res).code);
  assert.equal(seen.length, 1);
  const request = seen[0];
  assert.ok(request);
  assert.deepEqual(request.scope, ['read', 'write']);
  assert.deepEqual(request.prompt, ['consent']);
  assert.equal(request.fresh, true);
  await done(s);
});

test('a wider scope request is not covered by a narrower consent; prompt=consent forces a fresh decision', async () => {
  const decider = createConsentDecider();
  decider.approve('user-1', 'pub', ['read']);
  const s = await setup(decider.consent);
  const narrow = await s.server.inject({ method: 'GET', url: authorization({ scope: 'read' }) });
  assert.ok(result(narrow).code, 'approved scope is authorized');

  const wider = await s.server.inject({ method: 'GET', url: authorization({ scope: 'read write' }) });
  assert.equal(result(wider).error, 'access_denied');
  assert.equal(result(wider).code, null);

  const reprompt = await s.server.inject({ method: 'GET', url: authorization({ scope: 'read', prompt: 'consent' }) });
  assert.equal(result(reprompt).error, 'access_denied');
  assert.deepEqual(decider.decisionsFor('user-1', 'pub'), ['read'], 'cached decisions survive a denied re-prompt');

  decider.approve('user-1', 'pub', ['read', 'write']);
  const fresh = await s.server.inject({ method: 'GET', url: authorization({ scope: 'read write', prompt: 'consent' }) });
  assert.equal(result(fresh).error, 'access_denied', 'prompt=consent never reuses a cached decision');

  await done(s);
});

test('prompt=none without a decision returns consent_required, never a login redirect', async () => {
  const s = await setup(() => false);
  const res = await s.server.inject({ method: 'GET', url: authorization({ scope: 'read', prompt: 'none' }) });
  assert.equal(res.statusCode, 302);
  const out = result(res);
  assert.equal(out.error, 'consent_required');
  assert.equal(out.code, null);
  assert.equal(out.state, 'st-1');
  await done(s);
});

test('a denied request does not consume the request_uri', async () => {
  const decider = createConsentDecider();
  decider.approve('user-1', 'pub', ['read']);
  const s = await setup(decider.consent);
  const pushed = await s.server.inject({
    method: 'POST', url: '/oauth/par',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({
      client_id: 'pub', response_type: 'code', redirect_uri: CB,
      code_challenge: CHALLENGE, code_challenge_method: 'S256', scope: 'read write', state: 'st-1',
    }).toString(),
  });
  assert.equal(pushed.statusCode, 201);
  const requestUri = pushed.json().request_uri as string;
  const denied = await s.server.inject({ method: 'GET', url: authorization({ request_uri: requestUri }) });
  assert.equal(result(denied).error, 'access_denied');

  decider.approve('user-1', 'pub', ['read', 'write']);
  const allowed = await s.server.inject({ method: 'GET', url: authorization({ request_uri: requestUri }) });
  assert.ok(result(allowed).code, 'request_uri remains usable after a consent denial');
  await done(s);
});
