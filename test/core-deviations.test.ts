// Regression tests for the five core conformance deviations that were removed
// from conformance.yaml: unknown client (RFC 6749 4.1.1), loopback any-port
// (RFC 8252 7.3 / RFC 6749 3.1.2) and a missing PKCE verifier (RFC 7636 4.3).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { FastifyInstance } from 'fastify';
import { exportPKCS8, generateKeyPair } from 'jose';
import { redirectUriMatches } from '../src/redirect-uri.js';
import type { ClientRecord } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';

const ISSUER = 'http://localhost:8080';
const VERIFIER = 'v'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');

async function setup() {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base: Omit<ClientRecord, 'clientId' | 'redirectUris'> = {
    clientSecretHash: null, grantTypes: ['authorization_code'], scopes: ['read'], enabled: true,
  };
  await store.saveClient({ ...base, clientId: 'v4', redirectUris: ['http://127.0.0.1/cb'] });
  await store.saveClient({ ...base, clientId: 'v6', redirectUris: ['http://[::1]/cb'] });
  await store.saveClient({ ...base, clientId: 'lh', redirectUris: ['http://localhost/cb'] });
  await store.saveClient({ ...base, clientId: 'web', redirectUris: ['https://app.example/cb'] });
  await store.saveClient({ ...base, clientId: 'off', redirectUris: ['https://app.example/cb'], enabled: false });
  const server = buildServer({
    store, signer, clock: { now: () => 1_000_000 }, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'user-1',
  });
  return { server, store };
}

function authz(server: FastifyInstance, clientId: string, redirectUri: string) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
    code_challenge: CHALLENGE, code_challenge_method: 'S256', state: 's1',
  });
  return server.inject({ method: 'GET', url: `/oauth/authorize?${q.toString()}` });
}

function token(server: FastifyInstance, form: Record<string, string>) {
  return server.inject({
    method: 'POST', url: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(form).toString(),
  });
}

test('RFC 6749 4.1.1: unknown or disabled client_id is invalid_client (401) and never redirected', async () => {
  const s = await setup();
  for (const id of ['no-such-client', 'off']) {
    const res = await authz(s.server, id, 'https://app.example/cb');
    assert.equal(res.statusCode, 401, id);
    assert.equal(res.json().error, 'invalid_client', id);
    assert.equal(res.headers.location, undefined, id);
  }
  // A known client with an unregistered redirect_uri stays a non-redirecting invalid_request.
  const bad = await authz(s.server, 'web', 'https://evil.example/cb');
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.json().error, 'invalid_request');
  assert.equal(bad.headers.location, undefined);
  await s.server.close();
  await s.store.close();
});

test('RFC 8252 7.3: IPv4 and IPv6 loopback redirect URIs accept any port and redirect back to it', async () => {
  const s = await setup();
  for (const [client, uri] of [['v4', 'http://127.0.0.1:9999/cb'], ['v6', 'http://[::1]:9999/cb'], ['v4', 'http://127.0.0.1:7777/cb']] as const) {
    const res = await authz(s.server, client, uri);
    assert.equal(res.statusCode, 302, uri);
    const loc = new URL(res.headers.location as string);
    assert.equal(loc.origin + loc.pathname, uri);
    assert.ok(loc.searchParams.get('code'));
  }
  await s.server.close();
  await s.store.close();
});

test('RFC 8252 7.3/8.3: the port wildcard is limited to the same loopback literal, scheme and path', async () => {
  const s = await setup();
  const rejected: Array<[string, string]> = [
    ['v4', 'http://127.0.0.1:9999/other'], // different path
    ['v4', 'http://127.0.0.1:9999/cb?x=1'], // extra query is not an exact path match
    ['v4', 'https://127.0.0.1:9999/cb'], // different scheme
    ['v4', 'http://[::1]:9999/cb'], // IPv4 registration does not cover IPv6
    ['v6', 'http://127.0.0.1:9999/cb'], // and vice versa
    ['v4', 'http://127.0.0.2:9999/cb'], // not the loopback literal
    ['lh', 'http://localhost:9999/cb'], // localhost hostname gets no wildcard
    ['web', 'https://app.example:8443/cb'], // non-loopback gets no wildcard
    ['v4', 'http://user@127.0.0.1:9999/cb'], // userinfo
    ['v4', 'http://127.0.0.1:99999/cb'], // invalid port
  ];
  for (const [client, uri] of rejected) {
    const res = await authz(s.server, client, uri);
    assert.equal(res.statusCode, 400, `${client} ${uri}`);
    assert.equal(res.headers.location, undefined, `${client} ${uri}`);
  }
  // Exact match on localhost still works.
  assert.equal((await authz(s.server, 'lh', 'http://localhost/cb')).statusCode, 302);
  await s.server.close();
  await s.store.close();
});

test('redirectUriMatches: exact, loopback port wildcard and a registered explicit port', () => {
  assert.equal(redirectUriMatches(['https://a.example/cb'], 'https://a.example/cb'), true);
  assert.equal(redirectUriMatches(['https://a.example/cb'], 'https://a.example/cb/'), false);
  assert.equal(redirectUriMatches(['http://127.0.0.1:3000/cb'], 'http://127.0.0.1:54321/cb'), true);
  assert.equal(redirectUriMatches(['http://localhost:3000/cb'], 'http://localhost:3000/cb'), true);
  assert.equal(redirectUriMatches(['http://localhost:3000/cb'], 'http://localhost:4000/cb'), false);
  assert.equal(redirectUriMatches([], 'http://127.0.0.1:1/cb'), false);
  assert.equal(redirectUriMatches(['not a url'], 'http://127.0.0.1:1/cb'), false);
});

test('RFC 7636 4.3: a code exchange omitting code_verifier is invalid_grant and burns the code', async () => {
  const s = await setup();
  const res = await authz(s.server, 'web', 'https://app.example/cb');
  const code = new URL(res.headers.location as string).searchParams.get('code') as string;
  const form = { grant_type: 'authorization_code', code, client_id: 'web', redirect_uri: 'https://app.example/cb' };
  const missing = await token(s.server, form);
  assert.equal(missing.statusCode, 400);
  assert.equal(missing.json().error, 'invalid_grant');
  // The code was consumed: even a correct verifier cannot redeem it now.
  const retry = await token(s.server, { ...form, code_verifier: VERIFIER });
  assert.equal(retry.json().error, 'invalid_grant');
  await s.server.close();
  await s.store.close();
});
