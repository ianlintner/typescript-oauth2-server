import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPair, exportPKCS8, SignJWT } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { Clock } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';
const SECRET = 'confidential-client-secret-value';
const PLR = 'https://client.example/logged-out';

async function setup() {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(pair.privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const secretHash = await hashClientSecret(SECRET);
  await store.saveClient({
    clientId: 'conf', clientSecretHash: secretHash, redirectUris: [CB],
    grantTypes: ['authorization_code'], scopes: ['openid'], enabled: true,
    postLogoutRedirectUris: [PLR],
  });
  await store.saveClient({
    clientId: 'other', clientSecretHash: secretHash, redirectUris: [CB],
    grantTypes: ['authorization_code'], scopes: ['openid'], enabled: true,
    postLogoutRedirectUris: [PLR],
  });
  await store.saveClient({
    clientId: 'fallback', clientSecretHash: secretHash,
    redirectUris: [CB, 'https://client.example/fallback-logout'],
    grantTypes: ['authorization_code'], scopes: ['openid'], enabled: true,
    // No postLogoutRedirectUris: a redirect_uris fallback must never be used.
  });
  const clock: Clock = { now: () => 1_000_000 };
  let ended = 0;
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'alice',
    endSession: () => { ended += 1; },
  });
  return { server, signer, pair, ended: () => ended };
}

type Sut = Awaited<ReturnType<typeof setup>>;

function hint(s: Sut, aud: string | string[], extra: Record<string, unknown> = {}) {
  return s.signer.sign({ iss: ISSUER, sub: 'alice', aud, iat: 1_000_000, exp: 2_000_000, ...extra });
}

function logout(s: Sut, params: Record<string, string>) {
  return s.server.inject({ method: 'GET', url: `/oauth/logout?${new URLSearchParams(params)}` });
}

function errorOf(res: { json(): unknown }) {
  return (res.json() as { error?: string }).error;
}

// -- Discovery --

test('discovery advertises end_session_endpoint on both well-known documents', async () => {
  const s = await setup();
  for (const path of ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server']) {
    const res = await s.server.inject({ method: 'GET', url: path });
    assert.equal(res.statusCode, 200);
    assert.equal(res.json().end_session_endpoint, `${ISSUER}/oauth/logout`, path);
  }
});

// -- Positive redirect --

test('a registered post_logout_redirect_uri gets a 302 with state appended via the URL query API', async () => {
  const s = await setup();
  const idt = await hint(s, 'conf');
  const state = 's=1&state=evil';
  const res = await logout(s, { id_token_hint: idt, post_logout_redirect_uri: PLR, state });
  assert.equal(res.statusCode, 302);
  const location = res.headers.location as string;
  assert.ok(location.startsWith(`${PLR}?`), location);
  assert.equal(new URL(location).searchParams.get('state'), state);
  // A string-concatenation implementation would append a second `state` parameter.
  assert.deepEqual(new URL(location).searchParams.getAll('state'), [state]);
  assert.match(location, /%26state%3Devil/);
  assert.equal(s.ended(), 1);
});

test('client_id matching an audience restricts the redirect to that client registration', async () => {
  const s = await setup();
  const idt = await hint(s, ['conf', 'other']);
  const res = await logout(s, { id_token_hint: idt, client_id: 'other', post_logout_redirect_uri: PLR, state: 'ok' });
  assert.equal(res.statusCode, 302);
  assert.equal(new URL(res.headers.location as string).searchParams.get('state'), 'ok');
  assert.equal(s.ended(), 1);
});

// -- Negative redirect cases --

test('an unregistered post_logout_redirect_uri is an invalid_request error, never a redirect', async () => {
  const s = await setup();
  const idt = await hint(s, 'conf');
  const res = await logout(s, { id_token_hint: idt, post_logout_redirect_uri: 'https://client.example/nope', state: 's' });
  assert.equal(res.statusCode, 400);
  assert.equal(errorOf(res), 'invalid_request');
  assert.equal(res.headers.location, undefined);
  assert.equal(s.ended(), 0);
});

test('a registered URI with an extra path is not an exact match', async () => {
  const s = await setup();
  const idt = await hint(s, 'conf');
  const res = await logout(s, { id_token_hint: idt, post_logout_redirect_uri: `${PLR}/extra`, state: 's' });
  assert.equal(res.statusCode, 400);
  assert.equal(errorOf(res), 'invalid_request');
  assert.equal(res.headers.location, undefined);
  assert.equal(s.ended(), 0);
});

test('a post_logout_redirect_uri with a fragment is rejected', async () => {
  const s = await setup();
  const idt = await hint(s, 'conf');
  const res = await logout(s, { id_token_hint: idt, post_logout_redirect_uri: `${PLR}#frag` });
  assert.equal(res.statusCode, 400);
  assert.equal(errorOf(res), 'invalid_request');
  assert.equal(s.ended(), 0);
});

test('a non-http(s) post_logout_redirect_uri is rejected', async () => {
  const s = await setup();
  const idt = await hint(s, 'conf');
  const res = await logout(s, { id_token_hint: idt, post_logout_redirect_uri: 'javascript:alert(1)' });
  assert.equal(res.statusCode, 400);
  assert.equal(errorOf(res), 'invalid_request');
  assert.equal(s.ended(), 0);
});

test('redirect_uris are never used as a post-logout redirect fallback', async () => {
  const s = await setup();
  const idt = await hint(s, 'fallback');
  const res = await logout(s, { id_token_hint: idt, post_logout_redirect_uri: 'https://client.example/fallback-logout' });
  assert.equal(res.statusCode, 400);
  assert.equal(errorOf(res), 'invalid_request');
  assert.equal(s.ended(), 0);
});

test('client_id outside the hint audiences is rejected even if it registered the URI', async () => {
  const s = await setup();
  const idt = await hint(s, 'conf');
  const res = await logout(s, { id_token_hint: idt, client_id: 'other', post_logout_redirect_uri: PLR });
  assert.equal(res.statusCode, 400);
  assert.equal(errorOf(res), 'invalid_request');
  assert.equal(res.headers.location, undefined);
  assert.equal(s.ended(), 0);
});

test('an invalid signature never redirects, even with a registered URI', async () => {
  const s = await setup();
  const other = await generateKeyPair('ES256');
  const forged = await new SignJWT({ iss: ISSUER, aud: 'conf', sub: 'alice' })
    .setProtectedHeader({ alg: 'ES256' }).sign(other.privateKey);
  const res = await logout(s, { id_token_hint: forged, post_logout_redirect_uri: PLR, state: 's' });
  assert.equal(res.statusCode, 400);
  assert.equal(errorOf(res), 'invalid_request');
  assert.equal(res.headers.location, undefined);
  assert.equal(s.ended(), 0);
});

test('a duplicate post_logout_redirect_uri parameter is rejected', async () => {
  const s = await setup();
  const idt = await hint(s, 'conf');
  const res = await s.server.inject({
    method: 'GET',
    url: `/oauth/logout?id_token_hint=${idt}&post_logout_redirect_uri=${encodeURIComponent(PLR)}&post_logout_redirect_uri=${encodeURIComponent(PLR)}`,
  });
  assert.equal(res.statusCode, 400);
  assert.equal(errorOf(res), 'invalid_request');
  assert.equal(s.ended(), 0);
});

test('without a redirect URI logout still ends the session with 200 text/plain', async () => {
  const s = await setup();
  const idt = await hint(s, 'conf');
  const res = await logout(s, { id_token_hint: idt, state: 'unused' });
  assert.equal(res.statusCode, 200);
  assert.match(res.headers['content-type'] as string, /text\/plain/);
  assert.equal(res.body, 'logged out');
  assert.equal(s.ended(), 1);
});
