import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { generateKeyPair, exportPKCS8 } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import type { ClientRecord } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';
import type { RegistrationPolicy } from '../src/device-grant.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';
const DEVICE_SECRET = 'device-client-secret';
const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

async function setup(opts: { dynamicRegistration?: boolean; registrationPolicy?: RegistrationPolicy } = {}) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base: Omit<ClientRecord, 'clientId' | 'clientSecretHash'> = {
    redirectUris: [CB], grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'], scopes: ['openid', 'read', 'write'], enabled: true,
  };
  await store.saveClient({ ...base, clientId: 'pub', clientSecretHash: null });
  await store.saveClient({ ...base, clientId: 'conf', clientSecretHash: await hashClientSecret('conf-secret') });
  await store.saveClient({
    ...base, clientId: 'device', clientSecretHash: await hashClientSecret(DEVICE_SECRET),
    grantTypes: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
  });
  let now = 1_000_000;
  const clock = { now: () => now };
  const server = buildServer({
    store, signer, clock, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'user-1',
    dynamicRegistration: opts.dynamicRegistration ?? true,
    registrationPolicy: opts.registrationPolicy,
  });
  return { server, store, signer, clock, advance: (s: number) => { now += s; } };
}

function form(payload: URLSearchParams, headers: Record<string, string> = {}) {
  return { 'content-type': 'application/x-www-form-urlencoded', ...headers };
}

// -- RFC 8628 device authorization grant --

test('device_authorization issues device_code and user_code with verification URI', async () => {
  const s = await setup();
  const res = await s.server.inject({
    method: 'POST', url: '/oauth/device_authorization', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ client_id: 'device', client_secret: DEVICE_SECRET, scope: 'read' }).toString(),
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.ok(body.device_code);
  assert.match(body.user_code, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  assert.equal(body.verification_uri, `${ISSUER}/oauth/device/verify`);
  assert.ok(body.verification_uri_complete.startsWith(`${ISSUER}/oauth/device/verify?user_code=`));
  assert.equal(body.expires_in, 600);
  assert.equal(body.interval, 5);

  // Only hashes are stored: lookup by hash works, lookup by the plaintext code does not.
  const stored = await s.store.getDeviceCode(sha256(body.device_code));
  assert.equal(stored?.clientId, 'device');
  assert.notEqual(stored?.deviceCodeHash, body.device_code);
  assert.equal(await s.store.getDeviceCode(body.device_code), null);
  await s.server.close();
});

test('device token grant returns authorization_pending while unapproved', async () => {
  const s = await setup();
  const dev = await s.server.inject({
    method: 'POST', url: '/oauth/device_authorization', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ client_id: 'device', client_secret: DEVICE_SECRET }).toString(),
  });
  const { device_code: deviceCode } = dev.json();
  const res = await s.server.inject({
    method: 'POST', url: '/oauth/token', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: 'device', client_secret: DEVICE_SECRET, device_code: deviceCode }).toString(),
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'authorization_pending');
  await s.server.close();
});

test('device token grant enforces slow_down when polling faster than interval', async () => {
  const s = await setup();
  const dev = await s.server.inject({
    method: 'POST', url: '/oauth/device_authorization', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ client_id: 'device', client_secret: DEVICE_SECRET }).toString(),
  });
  const { device_code: deviceCode } = dev.json();
  const poll = () => s.server.inject({
    method: 'POST', url: '/oauth/token', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: 'device', client_secret: DEVICE_SECRET, device_code: deviceCode }).toString(),
  });
  // First poll within interval -> authorization_pending (interval 5s not elapsed).
  assert.equal((await poll()).json().error, 'authorization_pending');
  // Immediate second poll -> slow_down.
  s.advance(1);
  const res = await poll();
  assert.equal(res.json().error, 'slow_down');
  await s.server.close();
});

test('device token grant completes once approved (one-time)', async () => {
  const s = await setup();
  const dev = await s.server.inject({
    method: 'POST', url: '/oauth/device_authorization', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ client_id: 'device', client_secret: DEVICE_SECRET, scope: 'read' }).toString(),
  });
  const { device_code: deviceCode, user_code: userCode, interval } = dev.json();

  // Approve via the verification endpoint.
  const approve = await s.server.inject({
    method: 'POST', url: '/oauth/device/verify', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ user_code: userCode.toLowerCase().replace('-', ''), action: 'approve' }).toString(),
  });
  assert.equal(approve.statusCode, 200);

  s.advance(interval + 1);
  const res = await s.server.inject({
    method: 'POST', url: '/oauth/token', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: 'device', client_secret: DEVICE_SECRET, device_code: deviceCode }).toString(),
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().token_type, 'Bearer');
  assert.equal(res.json().scope, 'read');
  assert.ok(res.json().access_token);

  // Reuse must fail as already used.
  const again = await s.server.inject({
    method: 'POST', url: '/oauth/token', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: 'device', client_secret: DEVICE_SECRET, device_code: deviceCode }).toString(),
  });
  assert.equal(again.json().error, 'invalid_grant');
  await s.server.close();
});

test('device token grant reports access_denied when the device is denied', async () => {
  const s = await setup();
  const dev = await s.server.inject({
    method: 'POST', url: '/oauth/device_authorization', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ client_id: 'device', client_secret: DEVICE_SECRET }).toString(),
  });
  const { device_code: deviceCode, user_code: userCode } = dev.json();
  await s.server.inject({
    method: 'POST', url: '/oauth/device/verify', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ user_code: userCode, action: 'deny' }).toString(),
  });
  const res = await s.server.inject({
    method: 'POST', url: '/oauth/token', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: 'device', client_secret: DEVICE_SECRET, device_code: deviceCode }).toString(),
  });
  assert.equal(res.json().error, 'access_denied');
  await s.server.close();
});

// -- RFC 9126 Pushed Authorization Request --

test('PAR returns 201 with request_uri and expires_in', async () => {
  const s = await setup();
  const res = await s.server.inject({
    method: 'POST', url: '/oauth/par', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({
      client_id: 'conf', client_secret: 'conf-secret', redirect_uri: CB, response_type: 'code',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', state: 'st1',
    }).toString(),
  });
  assert.equal(res.statusCode, 201);
  const body = res.json();
  assert.match(body.request_uri, /^urn:ietf:params:oauth:request_uri:/);
  assert.equal(body.expires_in, 60);
  await s.server.close();
});

test('PAR request_uri is single-use and bound to the pushing client', async () => {
  const s = await setup();
  const push = await s.server.inject({
    method: 'POST', url: '/oauth/par', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({
      client_id: 'conf', client_secret: 'conf-secret', redirect_uri: CB, response_type: 'code',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256',
    }).toString(),
  });
  const { request_uri: requestUri } = push.json();
  const q = (cid: string) => `/oauth/authorize?request_uri=${encodeURIComponent(requestUri)}&client_id=${cid}`;

  // Another client cannot use it, and the failed attempt must not burn it.
  const other = await s.server.inject({ method: 'GET', url: q('pub') });
  assert.equal(other.statusCode, 400);
  assert.equal(other.json().error, 'invalid_request');

  // The owner can use it exactly once.
  const first = await s.server.inject({ method: 'GET', url: q('conf') });
  assert.equal(first.statusCode, 302);
  assert.ok(new URL(first.headers.location as string).searchParams.get('code'));
  const replay = await s.server.inject({ method: 'GET', url: q('conf') });
  assert.equal(replay.statusCode, 400);
  assert.equal(replay.json().error, 'invalid_request_uri');
  await s.server.close();
});

test('PAR request_uri expires after 60 seconds', async () => {
  const s = await setup();
  const push = await s.server.inject({
    method: 'POST', url: '/oauth/par', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({
      client_id: 'conf', client_secret: 'conf-secret', redirect_uri: CB, response_type: 'code',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256',
    }).toString(),
  });
  s.advance(61);
  const res = await s.server.inject({
    method: 'GET', url: `/oauth/authorize?request_uri=${encodeURIComponent(push.json().request_uri)}&client_id=conf`,
  });
  assert.equal(res.json().error, 'invalid_request_uri');
  await s.server.close();
});

test('PAR requires client authentication', async () => {
  const s = await setup();
  const res = await s.server.inject({
    method: 'POST', url: '/oauth/par', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ client_id: 'conf', client_secret: 'wrong', redirect_uri: CB }).toString(),
  });
  assert.equal(res.statusCode, 401);
  await s.server.close();
});

test('PAR rejects an unknown or expired request_uri', async () => {
  const s = await setup();
  const auth = await s.server.inject({
    method: 'GET', url: `/oauth/authorize?request_uri=${encodeURIComponent('urn:ietf:params:oauth:request_uri:bogus')}&client_id=conf&redirect_uri=${encodeURIComponent(CB)}`,
  });
  assert.equal(auth.statusCode, 400);
  assert.equal(auth.json().error, 'invalid_request_uri');
  await s.server.close();
});

// -- RFC 7591 / 7592 dynamic client registration --

test('dynamic registration creates a client with registration access token', async () => {
  const s = await setup({ dynamicRegistration: true });
  const res = await s.server.inject({
    method: 'POST', url: '/connect/register',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ redirect_uris: ['https://new.example/cb'], token_endpoint_auth_method: 'client_secret_basic' }),
  });
  assert.equal(res.statusCode, 201);
  const body = res.json();
  assert.ok(body.client_id);
  assert.ok(body.client_secret);
  assert.ok(body.registration_access_token);
  assert.match(body.registration_client_uri, /\/connect\/register\//);
  assert.equal(body.client_secret_expires_at, 0);
  assert.ok(body.client_id_issued_at);

  // The stored client is usable and carries registration metadata (token hashed).
  const stored = await s.store.getClient(body.client_id);
  assert.ok(stored);
  assert.ok(stored.registration);
  assert.notEqual(stored.registration.tokenHash, body.registration_access_token); // hashed only
  assert.deepEqual((stored.registration.metadata as { redirect_uris: string[] }).redirect_uris, ['https://new.example/cb']);
  await s.server.close();
});

test('dynamic registration is disabled by default', async () => {
  const s = await setup({ dynamicRegistration: false });
  const res = await s.server.inject({
    method: 'POST', url: '/connect/register',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ redirect_uris: ['https://new.example/cb'] }),
  });
  assert.equal(res.statusCode, 403);
  assert.equal(res.json().error, 'access_denied');
  await s.server.close();
});

test('dynamic registration rejects privileged scopes', async () => {
  const s = await setup({ dynamicRegistration: true });
  const res = await s.server.inject({
    method: 'POST', url: '/connect/register',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ redirect_uris: ['https://new.example/cb'], scope: 'openid admin' }),
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_client_metadata');
  await s.server.close();
});

test('dynamic registration accepts the jwt-bearer grant type when the policy allows it', async () => {
  const GT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
  const s = await setup({ dynamicRegistration: true, registrationPolicy: { allowedGrantTypes: [GT] } });
  const res = await s.server.inject({
    method: 'POST', url: '/connect/register',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ redirect_uris: ['https://new.example/cb'], token_endpoint_auth_method: 'client_secret_basic', grant_types: [GT] }),
  });
  assert.equal(res.statusCode, 201, res.body);
  assert.deepEqual(res.json().grant_types, [GT]);
  const stored = await s.store.getClient(res.json().client_id);
  assert.ok(stored);
  assert.deepEqual(stored.grantTypes, [GT]);
  await s.server.close();
});

test('registration access token reads, updates and deletes the client', async () => {
  const s = await setup({ dynamicRegistration: true });
  const reg = await s.server.inject({
    method: 'POST', url: '/connect/register',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ redirect_uris: ['https://new.example/cb'], client_name: 'My App' }),
  });
  const { client_id: cid, registration_access_token: rat, registration_client_uri: uri } = reg.json();

  // READ
  const read = await s.server.inject({ method: 'GET', url: uri, headers: { authorization: `Bearer ${rat}` } });
  assert.equal(read.statusCode, 200);
  assert.equal(read.json().client_name, 'My App');

  // UPDATE
  const upd = await s.server.inject({
    method: 'PUT', url: uri, headers: { 'content-type': 'application/json', authorization: `Bearer ${rat}` },
    payload: JSON.stringify({ redirect_uris: ['https://new.example/cb2'], client_name: 'Renamed' }),
  });
  assert.equal(upd.statusCode, 200);
  assert.equal(upd.json().client_name, 'Renamed');

  // DELETE
  const del = await s.server.inject({ method: 'DELETE', url: uri, headers: { authorization: `Bearer ${rat}` } });
  assert.equal(del.statusCode, 204);
  assert.equal(await s.store.getClient(cid), null);
  await s.server.close();
});

test('registration access token rejects a wrong token', async () => {
  const s = await setup({ dynamicRegistration: true });
  const reg = await s.server.inject({
    method: 'POST', url: '/connect/register',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ redirect_uris: ['https://new.example/cb'] }),
  });
  const { registration_client_uri: uri } = reg.json();
  const res = await s.server.inject({ method: 'GET', url: uri, headers: { authorization: 'Bearer wrong-token' } });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
  await s.server.close();
});

// -- review fixes: public registration, PAR push-time validation, user-code throttling --

test('dynamic registration with auth method none yields a public client without a secret', async () => {
  const s = await setup();
  const res = await s.server.inject({
    method: 'POST', url: '/connect/register', headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ redirect_uris: [CB], token_endpoint_auth_method: 'none' }),
  });
  assert.equal(res.statusCode, 201);
  const body = res.json();
  assert.equal(body.client_secret, undefined);
  assert.equal(body.client_secret_expires_at, undefined);
  const stored = await s.store.getClient(body.client_id);
  assert.equal(stored?.clientSecretHash, null);
  // A public client authenticates with client_id only (PAR proves it passes client auth).
  const par = await s.server.inject({
    method: 'POST', url: '/oauth/par', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ client_id: body.client_id, response_type: 'code', redirect_uri: CB }).toString(),
  });
  assert.equal(par.statusCode, 201);
  await s.server.close();
});

test('PAR rejects unregistered redirect_uri and unsupported response_type at push time', async () => {
  const s = await setup();
  const push = (extra: Record<string, string>) => s.server.inject({
    method: 'POST', url: '/oauth/par', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ client_id: 'conf', client_secret: 'conf-secret', ...extra }).toString(),
  });
  const badUri = await push({ response_type: 'code', redirect_uri: 'https://evil.example/cb' });
  assert.equal(badUri.statusCode, 400);
  assert.equal(badUri.json().error, 'invalid_request');
  const badType = await push({ response_type: 'token', redirect_uri: CB });
  assert.equal(badType.statusCode, 400);
  assert.equal(badType.json().error, 'unsupported_response_type');
  const ok = await push({ response_type: 'code', redirect_uri: CB });
  assert.equal(ok.statusCode, 201);
  await s.server.close();
});

test('device verify throttles repeated wrong user codes (RFC 8628 §5.1)', async () => {
  const s = await setup();
  const guess = () => s.server.inject({
    method: 'POST', url: '/oauth/device/verify', headers: form(new URLSearchParams()),
    payload: new URLSearchParams({ user_code: 'BBBB-BBBB', action: 'approve' }).toString(),
  });
  for (let i = 0; i < 5; i += 1) assert.equal((await guess()).statusCode, 400);
  assert.equal((await guess()).statusCode, 429);
  s.advance(61);
  assert.equal((await guess()).statusCode, 400);
  await s.server.close();
});

// -- registration policy: allow-lists and initial access token --

const regPost = (s: Awaited<ReturnType<typeof setup>>, body: unknown, headers: Record<string, string> = {}) => s.server.inject({
  method: 'POST', url: '/connect/register', headers: { 'content-type': 'application/json', ...headers }, payload: JSON.stringify(body),
});

test('registration refuses non-allow-listed grant types by default', async () => {
  const s = await setup({ dynamicRegistration: true });
  for (const g of ['urn:ietf:params:oauth:grant-type:jwt-bearer', 'client_credentials']) {
    const res = await regPost(s, { redirect_uris: [CB], grant_types: [g] });
    assert.equal(res.statusCode, 400, g);
    assert.equal(res.json().error, 'invalid_client_metadata');
  }
  const ok = await regPost(s, { redirect_uris: [CB], grant_types: ['authorization_code'] });
  assert.equal(ok.statusCode, 201);
  await s.server.close();
});

test('registration refuses scopes outside the allow-list', async () => {
  const s = await setup({ dynamicRegistration: true });
  for (const scope of ['orders:manage', 'openid admin:read', 'superuser']) {
    const res = await regPost(s, { redirect_uris: [CB], scope });
    assert.equal(res.statusCode, 400, scope);
    assert.equal(res.json().error, 'invalid_client_metadata');
  }
  const ok = await regPost(s, { redirect_uris: [CB], scope: 'openid profile' });
  assert.equal(ok.statusCode, 201);
  assert.deepEqual((await s.store.getClient(ok.json().client_id))?.scopes, ['openid', 'profile']);
  await s.server.close();
});

test('registration scope and grant allow-lists are operator-configurable', async () => {
  const s = await setup({ registrationPolicy: { allowedScopes: ['orders:manage'], allowedGrantTypes: ['client_credentials'] } });
  const ok = await regPost(s, { redirect_uris: [CB], scope: 'orders:manage', grant_types: ['client_credentials'] });
  assert.equal(ok.statusCode, 201);
  assert.equal((await regPost(s, { redirect_uris: [CB], scope: 'openid' })).statusCode, 400);
  await s.server.close();
});

test('registration refuses userinfo in a redirect URI', async () => {
  const s = await setup({ dynamicRegistration: true });
  const bad = await regPost(s, { redirect_uris: ['https://user:pass@app.example/cb'] });
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.json().error, 'invalid_redirect_uri');
  assert.equal((await regPost(s, { redirect_uris: ['https://user@app.example/cb'] })).statusCode, 400);
  assert.equal((await regPost(s, { redirect_uris: ['https://app.example/cb'] })).statusCode, 201);
  await s.server.close();
});

test('registration redirect schemes are an allow-list; http is limited to loopback IP literals', async () => {
  const s = await setup({ dynamicRegistration: true });
  for (const u of ['http://localhost:8080/cb', 'http://app.example/cb', 'com.example.app:/cb', 'javascript:alert(1)', 'data:text/html,x']) {
    const res = await regPost(s, { redirect_uris: [u] });
    assert.equal(res.statusCode, 400, u);
    assert.equal(res.json().error, 'invalid_redirect_uri');
  }
  for (const u of ['http://127.0.0.1:8080/cb', 'http://[::1]:8080/cb']) {
    assert.equal((await regPost(s, { redirect_uris: [u] })).statusCode, 201, u);
  }
  await s.server.close();
  const custom = await setup({ registrationPolicy: { allowedRedirectSchemes: ['https', 'com.example.app', 'javascript'] } });
  assert.equal((await regPost(custom, { redirect_uris: ['com.example.app:/cb'] })).statusCode, 201);
  assert.equal((await regPost(custom, { redirect_uris: ['javascript:alert(1)'] })).statusCode, 400);
  await custom.server.close();
});

test('PUT cannot widen grants or scopes past the policy', async () => {
  const s = await setup({ dynamicRegistration: true });
  const reg = (await regPost(s, { redirect_uris: [CB], grant_types: ['authorization_code'], scope: 'openid' })).json();
  const stored = JSON.stringify(await s.store.getClient(reg.client_id));
  const put = (body: unknown) => s.server.inject({
    method: 'PUT', url: `/connect/register/${reg.client_id}`,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${reg.registration_access_token}` }, payload: JSON.stringify(body),
  });
  for (const body of [
    { redirect_uris: [CB], grant_types: ['client_credentials'], scope: 'openid' },
    { redirect_uris: [CB], grant_types: ['authorization_code'], scope: 'orders:manage' },
  ]) {
    const res = await put(body);
    assert.equal(res.statusCode, 400);
    assert.equal(res.json().error, 'invalid_client_metadata');
  }
  assert.equal((await put({ redirect_uris: ['http://localhost/cb'], scope: 'openid' })).statusCode, 400);
  assert.equal(JSON.stringify(await s.store.getClient(reg.client_id)), stored);
  await s.server.close();
});

test('initial access token gates registration when configured', async () => {
  const IAT = 'initial-access-token-value';
  const s = await setup({ registrationPolicy: { initialAccessToken: IAT } });
  const body = { redirect_uris: [CB] };
  for (const headers of [{}, { authorization: 'Bearer wrong' }, { authorization: `Basic ${IAT}` }]) {
    const res = await regPost(s, body, headers);
    assert.equal(res.statusCode, 401);
    assert.equal(res.json().error, 'invalid_client');
  }
  const ok = await regPost(s, body, { authorization: `Bearer ${IAT}` });
  assert.equal(ok.statusCode, 201);
  const { registration_client_uri: uri, registration_access_token: rat } = ok.json();
  // Management methods stay gated by the per-client registration access token.
  for (const method of ['GET', 'PUT', 'DELETE'] as const) {
    const res = await s.server.inject({ method, url: uri, ...(method === 'PUT' ? { headers: { 'content-type': 'application/json' }, payload: JSON.stringify(body) } : {}) });
    assert.equal(res.statusCode, 401, method);
  }
  assert.equal((await s.server.inject({ method: 'GET', url: uri, headers: { authorization: `Bearer ${IAT}` } })).statusCode, 401);
  assert.equal((await s.server.inject({ method: 'GET', url: uri, headers: { authorization: `Bearer ${rat}` } })).statusCode, 200);
  await s.server.close();
});

// -- OIDC logout client registration metadata (ticket 1/5) --

const LOGOUT_METADATA = {
  post_logout_redirect_uris: ['https://app.example/logged-out'],
  backchannel_logout_uri: 'https://app.example/backchannel-logout',
  backchannel_logout_session_required: true,
  frontchannel_logout_uri: 'https://app.example/frontchannel-logout',
  frontchannel_logout_session_required: true,
};

test('DCR accepts, persists and echoes OIDC logout registration metadata', async () => {
  const s = await setup();
  const res = await regPost(s, { redirect_uris: [CB], ...LOGOUT_METADATA });
  assert.equal(res.statusCode, 201, JSON.stringify(res.json()));
  for (const [key, value] of Object.entries(LOGOUT_METADATA)) assert.deepEqual(res.json()[key], value, key);
  const id = res.json().client_id;
  const stored = await s.store.getClient(id);
  assert.deepEqual(stored?.postLogoutRedirectUris, LOGOUT_METADATA.post_logout_redirect_uris);
  assert.equal(stored?.backchannelLogoutUri, LOGOUT_METADATA.backchannel_logout_uri);
  assert.equal(stored?.backchannelLogoutSessionRequired, true);
  assert.equal(stored?.frontchannelLogoutUri, LOGOUT_METADATA.frontchannel_logout_uri);
  assert.equal(stored?.frontchannelLogoutSessionRequired, true);
  const read = await s.server.inject({
    method: 'GET', url: res.json().registration_client_uri,
    headers: { authorization: `Bearer ${res.json().registration_access_token}` },
  });
  assert.equal(read.statusCode, 200);
  for (const [key, value] of Object.entries(LOGOUT_METADATA)) assert.deepEqual(read.json()[key], value, key);
  await s.server.close();
});

test('DCR PUT updates OIDC logout registration metadata and echoes the new values', async () => {
  const s = await setup();
  const created = (await regPost(s, { redirect_uris: [CB], ...LOGOUT_METADATA })).json();
  const put = (body: unknown) => s.server.inject({
    method: 'PUT', url: created.registration_client_uri,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${created.registration_access_token}` },
    payload: JSON.stringify(body),
  });
  const update = {
    redirect_uris: [CB],
    post_logout_redirect_uris: ['https://app.example/bye'],
    backchannel_logout_uri: 'https://app.example/bcl-2',
    backchannel_logout_session_required: false,
    frontchannel_logout_uri: null,
    frontchannel_logout_session_required: false,
  };
  const res = await put(update);
  assert.equal(res.statusCode, 200, JSON.stringify(res.json()));
  assert.deepEqual(res.json().post_logout_redirect_uris, ['https://app.example/bye']);
  assert.equal(res.json().backchannel_logout_uri, 'https://app.example/bcl-2');
  assert.equal(res.json().backchannel_logout_session_required, false);
  assert.equal(res.json().frontchannel_logout_uri, undefined);
  const stored = await s.store.getClient(created.client_id);
  assert.deepEqual(stored?.postLogoutRedirectUris, ['https://app.example/bye']);
  assert.equal(stored?.backchannelLogoutUri, 'https://app.example/bcl-2');
  assert.equal(stored?.frontchannelLogoutUri, undefined);
  assert.equal(stored?.frontchannelLogoutSessionRequired, false);
  await s.server.close();
});

test('DCR rejects malformed OIDC logout registration metadata with invalid_client_metadata', async () => {
  const s = await setup();
  const bad = [
    { post_logout_redirect_uris: 'https://app.example/out' },
    { post_logout_redirect_uris: ['https://app.example/out#fragment'] },
    { post_logout_redirect_uris: ['not a url'] },
    { post_logout_redirect_uris: [7] },
    { backchannel_logout_uri: 'https://app.example/cb#fragment' },
    { backchannel_logout_uri: 'ftp://app.example/cb' },
    { backchannel_logout_uri: 'http://app.example/cb' },
    { backchannel_logout_uri: 7 },
    { frontchannel_logout_uri: 'javascript:alert(1)' },
    { backchannel_logout_session_required: 'yes' },
    { frontchannel_logout_session_required: 1 },
  ];
  for (const patch of bad) {
    const res = await regPost(s, { redirect_uris: [CB], ...LOGOUT_METADATA, ...patch });
    assert.equal(res.statusCode, 400, JSON.stringify(patch));
    assert.equal(res.json().error, 'invalid_client_metadata', JSON.stringify(patch));
  }
  // The conformance/test policy allows http only on loopback IP literals.
  const loopback = await regPost(s, {
    redirect_uris: [CB],
    backchannel_logout_uri: 'http://127.0.0.1:8099/backchannel-logout',
    frontchannel_logout_uri: 'http://[::1]:8099/frontchannel-logout',
    post_logout_redirect_uris: ['http://127.0.0.1:8099/logged-out'],
  });
  assert.equal(loopback.statusCode, 201, JSON.stringify(loopback.json()));
  await s.server.close();
});

test('DCR PUT rejects invalid logout metadata without changing the stored client', async () => {
  const s = await setup();
  const created = (await regPost(s, { redirect_uris: [CB], ...LOGOUT_METADATA })).json();
  const before = JSON.stringify(await s.store.getClient(created.client_id));
  const res = await s.server.inject({
    method: 'PUT', url: created.registration_client_uri,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${created.registration_access_token}` },
    payload: JSON.stringify({ redirect_uris: [CB], ...LOGOUT_METADATA, backchannel_logout_session_required: 'true' }),
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_client_metadata');
  assert.equal(JSON.stringify(await s.store.getClient(created.client_id)), before);
  await s.server.close();
});
