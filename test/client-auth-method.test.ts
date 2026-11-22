import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { generateKeyPair, exportPKCS8 } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import { parseSeed, applySeed } from '../src/sut/seed.js';
import type { ClientRecord } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { buildServer } from '../src/server.js';

const ISSUER = 'http://localhost:8080';
const CB = 'https://app.example/cb';
const VERIFIER = 'v'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const HEADERS = { 'content-type': 'application/x-www-form-urlencoded' };

async function setup() {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base: Omit<ClientRecord, 'clientId' | 'clientSecretHash'> = {
    redirectUris: [CB], grantTypes: ['authorization_code', 'client_credentials'], scopes: ['read'], enabled: true,
  };
  await store.saveClient({
    ...base, clientId: 'basic', clientSecretHash: await hashClientSecret('s1'),
    tokenEndpointAuthMethod: 'client_secret_basic',
  });
  await store.saveClient({
    ...base, clientId: 'post', clientSecretHash: await hashClientSecret('s2'),
    tokenEndpointAuthMethod: 'client_secret_post',
  });
  await store.saveClient({ ...base, clientId: 'legacy', clientSecretHash: await hashClientSecret('s3') });
  await store.saveClient({ ...base, clientId: 'pub', clientSecretHash: null, tokenEndpointAuthMethod: 'none' });
  const server = buildServer({
    store, signer, clock: { now: () => 1_000_000 }, random: cryptoRandom, issuer: ISSUER,
    authenticate: async () => 'user-1', throttle: false, dynamicRegistration: true,
  });
  return { server, store };
}

function post(server: Awaited<ReturnType<typeof setup>>['server'], form: Record<string, string>, headers: Record<string, string> = {}) {
  return server.inject({
    method: 'POST', url: '/oauth/token', headers: { ...HEADERS, ...headers },
    payload: new URLSearchParams(form).toString(),
  });
}

function basicHeader(id: string, secret: string): Record<string, string> {
  return { authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` };
}

async function close(s: Awaited<ReturnType<typeof setup>>) {
  await s.server.close();
  await s.store.close();
}

test('a client_secret_basic client is refused when the secret is sent in the body', async () => {
  const s = await setup();
  const res = await post(s.server, {
    grant_type: 'client_credentials', client_id: 'basic', client_secret: 's1',
  });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
  assert.equal((await post(s.server, { grant_type: 'client_credentials' }, basicHeader('basic', 's1'))).statusCode, 200);
  await close(s);
});

test('a client_secret_post client is refused when the secret is sent in the Basic header', async () => {
  const s = await setup();
  const res = await post(s.server, { grant_type: 'client_credentials' }, basicHeader('post', 's2'));
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
  assert.equal((await post(s.server, {
    grant_type: 'client_credentials', client_id: 'post', client_secret: 's2',
  })).statusCode, 200);
  await close(s);
});

test('a client recorded as `none` with a stored secret cannot authenticate on client_id alone', async () => {
  const s = await setup();
  await s.store.saveClient({
    redirectUris: [CB], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true,
    clientId: 'inconsistent', clientSecretHash: await hashClientSecret('s9'),
    tokenEndpointAuthMethod: 'none',
  });
  // No secret: must not authenticate as a public client.
  const noSecret = await post(s.server, { grant_type: 'client_credentials', client_id: 'inconsistent' });
  assert.equal(noSecret.statusCode, 401);
  assert.equal(noSecret.json().error, 'invalid_client');
  // A presented secret must not resurrect it either: `none` forbids credentials.
  const withSecret = await post(s.server, {
    grant_type: 'client_credentials', client_id: 'inconsistent', client_secret: 's9',
  });
  assert.equal(withSecret.statusCode, 401);
  assert.equal(withSecret.json().error, 'invalid_client');
  await close(s);
});

test('a client with no registered method still accepts Basic and body', async () => {
  const s = await setup();
  assert.equal((await post(s.server, { grant_type: 'client_credentials' }, basicHeader('legacy', 's3'))).statusCode, 200);
  assert.equal((await post(s.server, {
    grant_type: 'client_credentials', client_id: 'legacy', client_secret: 's3',
  })).statusCode, 200);
  await close(s);
});

test('dynamic registration persists the registered auth method on the client record', async () => {
  const s = await setup();
  const reg = await s.server.inject({
    method: 'POST', url: '/connect/register',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({
      redirect_uris: [CB], grant_types: ['authorization_code'],
      token_endpoint_auth_method: 'client_secret_post',
    }),
  });
  assert.equal(reg.statusCode, 201);
  const id = reg.json().client_id as string;
  const client = await s.store.getClient(id);
  assert.equal(client?.tokenEndpointAuthMethod, 'client_secret_post');
  await close(s);
});

test('the conformance seed persists token_endpoint_auth_method', async () => {
  const yaml = readFileSync(new URL('./data/conformance-seed.yaml', import.meta.url), 'utf8');
  const seed = parseSeed(yaml);
  const store = new SqliteStore(':memory:');
  await store.init();
  await applySeed(seed, store);
  assert.equal((await store.getClient('client-a'))?.tokenEndpointAuthMethod, 'client_secret_basic');
  assert.equal((await store.getClient('client-public'))?.tokenEndpointAuthMethod, 'none');
  await store.close();
});

test('introspection requires a credential, not a public client_id', async () => {
  const s = await setup();
  const authz = await s.server.inject({
    method: 'GET',
    url: `/oauth/authorize?${new URLSearchParams({
      response_type: 'code', client_id: 'pub', redirect_uri: CB,
      code_challenge: CHALLENGE, code_challenge_method: 'S256', state: 'st',
    })}`,
  });
  assert.equal(authz.statusCode, 302);
  const code = new URL(authz.headers.location as string).searchParams.get('code');
  assert.ok(code);
  const exchanged = await post(s.server, {
    grant_type: 'authorization_code', code, redirect_uri: CB,
    client_id: 'pub', code_verifier: VERIFIER,
  });
  assert.equal(exchanged.statusCode, 200);
  const at = exchanged.json().access_token as string;
  const introspect = (headers: Record<string, string> = {}, clientId = 'pub') => s.server.inject({
    method: 'POST', url: '/oauth/introspect', headers: { ...HEADERS, ...headers },
    payload: new URLSearchParams({ token: at, client_id: clientId }).toString(),
  });
  const publicOnly = await introspect();
  assert.equal(publicOnly.statusCode, 401);
  assert.equal(publicOnly.json().error, 'invalid_client');
  await close(s);
});

test('authentication performs one verification with a precomputed dummy hash', async () => {
  const source = readFileSync(new URL('../src/oauth.ts', import.meta.url), 'utf8');
  const auth = source.slice(source.indexOf('async function authenticateClientUnthrottled'), source.indexOf('export function bearerToken'));
  // One derivation for every client-id shape: no per-request hash of a dummy secret.
  assert.equal(auth.match(/verifyClientSecret\(/g)?.length ?? 0, 1);
  assert.doesNotMatch(auth, /hashClientSecret\(/);
});
