import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { verifyClientSecret } from '../src/client-auth.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { SeedError, applySeed, assertProvisionable, loadSeed, parseSeed } from '../src/sut/seed.js';

const SEED_PATH = new URL('./data/conformance-seed.yaml', import.meta.url).pathname;
const EXAMPLE = readFileSync(SEED_PATH, 'utf8');

const minimal = {
  issuer: 'http://localhost:8080',
  clients: [{ client_id: 'c', public: true, token_endpoint_auth_method: 'none', redirect_uris: ['https://a.example/cb'] }],
  users: [{ username: 'u', password: 'p' }],
};

function rejects(mutate: (s: Record<string, unknown>) => void, needle: RegExp) {
  const seed = structuredClone(minimal) as Record<string, unknown>;
  mutate(seed);
  assert.throws(() => parseSeed(JSON.stringify(seed)), (e) => e instanceof SeedError && needle.test(e.message));
}

test('the pinned contract example seed parses', () => {
  const seed = parseSeed(EXAMPLE);
  assert.equal(seed.issuer, 'http://localhost:8080');
  assert.equal(seed.clients.length, 8);
  assert.equal(seed.users[0]?.username, 'alice');
  const pub = seed.clients.find((c) => c.clientId === 'client-public');
  assert.equal(pub?.clientSecret, null);
  assert.deepEqual(pub?.grantTypes, ['authorization_code']);
  const enc = seed.clients.find((c) => c.clientId === 'client-enc');
  assert.equal(enc?.clientSecret, 'p@ss:w+rd %');
});

test('JSON seeds parse and defaults apply', () => {
  const seed = parseSeed(JSON.stringify(minimal));
  assert.deepEqual(seed.clients[0]?.grantTypes, ['authorization_code']);
  assert.deepEqual(seed.clients[0]?.scopes, ['openid', 'read']);
  assert.deepEqual(seed.users[0]?.autoApproveClients, []);
});

test('unparseable, non-object and oversized documents are rejected', () => {
  assert.throws(() => parseSeed('a: [unclosed'), SeedError);
  assert.throws(() => parseSeed('- just\n- a list'), /object/);
  assert.throws(() => parseSeed('a: 1\na: 2'), SeedError);
  assert.throws(() => parseSeed(' '.repeat(2 * 1024 * 1024)), /too large/);
});

test('schema violations are rejected', () => {
  rejects((s) => delete s.issuer, /issuer/);
  rejects((s) => (s.issuer = 'ftp://x'), /issuer/);
  rejects((s) => (s.issuer = 'http://localhost:8080/'), /issuer.*'\/'/);
  rejects((s) => (s.issuer = 'not a url'), /issuer/);
  rejects((s) => (s.extra = 1), /unknown property "extra"/);
  rejects((s) => (s.clients = []), /clients/);
  rejects((s) => (s.users = []), /users/);
  rejects((s) => delete s.clients, /clients/);
  rejects((s) => ((s.clients as Array<Record<string, unknown>>)[0]!.client_id = ''), /client_id/);
  rejects((s) => ((s.clients as Array<Record<string, unknown>>)[0]!.nope = 1), /unknown property "nope"/);
  rejects((s) => ((s.clients as Array<Record<string, unknown>>)[0]!.redirect_uris = []), /redirect_uris/);
  rejects((s) => ((s.clients as Array<Record<string, unknown>>)[0]!.redirect_uris = ['not a uri']), /redirect_uri/);
  rejects((s) => ((s.clients as Array<Record<string, unknown>>)[0]!.redirect_uris = ['https://a.example/cb#f']), /fragment/);
  rejects((s) => ((s.clients as Array<Record<string, unknown>>)[0]!.grant_types = ['implicit']), /grant type/);
  rejects((s) => ((s.clients as Array<Record<string, unknown>>)[0]!.scopes = ['a b']), /scope/);
  rejects((s) => ((s.clients as Array<Record<string, unknown>>)[0]!.token_endpoint_auth_method = 'private_key_jwt'), /token_endpoint_auth_method/);
  rejects((s) => ((s.users as Array<Record<string, unknown>>)[0]!.password = ''), /password/);
  rejects((s) => ((s.users as Array<Record<string, unknown>>)[0]!.email = 'x'), /email/);
});

test('inconsistent client definitions are rejected', () => {
  const client = (s: Record<string, unknown>) => (s.clients as Array<Record<string, unknown>>)[0]!;
  rejects((s) => (client(s).client_secret = 's'), /public client must not carry a secret/);
  rejects((s) => (client(s).token_endpoint_auth_method = 'client_secret_basic'), /public client must use method none/);
  rejects((s) => {
    delete client(s).public;
    delete client(s).token_endpoint_auth_method;
  }, /confidential client needs client_secret/);
  rejects((s) => {
    delete client(s).public;
    client(s).token_endpoint_auth_method = 'client_secret_basic';
  }, /client_secret/);
});

test('duplicates and dangling references are rejected', () => {
  rejects((s) => ((s.clients as unknown[]).push(structuredClone((s.clients as unknown[])[0]))), /duplicate client_id/);
  rejects((s) => ((s.users as unknown[]).push(structuredClone((s.users as unknown[])[0]))), /duplicate username/);
  rejects((s) => ((s.users as Array<Record<string, unknown>>)[0]!.auto_approve_clients = ['ghost']), /unknown client "ghost"/);
});

test('signing keys follow the schema; unprovisionable keys are refused before readiness', () => {
  const ok = parseSeed(JSON.stringify({ ...minimal, signingKeys: [{ kid: 'k1', alg: 'ES256', use: 'sig' }] }));
  assert.deepEqual(ok.signingKeys, [{ kid: 'k1', alg: 'ES256' }]);
  assert.doesNotThrow(() => assertProvisionable(ok, { issuer: minimal.issuer, signingKeyId: 'k1' }));
  rejects((s) => (s.signingKeys = [{ kid: '', alg: 'ES256' }]), /kid/);
  rejects((s) => (s.signingKeys = [{ kid: 'a', alg: 'nonsense' }]), /alg/);
  rejects((s) => (s.signingKeys = [{ kid: 'a', alg: 'ES256', use: 'enc' }]), /use/);
  rejects((s) => (s.signingKeys = [{ kid: 'a', alg: 'ES256', d: 'secret' }]), /unknown property "d"/);
  rejects((s) => (s.signingKeys = [{ kid: 'a', alg: 'ES256' }, { kid: 'a', alg: 'ES256' }]), /duplicate signing key/);
  const rs = parseSeed(JSON.stringify({ ...minimal, signingKeys: [{ kid: 'k1', alg: 'RS256' }] }));
  assert.throws(() => assertProvisionable(rs, { issuer: minimal.issuer, signingKeyId: 'k1' }), /cannot be provisioned/);
  assert.throws(() => assertProvisionable(ok, { issuer: minimal.issuer, signingKeyId: 'other' }), /does not match OAUTH2_SIGNING_KEY_ID/);
  assert.throws(() => assertProvisionable(ok, { issuer: 'http://other.example', signingKeyId: 'k1' }), /does not match OAUTH2_ISSUER/);
});

test('loadSeed aborts for a missing or unreadable file', async () => {
  await assert.rejects(loadSeed('/nonexistent/seed.yaml'), (e) => e instanceof SeedError && /cannot read/.test(e.message));
  await assert.rejects(loadSeed(new URL('./data', import.meta.url).pathname), SeedError);
  const seed = await loadSeed(SEED_PATH);
  assert.equal(seed.clients.length, 8);
});

test('applySeed stores clients with hashed secrets and never the plaintext', async () => {
  const store = new SqliteStore(':memory:');
  await store.init();
  await applySeed(parseSeed(EXAMPLE), store);
  const a = await store.getClient('client-a');
  assert.ok(a?.clientSecretHash?.startsWith('scrypt$'));
  assert.ok(!JSON.stringify(a).includes('test-only-secret'));
  assert.equal(await verifyClientSecret('test-only-secret', a!.clientSecretHash!), true);
  const pub = await store.getClient('client-public');
  assert.equal(pub?.clientSecretHash, null);
  assert.deepEqual(pub?.redirectUris, ['https://client.example/callback']);
  assert.deepEqual(pub?.scopes, ['openid', 'read']);
  assert.equal(pub?.enabled, true);
  await store.close();
});

test('applySeed aborts on pre-existing conflicting state rather than overwriting it', async () => {
  const store = new SqliteStore(':memory:');
  await store.init();
  await store.saveClient({
    clientId: 'client-a', clientSecretHash: null, redirectUris: ['https://x.example/'], grantTypes: [], scopes: [], enabled: true,
  });
  await assert.rejects(applySeed(parseSeed(EXAMPLE), store), /already exists/);
  assert.equal((await store.getClient('client-a'))?.redirectUris[0], 'https://x.example/');
  await store.close();
});
