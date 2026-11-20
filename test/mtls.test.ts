import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { decodeJwt, exportPKCS8, generateKeyPair } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import { ConfigError, loadConfig } from '../src/config.js';
import { certThumbprint, type MtlsConfig } from '../src/mtls.js';
import type { ClientRecord } from '../src/ports.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';

const ISSUER = 'http://localhost:8080';
const PROXY_SECRET = 'p'.repeat(16) + 'x'.repeat(16) + 'q1';
const cfg: MtlsConfig = { proxySecret: PROXY_SECRET, certHeader: 'x-client-cert' };
const clock = { now: () => Math.floor(Date.now() / 1000) };

const dir = mkdtempSync(join(tmpdir(), 'mtls-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
const sh = (...a: string[]) => execFileSync('openssl', a, { cwd: dir, stdio: 'pipe' });
function selfSigned(name: string, subj: string, san?: string): string {
  sh('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', subj, '-days', '2',
    '-keyout', `${name}.key`, '-out', `${name}.pem`, ...(san ? ['-addext', `subjectAltName=${san}`] : []));
  return readFileSync(join(dir, `${name}.pem`), 'utf8');
}
const pemA = selfSigned('a', '/O=Acme/CN=client-a', 'DNS:a.example');
const pemB = selfSigned('b', '/O=Acme/CN=client-b');
// CA + leaf issued by it.
const caPem = selfSigned('ca', '/O=Root/CN=Test CA');
sh('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/O=Acme/CN=leaf', '-keyout', 'leaf.key', '-out', 'leaf.csr');
sh('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '2', '-out', 'leaf.pem');
const leafPem = readFileSync(join(dir, 'leaf.pem'), 'utf8');

const enc = (pem: string) => encodeURIComponent(pem);
const thumb = (pem: string) => certThumbprint(new X509Certificate(pem));
const x5c = (pem: string) => new X509Certificate(pem).raw.toString('base64');
const viaProxy = (pem: string | undefined, secret: string | null = PROXY_SECRET): Record<string, string> => ({
  ...(secret !== null ? { 'x-mtls-proxy-secret': secret } : {}),
  ...(pem !== undefined ? { 'x-client-cert': enc(pem) } : {}),
});

async function setup(opts: { mtls?: MtlsConfig | undefined; clients?: Array<Partial<ClientRecord> & { clientId: string }> } = {}) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base = { clientSecretHash: null, redirectUris: [] as string[], grantTypes: ['client_credentials'], scopes: ['read'], enabled: true };
  for (const c of opts.clients ?? []) await store.saveClient({ ...base, ...c });
  const server = buildServer({ store, signer, clock, random: cryptoRandom, issuer: ISSUER, mtls: opts.mtls });
  return { server, store, signer };
}

const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const cc = (server: Awaited<ReturnType<typeof setup>>['server'], clientId: string, headers: Record<string, string>) =>
  server.inject({ method: 'POST', url: '/oauth/token', headers: { ...FORM, ...headers }, payload: form({ grant_type: 'client_credentials', client_id: clientId, scope: 'read' }) });

const dnClient = { clientId: 'dn', tokenEndpointAuthMethod: 'tls_client_auth', mtls: { subjectDn: 'CN=client-a,O=Acme' } };

test('tls_client_auth by subject DN issues a cert-bound token', async () => {
  const { server } = await setup({ mtls: cfg, clients: [dnClient] });
  const res = await cc(server, 'dn', viaProxy(pemA));
  assert.equal(res.statusCode, 200, res.body);
  assert.equal(res.json().token_type, 'Bearer');
  assert.deepEqual(decodeJwt(res.json().access_token).cnf, { 'x5t#S256': thumb(pemA) });
});

test('tls_client_auth by SAN dNSName', async () => {
  const { server } = await setup({ mtls: cfg, clients: [{ clientId: 'san', tokenEndpointAuthMethod: 'tls_client_auth', mtls: { sanDns: 'a.example' } }] });
  assert.equal((await cc(server, 'san', viaProxy(pemA))).statusCode, 200);
  assert.equal((await cc(server, 'san', viaProxy(pemB))).statusCode, 401);
});

test('fails closed: disabled, untrusted proxy, missing/garbled cert, wrong subject, secret alongside cert', async () => {
  const off = await setup({ clients: [dnClient] });
  assert.equal((await cc(off.server, 'dn', viaProxy(pemA))).statusCode, 401);
  const { server } = await setup({ mtls: cfg, clients: [dnClient] });
  for (const headers of [
    viaProxy(pemA, null), // direct hit, no proxy secret
    viaProxy(pemA, 'z'.repeat(34)), // wrong proxy secret
    viaProxy(undefined), // trusted proxy, no client cert
    { 'x-mtls-proxy-secret': PROXY_SECRET, 'x-client-cert': 'not-a-cert' },
    viaProxy(pemB), // valid cert, wrong subject
  ]) {
    const res = await cc(server, 'dn', headers);
    assert.equal(res.statusCode, 401);
    assert.equal(res.json().error, 'invalid_client');
  }
  const withSecret = await server.inject({ method: 'POST', url: '/oauth/token', headers: { ...FORM, ...viaProxy(pemA) },
    payload: form({ grant_type: 'client_credentials', client_id: 'dn', client_secret: 'whatever' }) });
  assert.equal(withSecret.statusCode, 401);
});

test('mtls client without a configured subject identifier never authenticates', async () => {
  const { server } = await setup({ mtls: cfg, clients: [{ clientId: 'none', tokenEndpointAuthMethod: 'tls_client_auth' }, { clientId: 'both', tokenEndpointAuthMethod: 'tls_client_auth', mtls: { subjectDn: 'CN=client-a,O=Acme', sanDns: 'a.example' } }] });
  assert.equal((await cc(server, 'none', viaProxy(pemA))).statusCode, 401);
  assert.equal((await cc(server, 'both', viaProxy(pemA))).statusCode, 401);
});

test('self_signed_tls_client_auth matches the registered x5c certificate only', async () => {
  const client = { clientId: 'ss', tokenEndpointAuthMethod: 'self_signed_tls_client_auth', jwks: { keys: [{ kty: 'EC', x5c: [x5c(pemA)] }] } };
  const { server } = await setup({ mtls: cfg, clients: [client] });
  const ok = await cc(server, 'ss', viaProxy(pemA));
  assert.equal(ok.statusCode, 200, ok.body);
  assert.equal(decodeJwt(ok.json().access_token).cnf?.['x5t#S256' as never], thumb(pemA));
  assert.equal((await cc(server, 'ss', viaProxy(pemB))).statusCode, 401);
});

test('optional CA anchor: tls_client_auth cert must be issued by it', async () => {
  const withCa: MtlsConfig = { ...cfg, caPem };
  const clients = [{ clientId: 'leaf', tokenEndpointAuthMethod: 'tls_client_auth', mtls: { subjectDn: 'CN=leaf,O=Acme' } }];
  const { server } = await setup({ mtls: withCa, clients });
  assert.equal((await cc(server, 'leaf', viaProxy(leafPem))).statusCode, 200);
  const otherCa = selfSigned('other', '/O=Other/CN=Other CA');
  const { server: s2 } = await setup({ mtls: { ...cfg, caPem: otherCa }, clients });
  assert.equal((await cc(s2, 'leaf', viaProxy(leafPem))).statusCode, 401);
});

test('secret client with boundTokens binds to the presented cert and refuses without one', async () => {
  const secret = 'bound-client-secret-value';
  const { server } = await setup({ mtls: cfg, clients: [{ clientId: 'bt', clientSecretHash: await hashClientSecret(secret), mtls: { boundTokens: true } }] });
  const basic = { authorization: `Basic ${Buffer.from(`bt:${secret}`).toString('base64')}` };
  const ok = await cc(server, 'bt', { ...basic, ...viaProxy(pemB) });
  assert.equal(ok.statusCode, 200, ok.body);
  assert.deepEqual(decodeJwt(ok.json().access_token).cnf, { 'x5t#S256': thumb(pemB) });
  assert.equal((await cc(server, 'bt', basic)).statusCode, 401);
});

test('plain secret clients stay unbound even when a cert is forwarded', async () => {
  const secret = 'plain-client-secret-value';
  const { server } = await setup({ mtls: cfg, clients: [{ clientId: 'pl', clientSecretHash: await hashClientSecret(secret) }] });
  const res = await cc(server, 'pl', { authorization: `Basic ${Buffer.from(`pl:${secret}`).toString('base64')}`, ...viaProxy(pemA) });
  assert.equal(decodeJwt(res.json().access_token).cnf, undefined);
});

test('introspection reports cnf x5t#S256; userinfo demands the bound certificate', async () => {
  const { server, store, signer } = await setup({ mtls: cfg, clients: [dnClient] });
  const issued = await cc(server, 'dn', viaProxy(pemA));
  const intro = await server.inject({ method: 'POST', url: '/oauth/introspect', headers: { ...FORM, ...viaProxy(pemA) },
    payload: form({ token: issued.json().access_token, client_id: 'dn' }) });
  assert.deepEqual(intro.json().cnf, { 'x5t#S256': thumb(pemA) });

  const now = clock.now();
  const token = await signer.sign({ iss: ISSUER, sub: 'user-1', aud: 'dn', client_id: 'dn', iat: now, exp: now + 600, jti: 'j1', scope: 'openid', cnf: { 'x5t#S256': thumb(pemA) } });
  await store.saveAccessToken({ jti: 'j1', clientId: 'dn', subject: 'user-1', scope: 'openid', expiresAt: now + 600, revokedAt: null, tokenHash: null });
  const get = (headers: Record<string, string>) => server.inject({ method: 'GET', url: '/oauth/userinfo', headers: { authorization: `Bearer ${token}`, ...headers } });
  assert.equal((await get(viaProxy(pemA))).statusCode, 200);
  assert.equal((await get({})).statusCode, 401);
  assert.equal((await get(viaProxy(pemB))).statusCode, 401);
  assert.equal((await get(viaProxy(pemA, 'z'.repeat(34)))).statusCode, 401);
});

test('discovery advertises mTLS only when configured', async () => {
  const on = (await (await setup({ mtls: cfg })).server.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })).json();
  assert.equal(on.tls_client_certificate_bound_access_tokens, true);
  assert.ok(on.token_endpoint_auth_methods_supported.includes('tls_client_auth'));
  assert.ok(on.token_endpoint_auth_methods_supported.includes('self_signed_tls_client_auth'));
  const off = (await (await setup()).server.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })).json();
  assert.equal(off.tls_client_certificate_bound_access_tokens, undefined);
  assert.ok(!off.token_endpoint_auth_methods_supported.includes('tls_client_auth'));
});

test('config: mtls is off by default and validated when enabled', async () => {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const env = {
    OAUTH2_ENV: 'test', OAUTH2_ISSUER: ISSUER, OAUTH2_SESSION_SECRET: 's3ssion-'.repeat(5),
    OAUTH2_SIGNING_KEY_PEM: await exportPKCS8(privateKey), OAUTH2_SIGNING_KEY_ID: 'k1',
  };
  assert.equal(loadConfig(env).mtls, undefined);
  assert.deepEqual(loadConfig({ ...env, OAUTH2_MTLS_PROXY_SECRET: PROXY_SECRET }).mtls, { proxySecret: PROXY_SECRET, certHeader: 'x-client-cert', caPem: undefined });
  assert.throws(() => loadConfig({ ...env, OAUTH2_MTLS_PROXY_SECRET: 'short' }), ConfigError);
  assert.throws(() => loadConfig({ ...env, OAUTH2_MTLS_CERT_HEADER: 'x-cert' }), ConfigError);
  assert.throws(() => loadConfig({ ...env, OAUTH2_MTLS_PROXY_SECRET: PROXY_SECRET, OAUTH2_MTLS_CA_PEM: 'junk' }), ConfigError);
});
