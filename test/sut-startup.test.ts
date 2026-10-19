import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFile, mkdtemp } from 'node:fs/promises';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { startServer, type RunningServer } from '../src/main.js';

const SEED_PATH = new URL('./data/conformance-seed.yaml', import.meta.url).pathname;
const CHALLENGE = createHash('sha256').update('v'.repeat(43)).digest('base64url');

async function freePort(): Promise<number> {
  const probe = createNetServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  return port;
}

async function baseEnv(): Promise<Record<string, string>> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  return {
    OAUTH2_ENV: 'test',
    OAUTH2_ISSUER: 'http://localhost:8080',
    OAUTH2_SESSION_SECRET: 'x'.repeat(32),
    OAUTH2_SIGNING_KEY_PEM: await exportPKCS8(privateKey),
    OAUTH2_SIGNING_KEY_ID: 'k1',
    OAUTH2_PORT: String(await freePort()),
  };
}

function authorizeUrl(base: string, clientId: string, extra: Record<string, string> = {}): string {
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: 'https://client.example/callback',
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    state: 'st',
    scope: 'openid',
    ...extra,
  });
  return `${base}/oauth/authorize?${q.toString()}`;
}

async function withServer(env: Record<string, string>, fn: (base: string) => Promise<void>): Promise<void> {
  let running: RunningServer | undefined;
  try {
    running = await startServer(env);
    await fn(running.address);
  } finally {
    await running?.close();
  }
}

async function login(base: string, username: string, password: string): Promise<Response> {
  return fetch(`${base}/auth/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password }).toString(),
  });
}

test('normal start exposes no test login, no seeded client, and authorize stays access_denied', async () => {
  const env = await baseEnv();
  await withServer(env, async (base) => {
    assert.equal((await fetch(`${base}/health`)).status, 200);
    assert.equal((await fetch(`${base}/auth/login`)).status, 404);
    assert.equal((await login(base, 'alice', 'test-only-password')).status, 404);
    // Unknown client: the seed was never applied.
    assert.equal((await fetch(authorizeUrl(base, 'client-public'), { redirect: 'manual' })).status, 400);
  });
});

test('a seed path without the mode switch is ignored', async () => {
  const env = { ...(await baseEnv()), OAUTH2_CONFORMANCE_SEED: SEED_PATH };
  await withServer(env, async (base) => {
    assert.equal((await fetch(`${base}/auth/login`)).status, 404);
    assert.equal((await fetch(authorizeUrl(base, 'client-public'), { redirect: 'manual' })).status, 400);
  });
});

test('conformance mode seeds, then drives login, auto-approval and the OAuth redirect', async () => {
  const env = { ...(await baseEnv()), OAUTH2_CONFORMANCE_MODE: '1', OAUTH2_CONFORMANCE_SEED: SEED_PATH };
  await withServer(env, async (base) => {
    // Ready means seeded: the first request after listen already knows the client.
    assert.equal((await fetch(`${base}/health`)).status, 200);

    // Unauthenticated authorize goes to the login step (same-origin relative redirect).
    const first = await fetch(authorizeUrl(base, 'client-public'), { redirect: 'manual' });
    assert.equal(first.status, 302);
    assert.equal(first.headers.get('location'), '/auth/login');
    assert.equal((await fetch(`${base}/auth/login`)).status, 200);

    // Wrong password and unknown user are refused with error= and set no session.
    for (const [u, p] of [['alice', 'wrong'], ['mallory', 'test-only-password']] as const) {
      const refused = await login(base, u, p);
      assert.equal(refused.status, 302);
      assert.match(refused.headers.get('location') ?? '', /^\/auth\/login\?error=/);
      assert.equal(refused.headers.get('set-cookie'), null);
    }

    const ok = await login(base, 'alice', 'test-only-password');
    assert.equal(ok.status, 302);
    const cookie = (ok.headers.get('set-cookie') ?? '').split(';')[0] ?? '';
    assert.match(cookie, /^oauth2_test_session=.+/);
    assert.match(ok.headers.get('set-cookie') ?? '', /HttpOnly/i);

    // Auto-approved client: normal redirect with code, state and iss.
    const granted = await fetch(authorizeUrl(base, 'client-public'), { redirect: 'manual', headers: { cookie: cookie } });
    assert.equal(granted.status, 302);
    const loc = new URL(granted.headers.get('location') ?? '');
    assert.equal(loc.origin + loc.pathname, 'https://client.example/callback');
    assert.ok((loc.searchParams.get('code') ?? '').length >= 32);
    assert.equal(loc.searchParams.get('state'), 'st');
    assert.equal(loc.searchParams.get('iss'), 'http://localhost:8080');

    // Protocol validation is unchanged for an authenticated user: bad scope still invalid_scope.
    const badScope = await fetch(authorizeUrl(base, 'client-public', { scope: 'admin' }), { redirect: 'manual', headers: { cookie } });
    assert.equal(new URL(badScope.headers.get('location') ?? '').searchParams.get('error'), 'invalid_scope');

    // Consent is not auto-granted for clients outside auto_approve_clients (client-a has a secret
    // but is not auto-approved here for loopback-less variants): client-localhost is unlisted.
    const noConsent = await fetch(
      authorizeUrl(base, 'client-localhost', { redirect_uri: 'http://localhost/cb' }),
      { redirect: 'manual', headers: { cookie } },
    );
    const denied = new URL(noConsent.headers.get('location') ?? '');
    assert.equal(denied.searchParams.get('error'), 'access_denied');
    assert.equal(denied.searchParams.get('code'), null);

    // A forged session cookie is not a session.
    const forged = await fetch(authorizeUrl(base, 'client-public'), { redirect: 'manual', headers: { cookie: 'oauth2_test_session=forged' } });
    assert.equal(forged.headers.get('location'), '/auth/login');
  });
});

test('the issued code redeems at the token endpoint for the seeded identity', async () => {
  const env = { ...(await baseEnv()), OAUTH2_CONFORMANCE_MODE: '1', OAUTH2_CONFORMANCE_SEED: SEED_PATH };
  await withServer(env, async (base) => {
    const cookie = ((await login(base, 'alice', 'test-only-password')).headers.get('set-cookie') ?? '').split(';')[0] ?? '';
    const granted = await fetch(authorizeUrl(base, 'client-public'), { redirect: 'manual', headers: { cookie } });
    const code = new URL(granted.headers.get('location') ?? '').searchParams.get('code') ?? '';
    const res = await fetch(`${base}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'client-public',
        code,
        redirect_uri: 'https://client.example/callback',
        code_verifier: 'v'.repeat(43),
      }).toString(),
    });
    assert.equal(res.status, 200);
    assert.equal(((await res.json()) as { token_type: string }).token_type, 'Bearer');
  });
});

test('confidential seeded secret authenticates only while conformance mode is on', async () => {
  const basic = `Basic ${Buffer.from('client-a:test-only-secret').toString('base64')}`;
  const tokenReq = (base: string) =>
    fetch(`${base}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'nope', redirect_uri: 'https://client.example/callback', code_verifier: 'v'.repeat(43) }).toString(),
    });
  const on = { ...(await baseEnv()), OAUTH2_CONFORMANCE_MODE: '1', OAUTH2_CONFORMANCE_SEED: SEED_PATH };
  await withServer(on, async (base) => {
    // Client auth succeeds; the bogus code is what fails.
    assert.equal(((await (await tokenReq(base)).json()) as { error: string }).error, 'invalid_grant');
  });
  await withServer(await baseEnv(), async (base) => {
    assert.equal(((await (await tokenReq(base)).json()) as { error: string }).error, 'invalid_client');
  });
});

async function assertNotListening(port: string): Promise<void> {
  await assert.rejects(fetch(`http://127.0.0.1:${port}/health`));
}

test('startup aborts before listening for a missing, unreadable or invalid seed', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sut-seed-'));
  const bad = join(dir, 'bad.yaml');
  await writeFile(bad, 'issuer: http://localhost:8080\nclients: []\nusers: []\n');
  const mismatch = join(dir, 'mismatch.yaml');
  await writeFile(
    mismatch,
    'issuer: http://localhost:9999\nclients:\n  - client_id: c\n    public: true\n    redirect_uris: [https://a.example/cb]\nusers:\n  - username: u\n    password: p\n',
  );
  const unprovisionable = join(dir, 'rs.yaml');
  await writeFile(
    unprovisionable,
    'issuer: http://localhost:8080\nsigningKeys:\n  - kid: k1\n    alg: RS256\nclients:\n  - client_id: c\n    public: true\n    redirect_uris: [https://a.example/cb]\nusers:\n  - username: u\n    password: p\n',
  );
  for (const [path, pattern] of [
    [join(dir, 'missing.yaml'), /cannot read seed file/],
    [dir, /cannot read seed file/],
    [bad, /clients must be a nonempty array/],
    [mismatch, /does not match OAUTH2_ISSUER/],
    [unprovisionable, /cannot be provisioned/],
  ] as const) {
    const env: Record<string, string> = { ...(await baseEnv()), OAUTH2_CONFORMANCE_MODE: '1', OAUTH2_CONFORMANCE_SEED: path };
    await assert.rejects(startServer(env), pattern);
    await assertNotListening(env.OAUTH2_PORT ?? '');
  }
});

test('startup aborts for a missing seed variable or ambiguous mode value', async () => {
  const noSeed: Record<string, string> = { ...(await baseEnv()), OAUTH2_CONFORMANCE_MODE: '1' };
  await assert.rejects(startServer(noSeed), /OAUTH2_CONFORMANCE_SEED/);
  await assertNotListening(noSeed.OAUTH2_PORT ?? '');
  const typo: Record<string, string> = { ...(await baseEnv()), OAUTH2_CONFORMANCE_MODE: 'yes', OAUTH2_CONFORMANCE_SEED: SEED_PATH };
  await assert.rejects(startServer(typo), /OAUTH2_CONFORMANCE_MODE/);
  await assertNotListening(typo.OAUTH2_PORT ?? '');
});

test('startup aborts for unsafe configuration in conformance mode', async () => {
  const on: Record<string, string> = { OAUTH2_CONFORMANCE_MODE: '1', OAUTH2_CONFORMANCE_SEED: SEED_PATH };
  const dir = await mkdtemp(join(tmpdir(), 'sut-db-'));
  const cases: Array<[Record<string, string>, RegExp]> = [
    [{ OAUTH2_ENV: 'production', OAUTH2_ISSUER: 'https://auth.example.com', OAUTH2_DATABASE_PATH: join(dir, 'db.sqlite'), OAUTH2_SESSION_SECRET: 'q'.repeat(40) }, /not a known non-production environment/],
    [{ APP_ENV: 'staging' }, /APP_ENV/],
    [{ OAUTH2_DATABASE_PATH: join(dir, 'db.sqlite') }, /in-memory database/],
    [{ OAUTH2_HOST: '0.0.0.0' }, /loopback bind address/],
  ];
  for (const [overrides, pattern] of cases) {
    const env: Record<string, string> = { ...(await baseEnv()), ...on, ...overrides };
    await assert.rejects(startServer(env), pattern);
    await assertNotListening(env.OAUTH2_PORT ?? '');
  }
});
