import { createServer as createNetServer } from 'node:net';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair } from 'jose';
import { startServer } from '../src/main.js';
import { buildServer } from '../src/server.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { createJoseSigner } from '../src/signer.js';
import { systemClock, cryptoRandom } from '../src/runtime.js';

async function app() {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(':memory:');
  await store.init();
  const server = buildServer({ store, signer, clock: systemClock, random: cryptoRandom, issuer: 'http://localhost:8080' });
  return { server, store };
}

test('GET /health is ok and not cacheable', async () => {
  const { server, store } = await app();
  const res = await server.inject({ method: 'GET', url: '/health' });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), { status: 'ok' });
  assert.equal(res.headers['cache-control'], 'no-store');
  await server.close();
  await store.close();
});

test('GET /health returns 503 when storage is down', async () => {
  const { server, store } = await app();
  await store.close();
  const res = await server.inject({ method: 'GET', url: '/health' });
  assert.equal(res.statusCode, 503);
  assert.deepEqual(res.json(), { status: 'unavailable' });
  await server.close();
});

test('unknown route returns an OAuth-shaped JSON error, not framework HTML', async () => {
  const { server, store } = await app();
  const res = await server.inject({ method: 'GET', url: '/nope' });
  assert.equal(res.statusCode, 404);
  assert.equal(res.json().error, 'invalid_request');
  assert.equal(res.headers['cache-control'], 'no-store');
  await server.close();
  await store.close();
});

test('malformed JSON body yields invalid_request 400', async () => {
  const { server, store } = await app();
  server.post('/echo', async () => ({}));
  const res = await server.inject({ method: 'POST', url: '/echo', headers: { 'content-type': 'application/json' }, payload: '{bad' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_request');
  await server.close();
  await store.close();
});

test('unexpected handler error is opaque server_error and does not leak', async () => {
  const { server, store } = await app();
  server.get('/boom', async () => {
    throw new Error('password=hunter2');
  });
  const res = await server.inject({ method: 'GET', url: '/boom' });
  assert.equal(res.statusCode, 500);
  assert.deepEqual(res.json(), { error: 'server_error' });
  await server.close();
  await store.close();
});

test('server does not advertise framework identity or implement unported endpoints yet', async () => {
  const { server, store } = await app();
  const res = await server.inject({ method: 'POST', url: '/unregistered' });
  assert.equal(res.statusCode, 404);
  assert.equal(res.headers['x-powered-by'], undefined);
  await server.close();
  await store.close();
});

test('startServer refuses to boot with invalid config', async () => {
  await assert.rejects(startServer({ OAUTH2_ENV: 'production' }), /OAUTH2_/);
});

test('startServer boots with valid config on a free port and serves /health', async () => {
  const probe = createNetServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const port = (probe.address() as { port: number }).port;
  await new Promise((r) => probe.close(r));
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const env = {
    OAUTH2_ENV: 'development',
    OAUTH2_ISSUER: 'http://localhost:8080',
    OAUTH2_SESSION_SECRET: 'y'.repeat(32),
    OAUTH2_SIGNING_KEY_PEM: await exportPKCS8(privateKey),
    OAUTH2_SIGNING_KEY_ID: 'k1',
    OAUTH2_PORT: String(port),
  };
  const running = await startServer(env);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(res.status, 200);
  } finally {
    await running.close();
  }
});
