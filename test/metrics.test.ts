import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Metrics } from '../src/metrics.js';
import { buildServer } from '../src/server.js';
import { SqliteStore } from '../src/sqlite-store.js';

test('metrics only expose fixed operation and status labels, never input paths or bearer secrets', () => {
  const m = new Metrics();
  m.observe('GET', '/oauth/token/secret-123', 401, 0.02);
  m.observe('POST', '/oauth/token', 200, 0.12);
  const output = m.render();
  assert.match(output, /oauth_http_requests_total\{operation="token",status="2xx"\} 1/);
  assert.match(output, /oauth_http_requests_total\{operation="other",status="4xx"\} 1/);
  assert.doesNotMatch(output, /secret-123|\/oauth\/token/);
});

test('opt-in metrics endpoint and trace callback expose only static operation names', async () => {
  const store = new SqliteStore(':memory:');
  await store.init();
  const metrics = new Metrics();
  const spans: string[] = [];
  const server = buildServer({ store, metrics, trace: (name) => { spans.push(name); return () => undefined; },
    signer: { sign: async () => 'signed', publicJwks: async () => ({ keys: [] }) },
    clock: { now: () => 1000 }, random: { token: () => 'random' }, issuer: 'https://example.test' });
  try {
    await server.inject('/health?secret=hide-me');
    const res = await server.inject('/metrics');
    assert.equal(res.statusCode, 200);
    assert.match(res.body, /oauth_http_requests_total\{operation="health",status="2xx"\} 1/);
    assert.doesNotMatch(res.body, /hide-me/);
    assert.ok(spans.includes('oauth.http.health'));
  } finally { await server.close(); await store.close(); }
});
