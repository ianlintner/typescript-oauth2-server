import assert from 'node:assert/strict';
import { test } from 'node:test';
import { candidateKeys, fetchJwks } from '../src/jwks.js';
import type { Jwks } from '../src/ports.js';

test('candidateKeys skips null and non-object entries and still returns valid keys', () => {
  const jwks: Jwks = {
    keys: [
      { kty: 'EC', crv: 'P-256', x: 'a', y: 'b', kid: 'k1', alg: 'ES256' },
      null,
      'not-a-key',
      42,
      { kty: 'RSA', n: '..', e: 'AQAB', kid: 'r1', alg: 'RS256' },
    ],
  } as unknown as Jwks;
  // ES256 -> kty EC -> only the first key survives; null/non-objects are skipped.
  const out = candidateKeys(jwks, 'ES256', undefined);
  assert.equal(out.length, 1);
  assert.equal(out[0]!.kid, 'k1');
  // RS256 -> kty RSA -> only the RSA key survives.
  assert.equal(candidateKeys(jwks, 'RS256', undefined).length, 1);
});

test('fetchJwks rejects a redirect rather than following it', async () => {
  const prev = globalThis.fetch;
  globalThis.fetch = (async () => new Response(null, { status: 302, headers: { location: 'http://evil.example/jwks.json' } })) as typeof fetch;
  try {
    await assert.rejects(fetchJwks('https://idp.example/jwks.json'), /redirected/);
  } finally {
    globalThis.fetch = prev;
  }
});

test('fetchJwks aborts as soon as the body exceeds 128 KiB', async () => {
  const prev = globalThis.fetch;
  // A chunked body without content-length that streams more than the cap.
  const big = new Uint8Array(129 * 1024).fill(0x41); // 129 KiB of 'A'
  globalThis.fetch = (async () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(big);
      controller.close();
    },
  }), { status: 200, headers: { 'content-type': 'application/json' } })) as typeof fetch;
  try {
    await assert.rejects(fetchJwks('https://idp.example/jwks.json'), /too large/);
  } finally {
    globalThis.fetch = prev;
  }
});

test('fetchJwks succeeds for a small valid document and strips null keys', async () => {
  const prev = globalThis.fetch;
  const body = JSON.stringify({ keys: [{ kty: 'EC', kid: 'k1' }, null, 'x'] });
  globalThis.fetch = (async () => new Response(body, { status: 200, headers: { 'content-type': 'application/json' } })) as typeof fetch;
  try {
    const jwks = await fetchJwks('https://idp.example/jwks.json');
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0]!.kid, 'k1');
  } finally {
    globalThis.fetch = prev;
  }
});