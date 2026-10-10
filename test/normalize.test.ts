import assert from 'node:assert/strict';
import test from 'node:test';
import {
  NORMALIZED,
  normalizePayload,
  normalizeValue,
} from '../src/conformance/normalize.js';

test('normalizes a JWT into a deterministic placeholder', () => {
  assert.equal(
    normalizeValue('eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signature'),
    NORMALIZED,
  );
});

test('normalizes an opaque access token', () => {
  assert.equal(normalizeValue('kWJthG45ubWfYc8ZgN7aQdV9pJr3XoLm'), NORMALIZED);
});

test('leaves a plain-text scope value untouched', () => {
  assert.equal(normalizeValue('openid profile email'), 'openid profile email');
});

test('leaves a short non-token value untouched', () => {
  assert.equal(normalizeValue('Bearer'), 'Bearer');
});

test('normalizes a named token field in an object', () => {
  const result = normalizePayload({ access_token: 'any-opaque-blah' });
  assert.deepEqual(result, { access_token: NORMALIZED });
});

test('normalizes time claims exp iat nbf auth_time in an object', () => {
  const result = normalizePayload({
    exp: 1730000000,
    iat: 1729990000,
    sub: 'user1',
  });
  assert.deepEqual(result, { exp: NORMALIZED, iat: NORMALIZED, sub: 'user1' });
});

test('recursively normalizes nested token objects and arrays', () => {
  const result = normalizePayload({
    access_token: 'tok-A',
    claims: { jti: 'jti-A', aud: 'aud-A', roles: ['a', 'b'] },
  });
  assert.deepEqual(result, {
    access_token: NORMALIZED,
    claims: { jti: NORMALIZED, aud: 'aud-A', roles: ['a', 'b'] },
  });
});

test('rejects payload nesting deeper than 32 levels', () => {
  // Build a deeply nested object.
  let deep: unknown = 'leaf';
  for (let i = 0; i < 40; i += 1) deep = { nested: deep };
  assert.throws(() => normalizePayload(deep), /depth/);
});
