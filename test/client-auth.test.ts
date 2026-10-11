import assert from 'node:assert/strict';
import { test } from 'node:test';
import { hashClientSecret, verifyClientSecret } from '../src/client-auth.js';

test('client secret hashes verify, are salted, and never contain the secret', async () => {
  const a = await hashClientSecret('s3cret-value');
  const b = await hashClientSecret('s3cret-value');
  assert.notEqual(a, b);
  assert.ok(!a.includes('s3cret-value'));
  assert.equal(await verifyClientSecret('s3cret-value', a), true);
  assert.equal(await verifyClientSecret('wrong', a), false);
});

test('malformed stored hashes never verify', async () => {
  for (const bad of ['', 'plain', 'scrypt$x', 'scrypt$1$2$3$4', 'md5$aa$bb']) {
    assert.equal(await verifyClientSecret('x', bad), false);
  }
});
