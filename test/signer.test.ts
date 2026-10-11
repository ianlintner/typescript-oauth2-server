import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportPKCS8, generateKeyPair, jwtVerify, importJWK } from 'jose';
import { createJoseSigner } from '../src/signer.js';

test('signs a JWT verifiable with the published JWKS and carries kid', async () => {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const pem = await exportPKCS8(privateKey);
  const signer = await createJoseSigner(pem, 'k1');
  const jwt = await signer.sign({ sub: 'u1', iss: 'https://i.example' });
  const jwks = await signer.publicJwks();
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0]?.kid, 'k1');
  assert.equal('d' in (jwks.keys[0] ?? {}), false, 'private material must not be published');
  const pub = await importJWK(jwks.keys[0]!, 'ES256');
  const { payload, protectedHeader } = await jwtVerify(jwt, pub);
  assert.equal(payload.sub, 'u1');
  assert.equal(protectedHeader.kid, 'k1');
  assert.equal(protectedHeader.alg, 'ES256');
});

test('rejects an unparsable key', async () => {
  await assert.rejects(createJoseSigner('not a pem', 'k1'));
});

test('rejects an empty key id', async () => {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  await assert.rejects(createJoseSigner(await exportPKCS8(privateKey), ''), /kid/i);
});
