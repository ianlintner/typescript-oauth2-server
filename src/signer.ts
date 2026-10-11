import { SignJWT, exportJWK, importPKCS8 } from 'jose';
import type { Jwks, Signer } from './ports.js';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const ALG = 'ES256';

export async function createJoseSigner(pem: string, kid: string): Promise<Signer> {
  if (kid.trim() === '') throw new Error('signing key kid must be nonempty');
  const privateKey = await importPKCS8(pem, ALG);
  const publicJwk = await exportJWK(createPublicKey(createPrivateKey(pem)));
  const jwks: Jwks = { keys: [{ ...publicJwk, kid, alg: ALG, use: 'sig' }] };
  return {
    sign: (claims) => new SignJWT(claims).setProtectedHeader({ alg: ALG, kid, typ: 'JWT' }).sign(privateKey),
    publicJwks: async () => jwks,
  };
}
