import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

const PREFIX = 'scrypt';
const KEYLEN = 32;

function derive(secret: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(secret.normalize('NFKC'), salt, KEYLEN, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

/** Salted scrypt hash in the form `scrypt$<salt>$<hash>` (base64url). */
export async function hashClientSecret(secret: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(secret, salt);
  return `${PREFIX}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

/** Constant-time check; any malformed stored value simply fails to verify. */
export async function verifyClientSecret(secret: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== PREFIX || !parts[1] || !parts[2]) return false;
  const salt = Buffer.from(parts[1], 'base64url');
  const expected = Buffer.from(parts[2], 'base64url');
  if (salt.length < 16 || expected.length !== KEYLEN) return false;
  const actual = await derive(secret, salt);
  return timingSafeEqual(actual, expected);
}
