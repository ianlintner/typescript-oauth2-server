import { createCipheriv, createDecipheriv, createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

const PREFIX = 'scrypt';
const KEYLEN = 32;
/** Prefix on AES-256-GCM sealed symmetric client key material. Never log or expose the payload. */
const SEALED_PREFIX = 'aesgcm-v1';
/** Domain separator binding derived server keys to this purpose (RFC 7523 HMAC client secrets). */
const HMAC_KEY_CONTEXT = 'client-hmac-key:v1';

/**
 * Derive the server-side key encryption key from an operator secret. Uses the same
 * domain-separated HMAC pattern as DPoP nonce keys, so one session secret can serve
 * multiple independent purposes.
 */
export function deriveClientHmacKey(secret: string): Buffer {
  return createHmac('sha256', secret).update(HMAC_KEY_CONTEXT).digest();
}

/**
 * Seal a client's symmetric secret for at-rest storage. The AES-256-GCM AAD binds
 * the blob to a client id, so a sealed value cannot be copied to another client.
 * The returned string contains only nonces, ciphertext and the auth tag: a database
 * copy without the server key cannot recover the secret.
 */
export async function sealClientHmacSecret(secret: string, clientId: string, key: Buffer): Promise<string> {
  if (key.length < KEYLEN) throw new Error('client HMAC key-encryption key is too short');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(`client:${clientId}:${HMAC_KEY_CONTEXT}`, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return [SEALED_PREFIX, iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ciphertext.toString('base64url')].join('$');
}

/**
 * Unseal symmetric client key material. Returns null for any malformed blob, wrong
 * client id or wrong server key; callers must treat null as "HMAC unavailable" rather
 * than verifying under an empty or attacker-controlled key.
 */
export async function unsealClientHmacSecret(stored: string | null | undefined, clientId: string, key: Buffer): Promise<string | null> {
  if (typeof stored !== 'string' || stored === '' || key.length < KEYLEN) return null;
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== SEALED_PREFIX) return null;
  try {
    const iv = Buffer.from(parts[1]!, 'base64url');
    const tag = Buffer.from(parts[2]!, 'base64url');
    const ciphertext = Buffer.from(parts[3]!, 'base64url');
    if (iv.length !== 12 || tag.length !== 16 || ciphertext.length === 0) return null;
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(`client:${clientId}:${HMAC_KEY_CONTEXT}`, 'utf8'));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plain.toString('utf8');
  } catch {
    return null;
  }
}

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
