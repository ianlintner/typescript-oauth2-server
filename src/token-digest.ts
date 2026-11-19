import { createHash } from 'node:crypto';

/**
 * Refresh-token storage format, version 1.
 *
 * The refresh token handed to the client is a high-entropy bearer value. It is
 * never stored: the store keys, `family` and `parentJti` hold only this
 * non-recoverable digest, so a copy of the database cannot be replayed as a
 * refresh token. Every lookup hashes the presented value first, therefore a
 * legacy (raw-value) row can never match a presented token.
 */
export const REFRESH_ID_PREFIX = 'rt1.';

/** Stored identifier for a presented/issued refresh-token value. */
export function refreshTokenId(token: string): string {
  return REFRESH_ID_PREFIX + createHash('sha256').update('refresh_token:v1\0').update(token).digest('base64url');
}

/** True when a stored identifier uses the current (digest) format. */
export function isDigestRefreshId(id: string): boolean {
  return id.startsWith(REFRESH_ID_PREFIX);
}
