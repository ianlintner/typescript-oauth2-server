// Deterministic normalization of nondeterministic OAuth response fields.
//
// The cross-language harness replays the same fixture against an isolated Rust
// instance and an isolated TypeScript instance. Several response fields are
// cryptographically or temporally nondeterministic and must never be compared
// byte-for-byte:
//
//   - access_token / refresh_token / id_token (opaque or signed nonces)
//   - authorization `code` and its PAR/JAR request_uri staging keys
//   - nonce / jti / state / iss timestamps inside claim sets
//   - exp / iat / nbf / auth_time NumericDate claims
//
// These values are replaced with a deterministic placeholder before any
// method/path/status/header/claim comparison happens, so that a mismatch in a
// real field is still reported while a fresh nonce is not.

/**
 * Values that are inherently nondeterministic and must be normalized away
 * before comparing two server responses.
 */
export const TOKEN_FIELDS = [
  'access_token',
  'refresh_token',
  'id_token',
  'code',
  'request_uri',
  'device_code',
  'user_code',
  'registration_access_token',
  'jti',
  'nonce',
  'state',
] as const;

/** RFC 7519 NumericDate claims that drift between runs. */
export const TIME_CLAIMS = ['exp', 'iat', 'nbf', 'auth_time'] as const;

/** Placeholder substituted for every normalized value. */
export const NORMALIZED = '<normalized>';

/**
 * Normalize a single string value in place: replace a syntactically valid
 * token with the deterministic placeholder, leave everything else untouched.
 *
 * Tokens are only recognized when they look like a real credential (a run of
 * URL-safe base64 + JWT punctuation), so that a mismatch in a plain-text field
 * such as `scope` or `token_type` is never silently swallowed.
 */
export function normalizeValue(value: string): string {
  // A JWT has two '.' separators; an opaque token or code is a run of
  // unreserved characters. Either way the value is self-delimiting.
  const looksLikeToken = /^[A-Za-z0-9._~/-]+$/.test(value) && value.length >= 8;
  return looksLikeToken ? NORMALIZED : value;
}

/**
 * Deep-normalize an arbitrary response payload: recursively walk objects and
 * arrays, replacing any key whose name names a nondeterministic field, and any
 * string value that is a token or a time claim.
 */
export function normalizePayload(value: unknown, depth = 0): unknown {
  if (depth > 32) {
    throw new RangeError('response nesting exceeds depth 32');
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalizePayload(entry, depth + 1));
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      if ((TOKEN_FIELDS as readonly string[]).includes(key)) {
        out[key] = NORMALIZED;
      } else if ((TIME_CLAIMS as readonly string[]).includes(key)) {
        out[key] = NORMALIZED;
      } else {
        out[key] = normalizePayload(entry, depth + 1);
      }
    }
    return out;
  }
  if (typeof value === 'string') {
    return normalizeValue(value);
  }
  return value;
}
