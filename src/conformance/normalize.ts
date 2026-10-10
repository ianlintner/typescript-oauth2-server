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
] as const;

/** RFC 7519 NumericDate claims that drift between runs. */
export const TIME_CLAIMS = ['exp', 'iat', 'nbf', 'auth_time'] as const;

/** Placeholder substituted for every normalized value. */
export const NORMALIZED = '<normalized>';

/** Without a field name, strings carry no evidence of nondeterminism. */
export function normalizeValue(value: string): string {
  return value;
}

/** Normalize only explicitly named token and timestamp fields. */
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
