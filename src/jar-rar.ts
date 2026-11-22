import { importJWK, jwtVerify, type JWK } from 'jose';
import { OAuthError } from './errors.js';
import type { ClientRecord } from './ports.js';

export const REQUEST_OBJECT_SIGNING_ALGS = ['RS256', 'ES256'] as const;

/** RFC 9396 §2: authorization_details must be a JSON array of typed objects. */
export function parseAuthorizationDetails(raw: string | undefined, allowedTypes: readonly string[] | undefined): unknown[] | undefined {
  if (raw === undefined) return undefined;
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new OAuthError('invalid_authorization_details', 'authorization_details is not valid JSON'); }
  if (!Array.isArray(parsed) || parsed.length === 0 ||
      parsed.some((entry) => entry === null || typeof entry !== 'object' || Array.isArray(entry) ||
        typeof (entry as { type?: unknown }).type !== 'string' ||
        !allowedTypes?.includes((entry as { type: string }).type))) {
    throw new OAuthError('invalid_authorization_details', 'authorization_details contains an unsupported type');
  }
  return parsed;
}

function decodeJar(request: string): { header: Record<string, unknown>; claims: Record<string, unknown>; signature: string } {
  const parts = request.split('.');
  if (parts.length !== 3 || parts[0] === '' || parts[1] === '') {
    throw new OAuthError('invalid_request', 'JAR request is not a valid JWT (expected header.payload.signature)');
  }
  try {
    return {
      header: JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8')) as Record<string, unknown>,
      claims: JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>,
      signature: parts[2]!,
    };
  } catch {
    throw new OAuthError('invalid_request', 'JAR request is not a valid JWT (expected header.payload.signature)');
  }
}

const JAR_CLAIM_KEYS = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce',
  'code_challenge', 'code_challenge_method', 'authorization_details', 'claims', 'acr_values', 'resource',
  'prompt', 'max_age', 'login_hint'] as const;

/**
 * RFC 9101 §4: verify the request object and return its authorization parameters.
 * `alg=none` is accepted only from public clients exactly as in the Rust reference;
 * asymmetric JARs are verified against the client's registered inline JWKS.
 * HS256 cannot be mirrored: this port stores only a hash of the client secret and
 * never has the plaintext at the authorization endpoint.
 */
export async function verifyJar(request: string, client: ClientRecord, authorizationEndpoint: string, now: number): Promise<Record<string, string>> {
  const { header, claims, signature } = decodeJar(request);
  const alg = header.alg;
  const iss = claims.iss;
  if (typeof iss !== 'string' || iss !== client.clientId) {
    throw new OAuthError('invalid_request', "JAR 'iss' claim must equal client_id");
  }
  const exp = claims.exp;
  if (typeof exp !== 'number' || exp <= now) {
    throw new OAuthError('invalid_request', "JAR 'exp' claim is missing or expired");
  }
  // RFC 9101 §4.2: aud must identify the authorization endpoint, for every alg
  // (including alg=none, where no signature otherwise constrains the claims).
  const aud = claims.aud;
  const audiences = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud : [];
  if (!audiences.includes(authorizationEndpoint)) {
    throw new OAuthError('invalid_request', "JAR 'aud' claim must be the authorization endpoint");
  }

  if (alg === 'none') {
    if (signature !== '') throw new OAuthError('invalid_request', 'JAR alg=none must not carry a signature');
    if ((client.tokenEndpointAuthMethod ?? 'none') !== 'none' || client.clientSecretHash !== null) {
      throw new OAuthError('invalid_request', 'JAR alg=none is only accepted for public clients');
    }
  } else if ((REQUEST_OBJECT_SIGNING_ALGS as readonly string[]).includes(String(alg))) {
    if (!client.jwks?.keys?.length) throw new OAuthError('invalid_request', 'No matching kid in client JWKS for JAR');
    const kid = typeof header.kid === 'string' ? header.kid : undefined;
    const keys = client.jwks.keys.filter((k: JWK) =>
      (alg === 'ES256' ? k.kty === 'EC' : k.kty === 'RSA') &&
      k.use !== 'enc' && (k.alg === undefined || k.alg === alg) &&
      (kid === undefined || k.kid === kid));
    if (keys.length === 0) throw new OAuthError('invalid_request', 'No matching kid in client JWKS for JAR');
    let verified = false;
    for (const key of keys) {
      try {
        const keyLike = await importJWK(key, String(alg));
        await jwtVerify(request, keyLike, { algorithms: [String(alg)], audience: authorizationEndpoint, issuer: client.clientId, currentDate: new Date(now * 1000) });
        verified = true;
        break;
      } catch { /* try the next candidate key */ }
    }
    if (!verified) throw new OAuthError('invalid_request', 'JAR signature verification failed');
  } else {
    throw new OAuthError('invalid_request', `Unsupported alg '${String(alg)}' for JAR`);
  }

  const merged: Record<string, string> = {};
  for (const key of JAR_CLAIM_KEYS) {
    const value = claims[key];
    if (typeof value === 'string') merged[key] = value;
    else if (value !== undefined && key === 'authorization_details') merged[key] = JSON.stringify(value);
  }
  return merged;
}

/**
 * RFC 9101 §6.3: when a request object is used, the signed claims are the sole
 * source of authorization parameters. Only the outer client_id/redirect_uri
 * (needed to locate and validate the client) are carried over, and both must
 * agree with the signed values. Copying unsigned query parameters here would
 * let an attacker substitute PKCE challenges, escalate scope or inject RAR.
 */
export function mergeJarParams(params: URLSearchParams, jarClaims: Record<string, string>, client: ClientRecord): URLSearchParams {
  if (jarClaims.client_id !== undefined && jarClaims.client_id !== client.clientId) {
    throw new OAuthError('invalid_request', "JAR 'iss' claim must equal client_id");
  }
  const outerClientId = singleParam(params, 'client_id');
  if (outerClientId !== undefined && outerClientId !== client.clientId) {
    throw new OAuthError('invalid_request', 'JAR client_id does not match the outer request');
  }
  if (jarClaims.redirect_uri !== undefined && !client.redirectUris.includes(jarClaims.redirect_uri)) {
    throw new OAuthError('invalid_request', 'JAR redirect_uri is not registered for this client');
  }
  const outerRedirect = singleParam(params, 'redirect_uri');
  if (outerRedirect !== undefined && jarClaims.redirect_uri !== undefined && outerRedirect !== jarClaims.redirect_uri) {
    throw new OAuthError('invalid_request', 'JAR redirect_uri does not match the outer request');
  }
  const merged = new URLSearchParams();
  // client_id is always required by the caller; take it from the signed claim
  // when present so the value used downstream is the authenticated one.
  merged.set('client_id', jarClaims.client_id ?? outerClientId ?? client.clientId);
  if (jarClaims.redirect_uri !== undefined) merged.set('redirect_uri', jarClaims.redirect_uri);
  else if (outerRedirect !== undefined) merged.set('redirect_uri', outerRedirect);
  for (const [key, value] of Object.entries(jarClaims)) merged.set(key, value);
  return merged;
}

function singleParam(params: URLSearchParams, key: string): string | undefined {
  const values = params.getAll(key);
  return values.length === 1 ? values[0] : undefined;
}
