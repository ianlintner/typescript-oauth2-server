import { createHash, timingSafeEqual } from 'node:crypto';
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { OAuthError } from './errors.js';
import type { Clock, Store } from './ports.js';

/** Signature algorithms accepted for DPoP proofs and advertised in metadata (RFC 9449 §5.1). */
export const DPOP_SIGNING_ALGS = ['ES256'] as const;
/** Oldest acceptable proof age, seconds (RFC 9449 §11.1 acceptance window). */
export const DPOP_MAX_AGE_SECONDS = 300;
/** Tolerated forward clock skew, seconds. */
export const DPOP_FUTURE_SKEW_SECONDS = 60;

// Parameters that must never appear in a public `jwk` header (RFC 9449 §4.2 item 7).
const PRIVATE_JWK_PARAMS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

export interface DpopCheck {
  /** Expected HTTP method (htm). */
  method: string;
  /** Absolute request URI built from the configured issuer, never from request headers (htu). */
  url: string;
  /** Present for protected-resource requests: the presented access token, which `ath` must hash. */
  accessToken?: string | undefined;
}

export interface DpopDeps {
  store: Store;
  clock: Clock;
}

const invalid = (why: string): OAuthError => new OAuthError('invalid_dpop_proof', why);

/** htu comparison form: scheme, authority and path only (RFC 9449 §4.2, RFC 3986 §6.2.2/6.2.3 normalisation via URL). */
export function htuForm(raw: string): string {
  const u = new URL(raw);
  return `${u.origin}${u.pathname}`;
}

/** base64url SHA-256 of the access token, the `ath` claim value (RFC 9449 §4.2). */
export const accessTokenHash = (token: string): string => createHash('sha256').update(token).digest('base64url');

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/**
 * Validate a DPoP proof (RFC 9449 §4.3) and record its jti so it cannot be
 * replayed (§11.1). The jti store is the injected Store, so enforcement is
 * shared across processes and survives restarts. Returns the JWK SHA-256
 * thumbprint of the proof key. The jti is consumed only after every other
 * check passes, so a malformed proof never burns a legitimate identifier.
 */
export async function validateDpopProof(deps: DpopDeps, header: string | string[] | undefined, check: DpopCheck): Promise<{ jkt: string }> {
  if (header === undefined) throw invalid('DPoP proof is required');
  // Duplicate headers arrive as an array or comma-joined; a compact JWS contains neither.
  if (Array.isArray(header) || header.includes(',') || header.trim() === '') throw invalid('exactly one DPoP proof is required');

  let jwk: JWK;
  try {
    const h = decodeProtectedHeader(header);
    if (h.typ !== 'dpop+jwt') throw invalid('typ must be dpop+jwt');
    if (!(DPOP_SIGNING_ALGS as readonly unknown[]).includes(h.alg)) throw invalid('unsupported proof algorithm');
    if (typeof h.jwk !== 'object' || h.jwk === null) throw invalid('jwk header is required');
    jwk = h.jwk as JWK;
  } catch (e) {
    throw e instanceof OAuthError ? e : invalid('malformed proof');
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw invalid('jwk is not a usable ES256 public key');
  for (const p of PRIVATE_JWK_PARAMS) if (p in jwk) throw invalid('jwk must be a public key');

  const now = deps.clock.now();
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(jwk, 'ES256');
    // exp/iat are not enforced by jose here; DPoP defines its own iat window below.
    payload = (await jwtVerify(header, key, { algorithms: [...DPOP_SIGNING_ALGS], currentDate: new Date(0) })).payload as Record<string, unknown>;
  } catch {
    throw invalid('proof signature is invalid');
  }

  const { jti, htm, htu, iat, ath } = payload;
  if (typeof jti !== 'string' || jti === '') throw invalid('jti is required');
  if (typeof htm !== 'string' || htm !== check.method) throw invalid('htm does not match the request method');
  let htuOk = false;
  try {
    htuOk = typeof htu === 'string' && htuForm(htu) === htuForm(check.url);
  } catch {
    htuOk = false;
  }
  if (!htuOk) throw invalid('htu does not match the request URI');
  if (typeof iat !== 'number' || !Number.isFinite(iat)) throw invalid('iat is required');
  if (iat < now - DPOP_MAX_AGE_SECONDS || iat > now + DPOP_FUTURE_SKEW_SECONDS) throw invalid('proof iat is outside the acceptance window');
  if (check.accessToken !== undefined) {
    if (typeof ath !== 'string') throw invalid('ath is required for protected-resource requests');
    if (!safeEqual(ath, accessTokenHash(check.accessToken))) throw invalid('ath does not match the access token');
  }

  const jkt = await calculateJwkThumbprint(jwk);
  // Scope jti per proof key so one client cannot exhaust or probe another's identifiers.
  const key = createHash('sha256').update(`${jkt}\n${jti}`).digest('base64url');
  const fresh = await deps.store.consumeDpopJti(key, iat + DPOP_MAX_AGE_SECONDS + 1, now);
  if (!fresh) throw invalid('proof has already been used');
  return { jkt };
}
