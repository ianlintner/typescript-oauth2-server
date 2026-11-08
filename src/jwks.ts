import type { JWK } from 'jose';
import { OAuthError } from './errors.js';
import type { Jwks } from './ports.js';

/** Algorithms accepted for RFC 7523 JWT-bearer assertions (§2.2). RS/ES/PS are the RFC 7518 asymmetric families. */
export const ASSERTION_ALGS = ['RS256', 'ES256', 'PS256'] as const;

const JWKS_TIMEOUT_MS = 10_000; // mirrors the reference's 10s fetch timeout
const JWKS_MAX_BYTES = 128 * 1024; // 128 KiB cap so a hostile endpoint cannot OOM the verifier

/**
 * `sub` (subject claim) or `email` (email claim) — the two mappings the
 * reference permits. Drives which assertion claim becomes the token subject.
 */
export type SubjectMapping = 'sub' | 'email';
export const ALLOWED_SUBJECT_MAPPINGS: readonly SubjectMapping[] = ['sub', 'email'];

export function validateJwksUri(uri: string): void {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new OAuthError('invalid_request', 'jwks_uri must be a valid URL');
  }
  if (parsed.protocol !== 'https:') throw new OAuthError('invalid_request', 'jwks_uri must use the https scheme');
  if (parsed.hostname === '') throw new OAuthError('invalid_request', 'jwks_uri must include a host');
  if (parsed.hash !== '') throw new OAuthError('invalid_request', 'jwks_uri must not contain a fragment');
}

/** Candidate verification keys for a given alg/kid, filtered from a JWKS document. */
export function candidateKeys(jwks: Jwks | undefined, alg: string, kid: string | undefined): JWK[] {
  if (!jwks) return [];
  const kty = alg.startsWith('ES') ? 'EC' : 'RSA';
  return (jwks.keys ?? []).filter(
    (k) => k.kty === kty && k.use !== 'enc' && (k.alg === undefined || k.alg === alg) && (kid === undefined || k.kid === kid),
  ) as JWK[];
}

/**
 * Fetch a remote JWKS with the reference's guards: https-only is enforced at
 * registration; here we bound the timeout and the response size so a hostile
 * or misbehaving endpoint cannot stall or exhaust the verifier. Every failure
 * collapses to a single opaque invalid_client (no oracle about which issuer/URI).
 */
export async function fetchJwks(url: string): Promise<Jwks> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), JWKS_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
      redirect: 'follow',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const contentLength = Number(res.headers.get('content-length') ?? '0');
    if (contentLength > JWKS_MAX_BYTES) throw new Error('JWKS document too large');
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > JWKS_MAX_BYTES) throw new Error('JWKS document too large');
    const text = new TextDecoder().decode(buf);
    const jwks = JSON.parse(text) as Jwks;
    if (!Array.isArray(jwks.keys)) throw new Error("JWKS missing 'keys' array");
    return jwks;
  } finally {
    clearTimeout(timer);
  }
}