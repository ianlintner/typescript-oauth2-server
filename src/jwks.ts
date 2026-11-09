import type { JWK } from 'jose';
import { OAuthError } from './errors.js';
import type { Jwks } from './ports.js';

/** Algorithms accepted for RFC 7523 JWT-bearer assertions (§2.2). RS/ES/PS are the RFC 7518 asymmetric families. */
export const ASSERTION_ALGS = ['RS256', 'ES256', 'PS256'] as const;

const JWKS_TIMEOUT_MS = 10_000; // mirrors the reference's 10s fetch timeout
const JWKS_MAX_BYTES = 128 * 1024; // 128 KiB cap so a hostile endpoint cannot OOM the verifier

/** How long a fetched JWKS document is reused before the endpoint is re-hit. */
const JWKS_CACHE_TTL_MS = 300_000; // 5 minutes

interface CachedJwks {
  jwks: Jwks;
  expiresAt: number;
  /** A fetch currently in flight for this URI; concurrent requests share it. */
  inFlight: Promise<Jwks> | null;
}

const jwksCache = new Map<string, CachedJwks>();

/** Drop all cached documents (test seam). */
export function clearJwksCache(): void {
  jwksCache.clear();
}

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
    (k) => k !== null && typeof k === 'object' && k.kty === kty && k.use !== 'enc' && (k.alg === undefined || k.alg === alg) && (kid === undefined || k.kid === kid),
  ) as JWK[];
}

/**
 * Fetch a remote JWKS with the reference's guards: https-only is enforced at
 * registration; here we bound the timeout and the response size so a hostile
 * or misbehaving endpoint cannot stall or exhaust the verifier, and we reject
 * redirects so an accepted https URL cannot silently downgrade to http during
 * the fetch. Every failure collapses to a single opaque invalid_client (no
 * oracle about which issuer/URI).
 */
async function fetchJwksDocument(url: string): Promise<Jwks> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), JWKS_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
      redirect: 'manual',
    });
    // Reject any redirect rather than following an unvalidated destination:
    // an https URL's 3xx may point at an http (or otherwise untrusted) endpoint.
    if (res.status >= 300 && res.status < 400) throw new Error('JWKS endpoint redirected');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (!res.body) throw new Error('JWKS response has no body');
    // Read the body incrementally and abort as soon as the accumulated byte count
    // exceeds the cap, so a chunked or compressed response cannot allocate far
    // beyond the limit before rejection.
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > JWKS_MAX_BYTES) throw new Error('JWKS document too large');
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { bytes.set(c, offset); offset += c.byteLength; }
    const text = new TextDecoder().decode(bytes);
    const jwks = JSON.parse(text) as Jwks;
    if (!Array.isArray(jwks.keys)) throw new Error("JWKS missing 'keys' array");
    // Skip null/non-object entries so a malformed document cannot throw before
    // the token handler's per-key handling, or block subsequent valid keys.
    jwks.keys = jwks.keys.filter((k) => k !== null && typeof k === 'object');
    return jwks;
  } finally {
    clearTimeout(timer);
    // Abort the fetch on every early exit (oversized body, redirect, non-2xx,
    // parse/schema failure) so a rejected response cannot keep streaming with
    // no timeout left to terminate it. Aborting after a successful read is a
    // no-op on an already-complete response.
    controller.abort();
  }
}

/**
 * Fetch a remote JWKS with a bounded-TTL cache and shared in-flight fetches,
 * keyed by URI. A document within TTL is reused verbatim, so an unchanged
 * keyset keeps verifying during a JWKS endpoint outage or rate limit; a
 * document is refetched (and a concurrent burst coalesced onto one request)
 * once the TTL elapses or a rotation requires fresh keys.
 */
export async function fetchJwks(url: string, forceFresh = false): Promise<Jwks> {
  const now = Date.now();
  const cached = jwksCache.get(url);
  if (!forceFresh) {
    if (cached && cached.expiresAt > now) return cached.jwks;
    if (cached?.inFlight) return cached.inFlight;
  } else if (cached?.inFlight) {
    return cached.inFlight; // coalesce onto an in-flight refresh
  }

  const inFlight = fetchJwksDocument(url).then((jwks) => {
    jwksCache.set(url, { jwks, expiresAt: Date.now() + JWKS_CACHE_TTL_MS, inFlight: null });
    return jwks;
  });
  jwksCache.set(url, { jwks: cached?.jwks ?? { keys: [] }, expiresAt: cached?.expiresAt ?? 0, inFlight });
  try {
    return await inFlight;
  } catch (err) {
    // A failed refresh must not wedge the guard entry for concurrent callers;
    // drop it so the next request starts a clean fetch.
    if (jwksCache.get(url)?.inFlight === inFlight) jwksCache.delete(url);
    throw err;
  }
}