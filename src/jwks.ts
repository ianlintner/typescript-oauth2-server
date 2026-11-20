import type { JWK } from 'jose';
import { OAuthError } from './errors.js';
import type { Jwks } from './ports.js';
import { assertPublicHost, isIpLiteral, isPublicAddress } from './net-guard.js';

export { setNetGuard as setJwksNetGuard } from './net-guard.js';

/** Algorithms accepted for RFC 7523 JWT-bearer assertions (§2.2). RS/ES/PS are the RFC 7518 asymmetric families. */
export const ASSERTION_ALGS = ['RS256', 'ES256', 'PS256'] as const;

const JWKS_TIMEOUT_MS = 10_000; // mirrors the reference's 10s fetch timeout
const JWKS_MAX_BYTES = 128 * 1024; // 128 KiB cap so a hostile endpoint cannot OOM the verifier

/** How long a fetched JWKS document is reused before the endpoint is re-hit. */
const JWKS_CACHE_TTL_MS = 300_000; // 5 minutes

/**
 * Minimum age of a cached document before a forced refresh (`forceFresh`) is
 * honoured. Repeated forced refreshes for a document fetched moments ago are
 * served from cache instead, so an unauthenticated client cannot turn the
 * token endpoint into a refresh-hammering amplifier against a slow JWKS host.
 */
const JWKS_FORCE_FRESH_COOLDOWN_MS = 5_000; // 5 seconds

/**
 * Longest a document may keep verifying after its last successful fetch while
 * refreshes are failing. Beyond this a removed issuer key must stop being trusted.
 */
const JWKS_STALE_MAX_AGE_MS = 24 * 3_600_000; // 24 hours

interface CachedJwks {
  jwks: Jwks;
  expiresAt: number;
  /** Wall-clock instant the document was last successfully fetched. */
  fetchedAt: number;
  /** A fetch currently in flight for this URI; concurrent requests share it. */
  inFlight: Promise<Jwks> | null;
}

const jwksCache = new Map<string, CachedJwks>();

/** Most recent fetch attempt per URI (start time and outcome); drives the cooldown for failures too. */
const lastAttempt = new Map<string, { at: number; ok: boolean }>();

/** The last good document for `url` if it is within the stale grace period, else undefined. */
function usableStale(url: string): Jwks | undefined {
  const entry = jwksCache.get(url);
  if (!entry || entry.fetchedAt === 0 || (entry.jwks.keys?.length ?? 0) === 0) return undefined;
  return jwksNow() - entry.fetchedAt <= JWKS_STALE_MAX_AGE_MS ? entry.jwks : undefined;
}

/** Injectable clock so tests can advance time without sleeping (see `__setJwksClock`). */
let jwksNow: () => number = () => Date.now();

/** Drop all cached documents and reset the injected clock (test seam). */
export function clearJwksCache(): void {
  jwksCache.clear();
  lastAttempt.clear();
  jwksNow = () => Date.now();
}

/** Override the cache clock (test seam); reset via `clearJwksCache`. @internal */
export function __setJwksClock(fn: () => number): void {
  jwksNow = fn;
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
  // Literal addresses can be judged now; names are checked against their resolved addresses at fetch time.
  if (isIpLiteral(parsed.hostname) && !isPublicAddress(parsed.hostname)) {
    throw new OAuthError('invalid_request', 'jwks_uri must not use a non-public address');
  }
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
    // Judge the addresses the host resolves to now, immediately before connecting.
    await assertPublicHost(new URL(url).hostname);
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
 * keyed by URI. A document within TTL is reused verbatim. Past the TTL it is
 * refetched (a concurrent burst coalesced onto one request); if that refresh
 * fails, every non-forced caller -- the initiator and any joiner alike -- is
 * served the last good document for up to `JWKS_STALE_MAX_AGE_MS` after its
 * last successful fetch, after which verification fails closed. Forced
 * (rotation-driven) callers never fall back to stale keys.
 *
 * Attempts, successful or not, are rate-limited per URI by the cooldown, so a
 * dead endpoint is probed at most once per window rather than on every request.
 */
export async function fetchJwks(url: string, forceFresh = false): Promise<Jwks> {
  const nowMs = jwksNow();
  const cached = jwksCache.get(url);
  if (!forceFresh && cached && cached.expiresAt > nowMs) return cached.jwks;

  let inFlight = cached?.inFlight ?? null;
  if (!inFlight) {
    const last = lastAttempt.get(url);
    if (last !== undefined && nowMs - last.at < JWKS_FORCE_FRESH_COOLDOWN_MS && (forceFresh || !last.ok)) {
      // Within the cooldown of the previous attempt: do not hit the endpoint.
      if (!forceFresh) {
        const stale = usableStale(url);
        if (stale) return stale;
        throw new Error('JWKS refresh in cooldown after a failed attempt');
      }
      if (cached && cached.fetchedAt !== 0 && (cached.expiresAt > nowMs || usableStale(url))) return cached.jwks;
      throw new Error('JWKS refresh rate-limited');
    }
    const startedAt = nowMs;
    inFlight = fetchJwksDocument(url).then(
      (jwks) => {
        const fetchedAt = jwksNow();
        lastAttempt.set(url, { at: startedAt, ok: true });
        jwksCache.set(url, { jwks, expiresAt: fetchedAt + JWKS_CACHE_TTL_MS, fetchedAt, inFlight: null });
        return jwks;
      },
      (err: unknown) => {
        lastAttempt.set(url, { at: startedAt, ok: false });
        // Clear only the in-flight promise, keeping the last good document so
        // non-forced callers can fall back to it within the stale bound.
        const entry = jwksCache.get(url);
        if (entry && entry.fetchedAt !== 0) jwksCache.set(url, { ...entry, inFlight: null });
        else jwksCache.delete(url);
        throw err;
      },
    );
    jwksCache.set(url, { jwks: cached?.jwks ?? { keys: [] }, expiresAt: cached?.expiresAt ?? 0, fetchedAt: cached?.fetchedAt ?? 0, inFlight });
  }
  try {
    return await inFlight;
  } catch (err) {
    if (!forceFresh) {
      const stale = usableStale(url);
      if (stale) return stale;
    }
    throw err;
  }
}
