/**
 * Redirect URI matching (RFC 6749 §3.1.2.3 exact match plus the RFC 8252 §7.3
 * loopback exception).
 *
 * The exception is deliberately narrow: only the IP-literal loopback hosts
 * `127.0.0.1` and `[::1]` (RFC 8252 §8.3 forbids relying on the `localhost`
 * name) over `http`, and only the port is free. Scheme, host literal, path and
 * query must still equal the registration, and userinfo/fragment are refused.
 */
export const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]']);

/**
 * Validate a URI carried as OIDC logout client metadata. These endpoints are
 * http(s) only, absolute, and carry no fragment or credentials. Plain http is
 * the conformance/test allowance and, as for redirect URIs, is limited to an
 * IP-literal loopback host (RFC 8252 §8.3).
 * Returns a reason string when invalid, or null when valid.
 */
export function logoutUriError(value: unknown): string | null {
  if (typeof value !== 'string') return 'must be a string';
  let parsed: URL;
  try { parsed = new URL(value); } catch { return 'must be an absolute URI'; }
  if (parsed.hash !== '' || value.includes('#')) return 'must not contain a fragment';
  if (parsed.username !== '' || parsed.password !== '') return 'must not contain credentials';
  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
  if (scheme === 'https') return null;
  if (scheme !== 'http') return 'scheme must be http or https';
  return LOOPBACK_HOSTS.has(parsed.hostname) ? null : 'http is only allowed for 127.0.0.1 or [::1] loopback';
}

function parseLoopback(uri: string): URL | null {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' || !LOOPBACK_HOSTS.has(url.hostname)) return null;
  if (url.username !== '' || url.password !== '' || url.hash !== '') return null;
  return url;
}

export function redirectUriMatches(registered: readonly string[], requested: string): boolean {
  if (registered.includes(requested)) return true;
  const req = parseLoopback(requested);
  if (!req) return false;
  return registered.some((r) => {
    const reg = parseLoopback(r);
    return reg !== null && reg.hostname === req.hostname && reg.pathname === req.pathname && reg.search === req.search;
  });
}
