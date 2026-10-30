/**
 * Redirect URI matching (RFC 6749 §3.1.2.3 exact match plus the RFC 8252 §7.3
 * loopback exception).
 *
 * The exception is deliberately narrow: only the IP-literal loopback hosts
 * `127.0.0.1` and `[::1]` (RFC 8252 §8.3 forbids relying on the `localhost`
 * name) over `http`, and only the port is free. Scheme, host literal, path and
 * query must still equal the registration, and userinfo/fragment are refused.
 */
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]']);

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
