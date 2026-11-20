import { X509Certificate, createHash, timingSafeEqual } from 'node:crypto';
import type { ClientRecord } from './ports.js';

/** RFC 8705 §2 client authentication methods. */
export const MTLS_AUTH_METHODS = ['tls_client_auth', 'self_signed_tls_client_auth'] as const;
export const isMtlsAuthMethod = (m: string | null | undefined): boolean => m === 'tls_client_auth' || m === 'self_signed_tls_client_auth';

/**
 * Trusted-proxy mTLS ingress. This server speaks plain HTTP; a TLS terminator
 * in front of it validates the client certificate handshake and forwards the
 * certificate in `certHeader`. The header is honoured only when the request
 * also carries `secretHeader` equal to the shared `proxySecret` (so a client
 * that reaches the app directly, or an untrusted hop, cannot inject a cert).
 * Anything else yields "no certificate" and every mTLS check fails closed.
 */
export interface MtlsConfig {
  proxySecret: string;
  /** Header carrying the client certificate (URL-encoded PEM or base64 DER). */
  certHeader: string;
  /** Optional PEM CA the app additionally requires `tls_client_auth` certs to be directly issued by. */
  caPem?: string | undefined;
}

export const MTLS_SECRET_HEADER = 'x-mtls-proxy-secret';
export const DEFAULT_CERT_HEADER = 'x-client-cert';

const safeEqual = (a: string, b: string): boolean => {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
};

function parseCert(raw: string): X509Certificate | null {
  try {
    const v = raw.trim();
    let decoded = v;
    if (v.includes('%')) decoded = decodeURIComponent(v);
    return decoded.startsWith('-----BEGIN') ? new X509Certificate(decoded) : new X509Certificate(Buffer.from(decoded, 'base64'));
  } catch {
    return null;
  }
}

/** The client certificate forwarded by the trusted proxy, or null (disabled, untrusted hop, missing, malformed). */
export function presentedCertificate(cfg: MtlsConfig | undefined, headers: Record<string, string | string[] | undefined>): X509Certificate | null {
  if (!cfg) return null;
  const secret = headers[MTLS_SECRET_HEADER];
  if (typeof secret !== 'string' || !safeEqual(secret, cfg.proxySecret)) return null;
  const raw = headers[cfg.certHeader];
  if (typeof raw !== 'string' || raw === '') return null; // duplicates arrive as arrays: reject
  return parseCert(raw);
}

/** RFC 8705 §3.1 `x5t#S256`: base64url SHA-256 of the DER certificate. */
export const certThumbprint = (cert: X509Certificate): string => createHash('sha256').update(cert.raw).digest('base64url');

/** Node prints subject RDNs one per line in encoded order; RFC 4514 is the reverse, comma-joined. */
function normalizeDn(s: string): string {
  return s.split(',').map((p) => p.trim()).filter(Boolean).join(',').toLowerCase();
}
function certDn(cert: X509Certificate): string {
  return normalizeDn(cert.subject.split('\n').reverse().join(','));
}

function withinValidity(cert: X509Certificate, nowSeconds: number): boolean {
  return Date.parse(cert.validFrom) <= nowSeconds * 1000 && nowSeconds * 1000 <= Date.parse(cert.validTo);
}

/** Does `cert` authenticate `client` under its registered RFC 8705 method? Every mismatch is just `false`. */
export function certificateAuthenticates(cfg: MtlsConfig, client: ClientRecord, cert: X509Certificate, nowSeconds: number): boolean {
  if (!withinValidity(cert, nowSeconds)) return false;
  if (client.tokenEndpointAuthMethod === 'self_signed_tls_client_auth') {
    // RFC 8705 §2.2.2: the certificate must match a key registered in the client's jwks (x5c).
    return (client.jwks?.keys ?? []).some((k) => {
      const x5c = k.x5c;
      return Array.isArray(x5c) && typeof x5c[0] === 'string' && Buffer.from(x5c[0], 'base64').equals(cert.raw);
    });
  }
  if (client.tokenEndpointAuthMethod !== 'tls_client_auth') return false;
  const m = client.mtls;
  // Exactly one subject identifier must be registered (RFC 8705 §2.1.2); otherwise fail closed.
  const identifiers = [m?.subjectDn, m?.sanDns].filter((v) => v !== undefined);
  if (identifiers.length !== 1) return false;
  if (cfg.caPem !== undefined) {
    try {
      const ca = new X509Certificate(cfg.caPem);
      if (cert.issuer !== ca.subject || !cert.verify(ca.publicKey) || !withinValidity(ca, nowSeconds)) return false;
    } catch {
      return false;
    }
  }
  if (m?.subjectDn !== undefined) return certDn(cert) === normalizeDn(m.subjectDn);
  const san = (cert.subjectAltName ?? '').split(',').map((s) => s.trim());
  return san.includes(`DNS:${m?.sanDns}`);
}
