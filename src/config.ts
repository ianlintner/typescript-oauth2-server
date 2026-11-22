import { isIP } from 'node:net';
import { DEFAULT_SWEEP_INTERVAL_SECONDS } from './sweep.js';

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export interface Config {
  env: 'development' | 'test' | 'production';
  issuer: string;
  host: string;
  port: number;
  databasePath: string;
  storage: 'sqlite' | 'postgres' | 'mongo';
  databaseUrl: string | null;
  metricsEnabled: boolean;
  sessionSecret: string;
  signingKeyPem: string;
  signingKeyId: string;
  adminToken: string | undefined;
  /** Seconds between expired-record sweeps; 0 disables the scheduled sweep. */
  sweepIntervalSeconds: number;
  /** RFC 8693 act-chain depth limit (levels). */
  maxDelegationDepth: number;
  /** Comma-separated proxy IPs/CIDRs whose X-Forwarded-For is trusted; undefined = trust none. */
  trustedProxies: string | undefined;
  /** RFC 9449 §8 DPoP nonces: 'off' (default) or 'required' (every proof must carry a server nonce). */
  dpopNonce: 'off' | 'required';
}

type Env = Record<string, string | undefined>;

const MIN_SECRET_LENGTH = 32;
const PLACEHOLDER = /change[-_ ]?me|example|secret|password|default|insecure/i;
// Well-known weak admin values the placeholder pattern does not already cover.
const WEAK_ADMIN_TOKEN = /^(admin|token|test|dev)/i;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

function required(env: Env, name: string): string {
  const v = env[name];
  if (v === undefined || v.trim() === '') throw new ConfigError(`${name} is required`);
  return v;
}

function parseIssuer(raw: string, production: boolean): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError('OAUTH2_ISSUER must be an absolute URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConfigError('OAUTH2_ISSUER must use https (or http on loopback outside production)');
  }
  if (url.search !== '' || url.hash !== '' || url.username !== '' || url.password !== '') {
    throw new ConfigError('OAUTH2_ISSUER must not contain query, fragment or credentials');
  }
  if (url.protocol === 'http:' && (production || !LOOPBACK.has(url.hostname))) {
    throw new ConfigError(
      production
        ? 'OAUTH2_ISSUER must use https in production'
        : 'OAUTH2_ISSUER must use https unless it is a loopback address',
    );
  }
  return raw;
}

function parsePort(raw: string | undefined): number {
  if (raw === undefined) return 8080;
  if (!/^\d+$/.test(raw)) throw new ConfigError('OAUTH2_PORT must be an integer');
  const port = Number(raw);
  if (port < 1 || port > 65535) throw new ConfigError('OAUTH2_PORT must be between 1 and 65535');
  return port;
}

/** Validate environment at startup. Fails closed; messages never include secret values. */
export function loadConfig(env: Env): Config {
  const mode = required(env, 'OAUTH2_ENV');
  if (mode !== 'development' && mode !== 'test' && mode !== 'production') {
    throw new ConfigError('OAUTH2_ENV must be one of development, test, production');
  }
  const production = mode === 'production';
  const issuer = parseIssuer(required(env, 'OAUTH2_ISSUER'), production);

  const sessionSecret = required(env, 'OAUTH2_SESSION_SECRET');
  if (sessionSecret.length < MIN_SECRET_LENGTH) {
    throw new ConfigError(`OAUTH2_SESSION_SECRET must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  if (production && PLACEHOLDER.test(sessionSecret)) {
    throw new ConfigError('OAUTH2_SESSION_SECRET looks like a placeholder; refusing to start in production');
  }

  const signingKeyPem = required(env, 'OAUTH2_SIGNING_KEY_PEM');
  const signingKeyId = required(env, 'OAUTH2_SIGNING_KEY_ID');

  const storage = env.OAUTH2_STORAGE ?? 'sqlite';
  if (storage !== 'sqlite' && storage !== 'postgres' && storage !== 'mongo') throw new ConfigError('OAUTH2_STORAGE must be sqlite, postgres or mongo');
  let databaseUrl: string | null = null;
  if (storage !== 'sqlite') {
    databaseUrl = required(env, 'OAUTH2_DATABASE_URL');
    let url: URL;
    try { url = new URL(databaseUrl); } catch { throw new ConfigError('OAUTH2_DATABASE_URL is invalid'); }
    if (storage === 'postgres' ? !['postgres:', 'postgresql:'].includes(url.protocol) : !['mongodb:', 'mongodb+srv:'].includes(url.protocol)) {
      throw new ConfigError('OAUTH2_DATABASE_URL has wrong scheme');
    }
  }
  const metricsEnabled = env.OAUTH2_METRICS_ENABLED === '1';
  if (env.OAUTH2_METRICS_ENABLED && !['0', '1'].includes(env.OAUTH2_METRICS_ENABLED)) throw new ConfigError('OAUTH2_METRICS_ENABLED must be 0 or 1');
  const host = env.OAUTH2_HOST?.trim() || '127.0.0.1';
  if (metricsEnabled && !LOOPBACK.has(host)) throw new ConfigError('OAUTH2_METRICS_ENABLED requires a loopback host');

  const adminToken = env.OAUTH2_ADMIN_TOKEN?.trim() || undefined;
  if (adminToken !== undefined) {
    if (PLACEHOLDER.test(adminToken) || WEAK_ADMIN_TOKEN.test(adminToken)) {
      throw new ConfigError('OAUTH2_ADMIN_TOKEN looks like a placeholder or well-known value');
    }
    if (adminToken.length < MIN_SECRET_LENGTH) {
      throw new ConfigError(`OAUTH2_ADMIN_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`);
    }
    if (!production && !LOOPBACK.has(host) && env.OAUTH2_ALLOW_ADMIN_ON_NON_LOOPBACK !== '1') {
      throw new ConfigError(
        'OAUTH2_ADMIN_TOKEN with a non-loopback OAUTH2_HOST requires OAUTH2_ALLOW_ADMIN_ON_NON_LOOPBACK=1 (only behind a trusted proxy)',
      );
    }
  }

  let maxDelegationDepth = 4;
  if (env.OAUTH2_MAX_DELEGATION_DEPTH !== undefined && env.OAUTH2_MAX_DELEGATION_DEPTH.trim() !== '') {
    const raw = env.OAUTH2_MAX_DELEGATION_DEPTH.trim();
    maxDelegationDepth = /^\d+$/.test(raw) ? Number(raw) : 0;
    if (maxDelegationDepth < 1 || maxDelegationDepth > 32) {
      throw new ConfigError('OAUTH2_MAX_DELEGATION_DEPTH must be an integer between 1 and 32');
    }
  }

  // Explicit proxy allow-list only (IP or CIDR); a blanket "trust everything" value is refused
  // because it would let any caller spoof X-Forwarded-For past the token-endpoint rate limiter.
  let trustedProxies: string | undefined;
  const rawProxies = env.OAUTH2_TRUSTED_PROXIES?.trim();
  if (rawProxies) {
    const entries = rawProxies.split(',').map((e) => e.trim());
    for (const e of entries) {
      const [addr = '', prefix, extra] = e.split('/');
      const family = isIP(addr);
      const maxPrefix = family === 4 ? 32 : 128;
      const prefixOk = prefix === undefined || (/^\d+$/.test(prefix) && Number(prefix) <= maxPrefix);
      const wildcard = prefix !== undefined && Number(prefix) === 0;
      if (family === 0 || extra !== undefined || !prefixOk || wildcard) {
        throw new ConfigError('OAUTH2_TRUSTED_PROXIES must be a comma-separated list of proxy IPs or CIDRs (not /0)');
      }
    }
    trustedProxies = entries.join(',');
  }

  const dpopNonce = env.OAUTH2_DPOP_NONCE ?? 'off';
  if (dpopNonce !== 'off' && dpopNonce !== 'required') throw new ConfigError('OAUTH2_DPOP_NONCE must be off or required');

  let databasePath = env.OAUTH2_DATABASE_PATH;
  if (production && storage === 'sqlite') {
    if (databasePath === undefined || databasePath.trim() === '' || databasePath === ':memory:') {
      throw new ConfigError('OAUTH2_DATABASE_PATH must be a persistent file path in production');
    }
  } else if (databasePath === undefined || databasePath.trim() === '') {
    databasePath = ':memory:';
  }

  let sweepIntervalSeconds = DEFAULT_SWEEP_INTERVAL_SECONDS;
  if (env.OAUTH2_SWEEP_INTERVAL_SECONDS !== undefined) {
    if (!/^\d{1,7}$/.test(env.OAUTH2_SWEEP_INTERVAL_SECONDS)) throw new ConfigError('OAUTH2_SWEEP_INTERVAL_SECONDS must be a non-negative integer');
    sweepIntervalSeconds = Number(env.OAUTH2_SWEEP_INTERVAL_SECONDS);
  }

  return {
    env: mode,
    issuer,
    host,
    port: parsePort(env.OAUTH2_PORT),
    databasePath: databasePath as string,
    storage,
    databaseUrl,
    metricsEnabled,
    sessionSecret,
    signingKeyPem,
    signingKeyId,
    adminToken,
    sweepIntervalSeconds,
    maxDelegationDepth,
    trustedProxies,
    dpopNonce,
  };
}
