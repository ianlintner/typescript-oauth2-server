import { X509Certificate } from 'node:crypto';
import { DEFAULT_CERT_HEADER, type MtlsConfig } from './mtls.js';

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
  /** RFC 8705 trusted-proxy mTLS ingress; undefined = mTLS disabled (fail closed). */
  mtls: MtlsConfig | undefined;
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

  let mtls: MtlsConfig | undefined;
  const proxySecret = env.OAUTH2_MTLS_PROXY_SECRET?.trim();
  if (proxySecret) {
    if (proxySecret.length < MIN_SECRET_LENGTH) throw new ConfigError(`OAUTH2_MTLS_PROXY_SECRET must be at least ${MIN_SECRET_LENGTH} characters`);
    if (PLACEHOLDER.test(proxySecret)) throw new ConfigError('OAUTH2_MTLS_PROXY_SECRET looks like a placeholder');
    const certHeader = (env.OAUTH2_MTLS_CERT_HEADER?.trim() || DEFAULT_CERT_HEADER).toLowerCase();
    if (!/^[a-z0-9-]+$/.test(certHeader) || certHeader === 'authorization') throw new ConfigError('OAUTH2_MTLS_CERT_HEADER is not a valid header name');
    const caPem = env.OAUTH2_MTLS_CA_PEM?.trim() || undefined;
    if (caPem !== undefined) {
      try { new X509Certificate(caPem); } catch { throw new ConfigError('OAUTH2_MTLS_CA_PEM is not a valid PEM certificate'); }
    }
    mtls = { proxySecret, certHeader, caPem };
  } else if (env.OAUTH2_MTLS_CERT_HEADER || env.OAUTH2_MTLS_CA_PEM) {
    throw new ConfigError('OAUTH2_MTLS_CERT_HEADER / OAUTH2_MTLS_CA_PEM require OAUTH2_MTLS_PROXY_SECRET');
  }

  let databasePath = env.OAUTH2_DATABASE_PATH;
  if (production && storage === 'sqlite') {
    if (databasePath === undefined || databasePath.trim() === '' || databasePath === ':memory:') {
      throw new ConfigError('OAUTH2_DATABASE_PATH must be a persistent file path in production');
    }
  } else if (databasePath === undefined || databasePath.trim() === '') {
    databasePath = ':memory:';
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
    mtls,
  };
}
