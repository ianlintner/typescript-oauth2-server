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
  sessionSecret: string;
  signingKeyPem: string;
  signingKeyId: string;
}

type Env = Record<string, string | undefined>;

const MIN_SECRET_LENGTH = 32;
const PLACEHOLDER = /change[-_ ]?me|example|secret|password|default|insecure/i;
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

  let databasePath = env.OAUTH2_DATABASE_PATH;
  if (production) {
    if (databasePath === undefined || databasePath.trim() === '' || databasePath === ':memory:') {
      throw new ConfigError('OAUTH2_DATABASE_PATH must be a persistent file path in production');
    }
  } else if (databasePath === undefined || databasePath.trim() === '') {
    databasePath = ':memory:';
  }

  return {
    env: mode,
    issuer,
    host: env.OAUTH2_HOST?.trim() || '127.0.0.1',
    port: parsePort(env.OAUTH2_PORT),
    databasePath: databasePath as string,
    sessionSecret,
    signingKeyPem,
    signingKeyId,
  };
}
