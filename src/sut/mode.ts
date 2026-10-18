import { ConfigError, type Config } from '../config.js';

export interface ConformanceMode {
  enabled: boolean;
  seedPath?: string;
}

/**
 * Decide whether conformance mode is on, from an env lookup. Returns the seed
 * path when on. An ambiguous OAUTH2_CONFORMANCE_MODE value or a missing seed
 * path is an error (fail closed). A seed path without the mode switch is
 * ignored: with the mode off nothing is exposed.
 */
export function conformanceModeFromEnv(env: Record<string, string | undefined>): ConformanceMode {
  const mode = env.OAUTH2_CONFORMANCE_MODE?.trim().toLowerCase();
  let enabled: boolean;
  switch (mode) {
    case undefined:
    case '':
    case '0':
    case 'false':
      enabled = false;
      break;
    case '1':
    case 'true':
      enabled = true;
      break;
    default:
      throw new ConfigError(
        `OAUTH2_CONFORMANCE_MODE=${JSON.stringify(mode)} is not a recognized value; use 1 to enable or unset it`,
      );
  }
  if (!enabled) return { enabled: false };
  const seedPath = env.OAUTH2_CONFORMANCE_SEED?.trim();
  if (!seedPath) throw new ConfigError('OAUTH2_CONFORMANCE_MODE=1 requires OAUTH2_CONFORMANCE_SEED to point at a seed file');
  return { enabled: true, seedPath };
}

const PROFILE_ENV_VARS = ['OAUTH2_ENV', 'OAUTH2_ENVIRONMENT', 'OAUTH2_PROFILE', 'APP_ENV', 'ENVIRONMENT', 'RUST_ENV', 'NODE_ENV'];

const NON_PRODUCTION_ENV_NAMES = ['test', 'testing', 'conformance', 'dev', 'development', 'local', 'ci'];

function inMemorySqlite(path: string): boolean {
  return path === ':memory:';
}

function isLoopback(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

/**
 * Abort-worthy reasons conformance mode must not run with this configuration.
 * Throws ConfigError (never warns and continues) when a profile variable names
 * anything other than a known non-production environment, the database is not
 * process-local in-memory SQLite, or the bind address is not loopback. The
 * profile allowlist is an allowlist so an unknown name fails closed.
 */
export function assertSafeForConformance(env: Record<string, string | undefined>, config: Config): void {
  for (const varName of PROFILE_ENV_VARS) {
    const value = env[varName];
    if (value === undefined) continue;
    const name = value.trim().toLowerCase();
    if (name !== '' && !NON_PRODUCTION_ENV_NAMES.includes(name)) {
      throw new ConfigError(
        `conformance mode refused: ${varName}=${JSON.stringify(value)} is not a known non-production ` +
          `environment (allowed: ${NON_PRODUCTION_ENV_NAMES.join(', ')})`,
      );
    }
  }
  if (!inMemorySqlite(config.databasePath)) {
    throw new ConfigError(
      'conformance mode refused: it requires an in-memory database so seeded test credentials are never persisted to a shared or production store',
    );
  }
  if (!isLoopback(config.host)) {
    throw new ConfigError('conformance mode refused: it requires a loopback bind address so test endpoints are never exposed on a shared interface');
  }
}
