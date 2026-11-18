import { pathToFileURL } from 'node:url';
import type { Store } from './ports.js';
import { REFRESH_ID_PREFIX } from './token-digest.js';

export interface CutoverReport {
  /** Storage format this build writes and accepts. */
  format: string;
  /** Legacy (raw-identifier) refresh-token rows found before any change. */
  legacyFound: number;
  /** Rows deleted (0 unless `apply`). */
  purged: number;
  applied: boolean;
}

/**
 * Operator-initiated refresh-token cutover. Never invoked on server startup.
 * Dry-run by default; deletion happens only with `apply: true`. Legacy rows are
 * already unusable by this build (lookups hash the presented value and so never
 * match a raw stored identifier); purging removes the stale plaintext values.
 */
export async function runRefreshCutover(store: Store, opts: { apply: boolean }): Promise<CutoverReport> {
  const legacyFound = await store.countLegacyRefreshTokens();
  const purged = opts.apply && legacyFound > 0 ? await store.purgeLegacyRefreshTokens() : 0;
  return { format: `${REFRESH_ID_PREFIX}sha256`, legacyFound, purged, applied: opts.apply };
}

async function storeFromEnv(env: Record<string, string | undefined>): Promise<Store> {
  const kind = env.OAUTH2_STORAGE ?? 'sqlite';
  if (kind === 'sqlite') {
    const path = env.OAUTH2_DATABASE_PATH;
    if (!path || path === ':memory:') throw new Error('OAUTH2_DATABASE_PATH must name the database file to operate on');
    return new (await import('./sqlite-store.js')).SqliteStore(path);
  }
  const url = env.OAUTH2_DATABASE_URL;
  if (!url) throw new Error('OAUTH2_DATABASE_URL is required');
  if (kind === 'postgres') return new (await import('./postgres-store.js')).PostgresStore(url);
  if (kind === 'mongo') return new (await import('./mongo-store.js')).MongoStore(url);
  throw new Error('OAUTH2_STORAGE must be sqlite, postgres or mongo');
}

async function main(argv: string[], env: Record<string, string | undefined>): Promise<void> {
  const apply = argv.includes('--apply');
  if (argv.some((a) => a !== '--apply')) throw new Error('usage: refresh-cutover [--apply]   (dry-run unless --apply)');
  const store = await storeFromEnv(env);
  await store.init();
  try {
    const r = await runRefreshCutover(store, { apply });
    process.stdout.write(`${JSON.stringify(r)}\n`);
    if (!apply && r.legacyFound > 0) process.stdout.write('dry run: re-run with --apply to delete the legacy rows\n');
  } finally {
    await store.close();
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2), process.env).catch((e: unknown) => {
    process.stderr.write(`cutover failed: ${e instanceof Error ? e.message : 'unknown error'}\n`);
    process.exit(1);
  });
}
