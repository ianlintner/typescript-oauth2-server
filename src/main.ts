import { pathToFileURL } from 'node:url';
import { loadConfig } from './config.js';
import { cryptoRandom, systemClock } from './runtime.js';
import { buildServer } from './server.js';
import { createJoseSigner } from './signer.js';
import { SqliteStore } from './sqlite-store.js';
import { assertSafeForConformance, conformanceModeFromEnv } from './sut/mode.js';
import { applySeed, assertProvisionable, loadSeed } from './sut/seed.js';
import { createTestRegistry, LOGIN_PATH, makeConsent, makeTestAuthenticate, registerTestLoginRoutes } from './sut/routes.js';

export interface RunningServer {
  address: string;
  close(): Promise<void>;
}

/**
 * Validate config, then open the signer and storage, then (optionally) apply
 * the conformance seed. Conformance mode is opt-in and fail-closed: any guard
 * failure, unreadable/invalid seed, or seed this server cannot provision aborts
 * startup before the process listens, so the seed is applied atomically and
 * completely — or not at all — before readiness.
 */
export async function startServer(env: Record<string, string | undefined>): Promise<RunningServer> {
  const config = loadConfig(env);
  const signer = await createJoseSigner(config.signingKeyPem, config.signingKeyId);
  const store = new SqliteStore(config.databasePath);
  await store.init();

  const mode = conformanceModeFromEnv(env);

  let registry: ReturnType<typeof createTestRegistry> | undefined;
  let consent: ((subject: string, clientId: string) => boolean) | undefined;
  if (mode.enabled) {
    assertSafeForConformance(env, config);
    const seed = await loadSeed(mode.seedPath!);
    assertProvisionable(seed, { issuer: config.issuer, signingKeyId: config.signingKeyId });
    await applySeed(seed, store);
    registry = createTestRegistry(seed.users);
    consent = makeConsent(seed.users);
  }

  const server = buildServer({
    store,
    signer,
    clock: systemClock,
    random: cryptoRandom,
    issuer: config.issuer,
    authenticate: registry ? makeTestAuthenticate(registry) : undefined,
    loginPath: registry ? LOGIN_PATH : undefined,
    consent,
  });
  if (registry) registerTestLoginRoutes(server, registry);

  return listen(server, store, config);
}

async function listen(
  server: import('fastify').FastifyInstance,
  store: SqliteStore,
  config: { host: string; port: number },
): Promise<RunningServer> {
  try {
    const address = await server.listen({ host: config.host, port: config.port });
    return {
      address,
      close: async () => {
        await server.close();
        await store.close();
      },
    };
  } catch (err) {
    await store.close();
    throw err;
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startServer(process.env).then(
    (s) => process.stdout.write(`listening on ${s.address}\n`),
    (e: unknown) => {
      process.stderr.write(`startup failed: ${e instanceof Error ? e.message : 'unknown error'}\n`);
      process.exit(1);
    },
  );
}
