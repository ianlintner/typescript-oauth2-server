import { pathToFileURL } from 'node:url';
import { loadConfig } from './config.js';
import { cryptoRandom, systemClock } from './runtime.js';
import { buildServer } from './server.js';
import { createJoseSigner } from './signer.js';
import { SqliteStore } from './sqlite-store.js';

export interface RunningServer {
  address: string;
  close(): Promise<void>;
}

/** Validate config, then open storage and signer; any failure aborts before listening. */
export async function startServer(env: Record<string, string | undefined>): Promise<RunningServer> {
  const config = loadConfig(env);
  const signer = await createJoseSigner(config.signingKeyPem, config.signingKeyId);
  const store = new SqliteStore(config.databasePath);
  await store.init();
  const server = buildServer({ store, signer, clock: systemClock, random: cryptoRandom, issuer: config.issuer });
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
