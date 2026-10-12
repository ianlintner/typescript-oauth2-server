// Conformance responder: an in-memory TypeScript server for cross-language runs.
//
// It seeds the clients the fixtures name and supplies a fixed authenticated
// resource owner so /oauth/authorize can issue a code without login UI. Test
// infrastructure only: ephemeral signing key and database, loopback bind, and
// it refuses to start when OAUTH2_ENV=production.
//
// Usage: node src/conformance/serve.ts [--port 3000]   (prints "listening on <url>")

import { generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:net';
import { pathToFileURL } from 'node:url';
import { hashClientSecret } from '../client-auth.js';
import { cryptoRandom, systemClock } from '../runtime.js';
import { buildServer } from '../server.js';
import { createJoseSigner } from '../signer.js';
import { SqliteStore } from '../sqlite-store.js';

export const CONFORMANCE_REDIRECT_URI = 'https://client.example/callback';
export const CONFORMANCE_PUBLIC_CLIENT = 'client-a';
export const CONFORMANCE_CONFIDENTIAL_CLIENT = 'client-conf';
export const CONFORMANCE_CLIENT_SECRET = 'conformance-client-secret';
export const CONFORMANCE_SUBJECT = 'conformance-user';

const HOST = '127.0.0.1';

export interface ConformanceServer {
  address: string;
  close(): Promise<void>;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, HOST, () => {
      const addr = probe.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      probe.close(() => resolve(port));
    });
  });
}

export async function startConformanceServer(
  opts: { port?: number; env?: Record<string, string | undefined> } = {},
): Promise<ConformanceServer> {
  if ((opts.env ?? process.env).OAUTH2_ENV === 'production') {
    throw new Error('the conformance server must not run with OAUTH2_ENV=production');
  }
  const port = opts.port !== undefined && opts.port !== 0 ? opts.port : await freePort();
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const signer = await createJoseSigner(pem, 'conformance-key');
  const store = new SqliteStore(':memory:');
  await store.init();
  const base = {
    redirectUris: [CONFORMANCE_REDIRECT_URI],
    grantTypes: ['authorization_code'],
    scopes: ['read', 'write'],
    enabled: true,
  };
  await store.saveClient({ ...base, clientId: CONFORMANCE_PUBLIC_CLIENT, clientSecretHash: null });
  await store.saveClient({
    ...base,
    clientId: CONFORMANCE_CONFIDENTIAL_CLIENT,
    clientSecretHash: await hashClientSecret(CONFORMANCE_CLIENT_SECRET),
  });
  const app = buildServer({
    store,
    signer,
    clock: systemClock,
    random: cryptoRandom,
    issuer: `http://${HOST}:${port}`,
    authenticate: async () => CONFORMANCE_SUBJECT,
  });
  try {
    const address = await app.listen({ host: HOST, port });
    return {
      address,
      close: async () => {
        await app.close();
        await store.close();
      },
    };
  } catch (err) {
    await store.close();
    throw err;
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const i = process.argv.indexOf('--port');
  const port = i >= 0 ? Number(process.argv[i + 1]) : 0;
  startConformanceServer({ port }).then(
    (s) => process.stdout.write(`listening on ${s.address}\n`),
    (e: unknown) => {
      process.stderr.write(`startup failed: ${e instanceof Error ? e.message : 'unknown error'}\n`);
      process.exit(1);
    },
  );
}
