import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import { OAuthError, errorResponse } from './errors.js';
import { registerOAuthRoutes, type OAuthDeps } from './oauth.js';
import type { Clock, Random, Signer, Store } from './ports.js';

export interface Deps {
  store: Store;
  signer: Signer;
  clock: Clock;
  random: Random;
  issuer: string;
  authenticate?: OAuthDeps['authenticate'] | undefined;
}

export function buildServer(deps: Deps): FastifyInstance {
  const app = Fastify({ logger: false });

  app.addHook('onRequest', async (_req, reply) => {
    reply.header('cache-control', 'no-store');
    reply.removeHeader('x-powered-by');
  });

  const fail = (reply: FastifyReply, err: unknown, status?: number) => {
    const r = errorResponse(err);
    return reply.status(status ?? r.status).headers(r.headers).send(r.body);
  };

  app.setNotFoundHandler((_req, reply) => fail(reply, new OAuthError('invalid_request', 'unknown endpoint'), 404));

  app.setErrorHandler((err: unknown, _req, reply) => {
    const code = (err as { statusCode?: number }).statusCode;
    if (typeof code === 'number' && code >= 400 && code < 500) {
      return fail(reply, new OAuthError('invalid_request', 'malformed request'), code);
    }
    return fail(reply, err);
  });

  app.get('/health', async (_req, reply) => {
    try {
      await deps.store.healthcheck();
      return { status: 'ok' };
    } catch {
      return reply.status(503).send({ status: 'unavailable' });
    }
  });

  registerOAuthRoutes(app, deps);

  return app;
}
