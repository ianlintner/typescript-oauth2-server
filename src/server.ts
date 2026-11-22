import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import { OAuthError, errorResponse } from './errors.js';
import { registerOAuthRoutes, type OAuthDeps } from './oauth.js';
import { registerExtensionRoutes, type RegistrationPolicy } from './device-grant.js';
import { registerAdminTrustedIssuerRoutes } from './admin-trusted-issuers.js';
import type { Clock, Random, Signer, Store } from './ports.js';
import { Metrics, ROUTES } from './metrics.js';
import { BOUNDED_REQUESTS_PER_SOURCE } from './rate-limit.js';

export interface Deps {
  store: Store;
  signer: Signer;
  clock: Clock;
  random: Random;
  issuer: string;
  authenticate?: OAuthDeps['authenticate'] | undefined;
  loginPath?: string | undefined;
  consent?: OAuthDeps['consent'] | undefined;
  authTime?: OAuthDeps['authTime'] | undefined;
  userClaims?: OAuthDeps['userClaims'] | undefined;
  endSession?: OAuthDeps['endSession'] | undefined;
  refreshTokenTtl?: number | undefined;
  /**
   * Per-source request bound on /oauth/userinfo and /oauth/logout, in requests per 60s.
   * `false` disables it; a positive integer overrides the default ({@link BOUNDED_REQUESTS_PER_SOURCE}).
   */
  rateLimit?: boolean | number | undefined;
  /** RFC 9449 §8 server-provided DPoP nonces; absent disables them. */
  dpopNonce?: OAuthDeps['dpopNonce'] | undefined;
  /** Whether RFC 7591 dynamic client registration is enabled. Defaults off. */
  dynamicRegistration?: boolean | undefined;
  /** Allow-lists (grant types, scopes, redirect schemes) and optional initial access token for registration. */
  registrationPolicy?: RegistrationPolicy | undefined;
  /** Metrics endpoint is opt-in and should only be bound to a trusted interface. */
  metrics?: Metrics | undefined;
  /**
   * Shared secret authorizing the admin trusted-issuer routes. Fail-closed:
   * leave unset and the admin routes are not registered.
   */
  adminToken?: string | undefined;
  /** Span boundary with fixed, secret-free names; caller controls exporter and sampling. */
  trace?: ((name: string) => () => void) | undefined;
}

export function buildServer(deps: Deps): FastifyInstance {
  const app = Fastify({ logger: false });

  if (deps.metrics || deps.trace) {
    const starts = new WeakMap<object, { time: number; finish: (() => void) | undefined }>();
    app.addHook('onRequest', (req, _reply, done) => {
      const operation = ROUTES[req.routeOptions.url ?? ''] ?? 'other';
      starts.set(req, { time: performance.now(), finish: deps.trace?.(`oauth.http.${operation}`) });
      done();
    });
    app.addHook('onResponse', (req, reply, done) => {
      const start = starts.get(req);
      if (start) {
        deps.metrics?.observe(req.method, req.routeOptions.url ?? '', reply.statusCode, (performance.now() - start.time) / 1000);
        start.finish?.();
      }
      done();
    });
  }

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

  if (deps.metrics) app.get('/metrics', async (_req, reply) => reply.type('text/plain; version=0.0.4').send(deps.metrics!.render()));

  // Per-source bound on the bounded OAuth routes: false disables, a positive integer overrides the
  // default, undefined uses the default. buildServer passes the resolved value through.
  const rateLimitEnabled = deps.rateLimit !== false;
  const rateLimitMax = typeof deps.rateLimit === 'number' ? deps.rateLimit : BOUNDED_REQUESTS_PER_SOURCE;

  registerOAuthRoutes(app, { ...deps, rateLimitMax });

  registerExtensionRoutes(app, {
    store: deps.store,
    signer: deps.signer,
    random: deps.random,
    clock: deps.clock,
    issuer: deps.issuer,
    authenticate: deps.authenticate,
    dynamicRegistration: deps.dynamicRegistration,
    registrationPolicy: deps.registrationPolicy,
    rateLimitEnabled,
    rateLimitMax,
  });

  registerAdminTrustedIssuerRoutes(app, {
    store: deps.store,
    random: deps.random,
    clock: deps.clock,
    adminToken: deps.adminToken,
  });

  return app;
}
