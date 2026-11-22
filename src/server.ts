import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import { OAuthError, errorResponse } from './errors.js';
import { registerOAuthRoutes, type OAuthDeps } from './oauth.js';
import { registerExtensionRoutes, type RegistrationPolicy } from './device-grant.js';
import { registerAdminTrustedIssuerRoutes } from './admin-trusted-issuers.js';
import type { Clock, Random, Signer, Store } from './ports.js';
import { Metrics, ROUTES } from './metrics.js';

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
  /** RFC 8693 act-chain depth limit (levels); defaults to 4. */
  maxDelegationDepth?: number | undefined;
  /** Per-client-address request budget for /oauth/token (all grants, incl. token exchange). Defaults to 120 per 60s. */
  tokenRateLimit?: { max: number; windowSeconds: number } | undefined;
  /**
   * Proxies whose X-Forwarded-For is trusted (Fastify `trustProxy`: IP/CIDR list string, or boolean).
   * Unset = forwarding headers are ignored and the peer address keys the rate limiter.
   */
  trustProxy?: boolean | string | undefined;
  /** Span boundary with fixed, secret-free names; caller controls exporter and sampling. */
  trace?: ((name: string) => () => void) | undefined;
  /** Bounds on failed client authentication and anonymous record creation. Defaults apply; `false` disables. */
  throttle?: OAuthDeps['throttle'] | undefined;
  /** Maximum request body in bytes (default 64 KiB; Fastify's own default is 1 MiB). */
  bodyLimit?: number | undefined;
}

const DEFAULT_BODY_LIMIT = 64 * 1024;

export function buildServer(deps: Deps): FastifyInstance {
  // Forwarding headers are only honored when the operator names the trusted proxy hop(s).
  const app = Fastify({
    logger: false,
    bodyLimit: deps.bodyLimit ?? DEFAULT_BODY_LIMIT,
    ...(deps.trustProxy !== undefined ? { trustProxy: deps.trustProxy } : {}),
  });

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
    if (code === 429) {
      const wait = (err as { retryAfter?: number }).retryAfter;
      if (wait) reply.header('retry-after', String(wait));
      return fail(reply, new OAuthError('temporarily_unavailable', 'too many requests'), 429);
    }
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

  // Per-route opt-in budget: the token endpoint authenticates clients and mints tokens, so it is the
  // brute-force / abuse surface. Keyed by client address; in-memory (per process).
  const limit = deps.tokenRateLimit ?? { max: 120, windowSeconds: 60 };
  void app.register(rateLimit, {
    global: false,
    errorResponseBuilder: (_req, ctx) => Object.assign(new Error('rate limited'), { statusCode: 429, retryAfter: Math.ceil(ctx.ttl / 1000) }),
  });
  // after(): routes must be added once the plugin's onRoute hook is live, in the same (unscoped) context.
  app.after(() => registerOAuthRoutes(app, deps, { rateLimit: { max: limit.max, timeWindow: limit.windowSeconds * 1000 } }));

  registerExtensionRoutes(app, {
    store: deps.store,
    signer: deps.signer,
    random: deps.random,
    clock: deps.clock,
    issuer: deps.issuer,
    authenticate: deps.authenticate,
    dynamicRegistration: deps.dynamicRegistration,
    throttle: deps.throttle,
    registrationPolicy: deps.registrationPolicy,
  });

  registerAdminTrustedIssuerRoutes(app, {
    store: deps.store,
    random: deps.random,
    clock: deps.clock,
    adminToken: deps.adminToken,
  });

  return app;
}
