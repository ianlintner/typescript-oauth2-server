import type { FastifyInstance } from 'fastify';
import { OAuthError, errorResponse } from './errors.js';

/** Requests one source address may make to a bounded route per {@link BOUNDED_WINDOW_SECONDS}. */
export const BOUNDED_REQUESTS_PER_SOURCE = 30;
/** Fixed window for every per-route bound, in seconds. */
export const BOUNDED_WINDOW_SECONDS = 60;

/**
 * Routes whose handler does work an unauthenticated caller can repeat freely: every request
 * verifies a JWT against the server's own keys, and logout may also end a session. Bounded per source address.
 */
export const BOUNDED_ROUTES: ReadonlySet<string> = new Set(['/oauth/userinfo', '/oauth/logout']);

interface Window {
  count: number;
  windowStart: number;
}

/**
 * Per-route, per-source fixed windows held in process memory. Time comes from the injected clock
 * so tests advance windows deterministically. A counter idle for a full window is dropped during
 * the next prune, so memory is bounded by the sources seen within one window.
 */
export class RouteBounds {
  readonly #counters = new Map<string, Window>();
  #lastPrune = Number.NEGATIVE_INFINITY;

  /**
   * Counts one request against `path` from `source`. `source` must be the socket address
   * (`req.ip` without trustProxy); forwarding headers are never consulted.
   * Returns null for a route that carries no bound.
   */
  hit(method: string, path: string, source: string, now: number): Window | null {
    if (!BOUNDED_ROUTES.has(path)) return null;
    if (now - this.#lastPrune >= BOUNDED_WINDOW_SECONDS) {
      for (const [key, window] of this.#counters) {
        if (now - window.windowStart >= BOUNDED_WINDOW_SECONDS) this.#counters.delete(key);
      }
      this.#lastPrune = now;
    }
    const key = `${method} ${path} ${source}`;
    const windowStart = Math.floor(now / BOUNDED_WINDOW_SECONDS) * BOUNDED_WINDOW_SECONDS;
    const current = this.#counters.get(key);
    const next: Window = current?.windowStart === windowStart
      ? { count: current.count + 1, windowStart }
      : { count: 1, windowStart };
    this.#counters.set(key, next);
    return next;
  }

  reset(): void {
    this.#counters.clear();
    this.#lastPrune = Number.NEGATIVE_INFINITY;
  }
}

/** Seconds until the window that produced an over-limit `hit` rolls over (always at least 1). */
export const retryAfterSeconds = (window: Window, now: number): number =>
  Math.max(1, window.windowStart + BOUNDED_WINDOW_SECONDS - now);

/**
 * Route context bound applied to the two expensive routes. The onRequest hook installed by
 * {@link registerRouteBounds} reads this config, so the limit is declared next to each route.
 */
export const routeBoundConfig = Object.freeze({
  config: {
    rateLimit: {
      max: BOUNDED_REQUESTS_PER_SOURCE,
      timeWindow: BOUNDED_WINDOW_SECONDS * 1000,
    },
  },
});

/**
 * Refuses a request whose source has used up the route's budget for the current window, with an
 * RFC 6749 §5.2 `temporarily_unavailable` and Retry-After. Runs as onRequest, before routing handlers,
 * so no JWT verification, store lookup or session change happens for a refused request.
 */
export function registerRouteBounds(app: FastifyInstance, bounds: RouteBounds, clock: { now(): number }): void {
  app.addHook('onRequest', (req, reply, done) => {
    const path = req.routeOptions.url;
    const limit = (req.routeOptions.config as { rateLimit?: { max?: number } } | undefined)?.rateLimit?.max;
    const max = typeof limit === 'number' ? limit : BOUNDED_REQUESTS_PER_SOURCE;
    const window = path === undefined ? null : bounds.hit(req.method, path, req.ip, clock.now());
    if (!window || window.count <= max) return done();
    const retryAfter = retryAfterSeconds(window, clock.now());
    const err = new OAuthError('temporarily_unavailable', `too many requests, retry after ${retryAfter} seconds`);
    const r = errorResponse(err);
    reply.status(429).header('retry-after', String(retryAfter)).headers(r.headers).send(r.body);
    return reply;
  });
}
