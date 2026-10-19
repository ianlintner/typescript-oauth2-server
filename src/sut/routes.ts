import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { SeedUser } from './seed.js';

/** Process-local test-login session registry for conformance mode only. */
export interface TestLoginRegistry {
  /** Verify seeded credentials; returns a fresh session id on success, or null. */
  login(username: string, password: string): string | null;
  /** Look up the username bound to a session id, or null. */
  usernameFor(sessionId: string | null): string | null;
}

export const SESSION_COOKIE = 'oauth2_test_session';
// The contract's core scenarios hardcode `with.loginPath: /auth/login` (the
// Rust reference path, shared by the Python port). The runner has no flag to
// override it, so the SUT test-login must live at /auth/login to be drivable.
export const LOGIN_PATH = '/auth/login';

function secureEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** Extract the test-session cookie from a request, or null. */
export function sessionFrom(request: FastifyRequest): string | null {
  const header = request.headers.cookie;
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === SESSION_COOKIE) return value === '' ? null : value;
  }
  return null;
}

/**
 * Build a process-local test registry from the seed's users. Credentials are
 * accepted only for seeded identities and only while this registry exists (it
 * is never constructed off conformance mode), so seeded passwords are dead in
 * normal operation.
 */
export function createTestRegistry(users: SeedUser[]): TestLoginRegistry {
  const byName = new Map<string, string>();
  const sessions = new Map<string, string>();
  for (const user of users) byName.set(user.username, user.password);

  return {
    login(username, password) {
      const expected = byName.get(username);
      if (expected === undefined || !secureEqual(expected, password)) return null;
      const sessionId = randomBytes(32).toString('base64url');
      sessions.set(sessionId, username);
      return sessionId;
    },
    usernameFor(sessionId) {
      return sessionId === null ? null : sessions.get(sessionId) ?? null;
    },
  };
}

/** Resolve an authorized subject for the authorize endpoint from the session cookie. */
export function makeTestAuthenticate(registry: TestLoginRegistry) {
  return async (req: FastifyRequest): Promise<string | null> => registry.usernameFor(sessionFrom(req));
}

/** Consent check: grant only if the subject's seed lists this client for auto-approval. */
export function makeConsent(users: SeedUser[]) {
  const auto = new Map<string, Set<string>>();
  for (const user of users) auto.set(user.username, new Set(user.autoApproveClients));
  return (subject: string, clientId: string): boolean => auto.get(subject)?.has(clientId) ?? false;
}

/**
 * Register non-interactive test login routes. Only called in conformance mode;
 * with the mode off they never exist and test credentials are never accepted.
 *
 * - GET /auth/login is the unauthenticated authorize redirect target (a bearer of a
 *   valid session never sees it). It returns the canonical login step.
 * - POST /auth/login verifies seeded credentials, sets the session cookie, and
 *   redirects to /oauth/authorize so the runner re-drives the request. A
 *   refused login redirects to /auth/login?error=..., which the runner treats as a
 *   refusal rather than an authorization result.
 */
export function registerTestLoginRoutes(app: FastifyInstance, registry: TestLoginRegistry): void {
  // The urlencoded body parser is already installed by registerOAuthRoutes.
  app.get(LOGIN_PATH, async (_req, reply) => {
    return reply.type('text/html; charset=utf-8').send('<!doctype html><title>Sign in</title>');
  });

  app.post(LOGIN_PATH, async (req, reply) => {
    const form = req.body;
    if (!(form instanceof URLSearchParams)) {
      return reply.status(400).send('content-type must be application/x-www-form-urlencoded');
    }
    const sessionId = registry.login(form.get('username') ?? '', form.get('password') ?? '');
    if (sessionId === null) {
      return reply.status(302).header('location', `${LOGIN_PATH}?error=invalid_credentials`).send();
    }
    reply.header('set-cookie', `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; SameSite=Lax`);
    return reply.status(302).header('location', '/oauth/authorize').send();
  });
}
