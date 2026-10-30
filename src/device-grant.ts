import { createHash, randomInt } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { OAuthError } from './errors.js';
import { redirectUriMatches } from './redirect-uri.js';
import { hashClientSecret, verifyClientSecret } from './client-auth.js';
import type { ClientRecord } from './ports.js';
// Reuse the core module's shared helpers and client auth so slice semantics stay identical.
import {
  authenticateClient, bearerToken, rejectDuplicates, safeEqual, single,
  type OAuthDeps,
} from './oauth.js';

export const DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';
/** The shorthand alias `device_code` is also accepted by the reference. */
export const DEVICE_GRANT_TYPE_ALIAS = 'device_code';
export const DEVICE_CODE_TTL_SECONDS = 600;
export const DEVICE_INTERVAL_SECONDS = 5;
export const PAR_TTL_SECONDS = 60;
/** RFC 8628 §6.1 charset; §6.2 default prefix. */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ'; // removed vowels and confusable glyphs
const DEVICE_CODE_BYTES = 32;
const USER_CODE_LENGTH = 8;

export type { OAuthDeps };

export interface ExtDeps {
  store: OAuthDeps['store'];
  signer: OAuthDeps['signer'];
  random: OAuthDeps['random'];
  clock: OAuthDeps['clock'];
  issuer: OAuthDeps['issuer'];
  /** Device verification UI; when set, POST /oauth/device/verify approves/denies a code. */
  deviceLoginPath?: string | undefined;
  authenticate?: ((req: FastifyRequest) => Promise<string | null>) | undefined;
  /** Whether dynamic client registration (RFC 7591) is enabled. Defaults off. */
  dynamicRegistration?: boolean | undefined;
}

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

/** Unbiased user code "ABCD-EFGH" (RFC 8628 §6.1); ~34 bits, short-lived and rate-limited by expiry. */
function randomUserCode(): string {
  const out: string[] = [];
  for (let i = 0; i < USER_CODE_LENGTH; i += 1) out.push(USER_CODE_ALPHABET.charAt(randomInt(USER_CODE_ALPHABET.length)));
  return `${out.slice(0, 4).join('')}-${out.slice(4).join('')}`;
}

/** Case/dash/space-insensitive form used for hashing and lookup (RFC 8628 §6.1). */
const normalizeUserCode = (code: string): string => code.toUpperCase().replace(/[\s-]/g, '');

/** RFC 8628 §5.1 brute-force guard: max failed user-code guesses per source per window. */
const USER_CODE_MAX_FAILURES = 5;
const USER_CODE_WINDOW_SECONDS = 60;

export function registerExtensionRoutes(app: FastifyInstance, deps: ExtDeps): void {
  const guessState = new Map<string, { count: number; windowStart: number }>();
  // -- RFC 8628 device authorization endpoint --
  // POST /oauth/device_authorization  (also /oauth/device for the reference admin path)
  const deviceAuth = async (req: FastifyRequest, reply: FastifyReply) => {
    const form = req.body;
    if (!(form instanceof URLSearchParams)) {
      throw new OAuthError('invalid_request', 'content-type must be application/x-www-form-urlencoded');
    }
    rejectDuplicates(form);
    const client = await authenticateClient(deps, req, form);
    if (!client.grantTypes.includes(DEVICE_GRANT_TYPE) && !client.grantTypes.includes(DEVICE_GRANT_TYPE_ALIAS)) {
      throw new OAuthError('unauthorized_client', 'client is not allowed to use device_code grant');
    }

    const scope = single(form, 'scope') ?? '';
    const requested = scope.split(' ').filter((s) => s !== '');
    if (requested.some((s) => !client.scopes.includes(s))) throw new OAuthError('invalid_scope');

    const now = deps.clock.now();
    const deviceCode = deps.random.token(DEVICE_CODE_BYTES);
    const userCode = randomUserCode();
    const deviceCodeHash = sha256(deviceCode);
    const userCodeHash = sha256(normalizeUserCode(userCode));

    await deps.store.saveDeviceCode({
      deviceCodeHash,
      userCodeHash,
      clientId: client.clientId,
      scope,
      expiresAt: now + DEVICE_CODE_TTL_SECONDS,
      interval: DEVICE_INTERVAL_SECONDS,
      lastPolledAt: null,
      status: 'pending',
      subject: null,
    });

    const verificationUri = `${deps.issuer}/oauth/device/verify`;
    return reply.header('cache-control', 'no-store').send({
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(userCode)}`,
      expires_in: DEVICE_CODE_TTL_SECONDS,
      interval: DEVICE_INTERVAL_SECONDS,
    });
  };
  app.post('/oauth/device_authorization', deviceAuth);
  app.post('/oauth/device', deviceAuth);

  // -- RFC 8628 device verification UI (approve/deny) --
  app.get('/oauth/device/verify', async (_req, reply) =>
    reply.type('text/html; charset=utf-8').send('<!doctype html><title>Device verification</title>'));
  app.post('/oauth/device/verify', async (req, reply) => {
    const form = req.body;
    if (!(form instanceof URLSearchParams)) {
      return reply.status(400).type('text/plain').send('content-type must be application/x-www-form-urlencoded');
    }
    const userCode = single(form, 'user_code');
    const action = single(form, 'action');
    if (!userCode || (action !== 'approve' && action !== 'deny')) {
      return reply.status(400).type('text/plain').send('user_code and action (approve|deny) are required');
    }
    // Both decisions require an authenticated end user; anonymous callers cannot approve or deny.
    const subject = deps.authenticate ? await deps.authenticate(req) : null;
    if (!subject) return reply.status(403).type('text/plain').send('authentication required');
    const status = action === 'approve' ? 'approved' : 'denied';
    const now = deps.clock.now();
    const key = `${req.ip}|${subject}`;
    let g = guessState.get(key);
    if (!g || now - g.windowStart >= USER_CODE_WINDOW_SECONDS) {
      g = { count: 0, windowStart: now };
      guessState.set(key, g);
    }
    if (g.count >= USER_CODE_MAX_FAILURES) {
      return reply.status(429).header('retry-after', String(USER_CODE_WINDOW_SECONDS - (now - g.windowStart)))
        .type('text/plain').send('too many attempts');
    }
    const ok = await deps.store.resolveDeviceCode(sha256(normalizeUserCode(userCode)), status, subject, deps.clock.now());
    if (!ok) {
      g.count += 1;
      return reply.status(400).type('text/plain').send('unknown, expired or already used user code');
    }
    return reply.type('text/html; charset=utf-8').send(`<!doctype html><title>${status}</title>`);
  });

  // -- RFC 9126 Pushed Authorization Request endpoint --
  app.post('/oauth/par', async (req, reply) => {
    const form = req.body;
    if (!(form instanceof URLSearchParams)) {
      throw new OAuthError('invalid_request', 'content-type must be application/x-www-form-urlencoded');
    }
    rejectDuplicates(form);
    const client = await authenticateClient(deps, req, form);
    if (!client.grantTypes.includes('authorization_code')) throw new OAuthError('unauthorized_client');

    const params: Record<string, string> = {};
    for (const key of form.keys()) {
      if (key === 'client_id' || key === 'client_secret') continue;
      params[key] = single(form, key) ?? '';
    }
    // Never allow a request_uri to piggy-back into a pushed request.
    delete params.request_uri;
    // RFC 9126 §2.3: validate the request at push time as the authorization endpoint would.
    if (params.response_type !== undefined && params.response_type !== 'code') {
      throw new OAuthError('unsupported_response_type', 'only response_type=code is supported');
    }
    if (params.redirect_uri !== undefined && !redirectUriMatches(client.redirectUris, params.redirect_uri)) {
      throw new OAuthError('invalid_request', 'redirect_uri is not registered for this client');
    }

    const now = deps.clock.now();
    const requestUri = `urn:ietf:params:oauth:request_uri:${deps.random.token(32)}`;
    await deps.store.savePar({
      requestUriHash: sha256(requestUri),
      clientId: client.clientId,
      params,
      expiresAt: now + PAR_TTL_SECONDS,
      consumedAt: null,
    });

    return reply.status(201).header('cache-control', 'no-store').send({
      request_uri: requestUri,
      expires_in: PAR_TTL_SECONDS,
    });
  });

  // -- RFC 7591 / 7592 dynamic client registration --
  app.post('/connect/register', async (req, reply) => {
    if (!deps.dynamicRegistration) {
      throw new OAuthError('access_denied', 'dynamic client registration is disabled');
    }
    const body = req.body;
    // Accept application/json; fastify's JSON parser yields an object.
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      throw new OAuthError('invalid_client_metadata', 'request body must be a JSON object');
    }
    const meta = body as Record<string, unknown>;

    const redirectUris = normalizeRedirectUris(meta.redirect_uris);
    if (redirectUris.length === 0) throw new OAuthError('invalid_redirect_uri', 'redirect_uris must not be empty');
    const authMethod = normalizeAuthMethod(meta.token_endpoint_auth_method);
    const grantTypes = normalizeGrantTypes(meta.grant_types, authMethod);
    const responseTypes = normalizeResponseTypes(meta.response_types);
    const scope = normalizeScope(meta.scope);

    const now = deps.clock.now();
    const clientId = deps.random.token(16);
    const clientSecret = authMethod === 'none' ? null : deps.random.token(32);
    const regToken = deps.random.token(32);
    const clientSecretHash = clientSecret === null ? null : await hashClientSecret(clientSecret);

    const metadata: Record<string, unknown> = {
      client_name: typeof meta.client_name === 'string' ? meta.client_name : clientId,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: authMethod,
      grant_types: grantTypes,
      response_types: responseTypes,
      scope,
    };
    for (const k of ['client_uri', 'logo_uri', 'tos_uri', 'policy_uri', 'jwks_uri', 'contacts']) {
      if (meta[k] !== undefined) metadata[k] = meta[k];
    }

    const client: ClientRecord = {
      clientId,
      clientSecretHash,
      redirectUris,
      grantTypes,
      scopes: scope.split(' ').filter((s) => s !== ''),
      enabled: true,
      registration: { tokenHash: sha256(regToken), issuedAt: now, metadata },
    };
    await deps.store.saveClient(client);

    return reply.status(201).send({
      client_id: clientId,
      ...(clientSecret === null ? {} : { client_secret: clientSecret, client_secret_expires_at: 0 }),
      registration_access_token: regToken,
      registration_client_uri: `${deps.issuer}/connect/register/${encodeURIComponent(clientId)}`,
      client_id_issued_at: now,
      ...metadata,
    });
  });

  const clientConfigHandler = async (req: FastifyRequest, reply: FastifyReply) => {
    const clientId = (req.params as { client_id: string }).client_id;
    const record = await authenticateRegToken(deps, req, clientId);
    return reply.header('cache-control', 'no-store').send({
      client_id: record.clientId,
      client_id_issued_at: record.registration?.issuedAt,
      ...(record.registration?.metadata ?? {}),
    });
  };
  app.get('/connect/register/:client_id', clientConfigHandler);
  app.put('/connect/register/:client_id', async (req, reply) => {
    const clientId = (req.params as { client_id: string }).client_id;
    const record = await authenticateRegToken(deps, req, clientId);
    const body = req.body;
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      throw new OAuthError('invalid_client_metadata', 'request body must be a JSON object');
    }
    const meta = body as Record<string, unknown>;
    const redirectUris = normalizeRedirectUris(meta.redirect_uris);
    if (redirectUris.length === 0) throw new OAuthError('invalid_redirect_uri', 'redirect_uris must not be empty');
    const authMethod = meta.token_endpoint_auth_method === undefined
      ? String(record.registration?.metadata.token_endpoint_auth_method ?? 'client_secret_basic')
      : normalizeAuthMethod(meta.token_endpoint_auth_method);
    // Switching public<->confidential would need a new secret; not supported on update.
    if ((authMethod === 'none') !== (record.clientSecretHash === null)) {
      throw new OAuthError('invalid_client_metadata', 'token_endpoint_auth_method cannot switch between public and confidential');
    }
    const grantTypes = normalizeGrantTypes(meta.grant_types, authMethod);
    const scope = normalizeScope(meta.scope);

    const prev = record.registration ?? { tokenHash: '', issuedAt: 0, metadata: {} as Record<string, unknown> };
    prev.metadata = {
      ...prev.metadata,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: authMethod,
      grant_types: grantTypes,
      response_types: normalizeResponseTypes(meta.response_types),
      scope,
    };
    if (typeof meta.client_name === 'string') prev.metadata.client_name = meta.client_name;
    record.registration = prev;
    record.redirectUris = redirectUris;
    record.grantTypes = grantTypes;
    record.scopes = scope.split(' ').filter((s) => s !== '');
    await deps.store.saveClient(record);
    return clientConfigHandler(req, reply);
  });
  app.delete('/connect/register/:client_id', async (req, reply) => {
    const clientId = (req.params as { client_id: string }).client_id;
    await authenticateRegToken(deps, req, clientId);
    await deps.store.deleteClient(clientId);
    return reply.status(204).send();
  });
}

async function authenticateRegToken(deps: ExtDeps, req: FastifyRequest, clientId: string): Promise<ClientRecord> {
  const token = bearerToken(req);
  if (!token) throw new OAuthError('invalid_client', 'missing registration_access_token');
  const record = await deps.store.getClient(clientId);
  const invalid = new OAuthError('invalid_client', 'invalid registration_access_token');
  if (!record || !record.enabled || !record.registration) {
    if (token) await verifyClientSecret(token, await hashClientSecret('dummy'));
    throw invalid;
  }
  if (!safeEqual(sha256(token), record.registration.tokenHash)) throw invalid;
  return record;
}

function normalizeRedirectUris(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new OAuthError('invalid_redirect_uri', 'redirect_uris must be an array');
  const uris: string[] = [];
  for (const u of value) {
    if (typeof u !== 'string') throw new OAuthError('invalid_redirect_uri', 'redirect_uris entries must be strings');
    let parsed: URL;
    try {
      parsed = new URL(u);
    } catch {
      throw new OAuthError('invalid_redirect_uri', 'redirect_uri is not an absolute URL');
    }
    // Fragment is never permitted in a redirect URI.
    if (parsed.hash !== '') throw new OAuthError('invalid_redirect_uri', 'redirect_uri must not contain a fragment');
    // Plain http only for loopback (RFC 8252 §7.3); other schemes must be https or a custom app scheme.
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    if (parsed.protocol === 'http:' && !loopback) throw new OAuthError('invalid_redirect_uri', 'http redirect_uri only allowed for loopback');
    if (parsed.protocol === 'javascript:' || parsed.protocol === 'data:') throw new OAuthError('invalid_redirect_uri', 'unsafe redirect_uri scheme');
    uris.push(u);
  }
  return uris;
}

function normalizeAuthMethod(value: unknown): string {
  if (value === undefined) return 'client_secret_basic';
  if (value !== 'client_secret_basic' && value !== 'client_secret_post' && value !== 'none') {
    throw new OAuthError('invalid_client_metadata', 'unsupported token_endpoint_auth_method');
  }
  return value;
}

function normalizeGrantTypes(value: unknown, authMethod: string): string[] {
  const allowed = ['authorization_code', 'refresh_token', 'client_credentials', DEVICE_GRANT_TYPE, DEVICE_GRANT_TYPE_ALIAS];
  if (value === undefined) {
    const out = ['authorization_code'];
    if (authMethod === 'none') return out;
    out.push('refresh_token');
    return out;
  }
  if (!Array.isArray(value)) throw new OAuthError('invalid_client_metadata', 'grant_types must be an array');
  const out: string[] = [];
  for (const g of value) {
    if (typeof g !== 'string' || !allowed.includes(g)) {
      throw new OAuthError('invalid_client_metadata', `unsupported grant_type: ${String(g)}`);
    }
    out.push(g);
  }
  return out;
}

function normalizeResponseTypes(value: unknown): string[] {
  if (value === undefined) return ['code'];
  if (!Array.isArray(value)) throw new OAuthError('invalid_client_metadata', 'response_types must be an array');
  const out: string[] = [];
  for (const g of value) {
    if (g !== 'code') throw new OAuthError('invalid_client_metadata', `unsupported response_type: ${String(g)}`);
    out.push(g);
  }
  return out;
}

function normalizeScope(value: unknown): string {
  if (value === undefined) return 'openid';
  if (typeof value !== 'string') throw new OAuthError('invalid_client_metadata', 'scope must be a string');
  const scope = value.trim();
  // Self-service registration may never mint privileged scopes (reference: admin/write rejected).
  if (scope.split(' ').some((s) => ['admin', 'write'].includes(s.toLowerCase()))) {
    throw new OAuthError('invalid_client_metadata', 'privileged scopes cannot be self-registered');
  }
  return scope;
}
