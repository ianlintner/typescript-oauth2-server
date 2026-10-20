import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { hashClientSecret, verifyClientSecret } from './client-auth.js';
import { OAuthError } from './errors.js';
import type { ClientRecord, Clock, Random, Signer, Store } from './ports.js';

export const CODE_TTL_SECONDS = 60;
export const ACCESS_TOKEN_TTL_SECONDS = 3600;
/** Unset unless the caller passes a value. */
const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 86_400; // 24h default
const REAUTH_GRACE_SECONDS = 5;

export interface OAuthDeps {
  store: Store;
  signer: Signer;
  clock: Clock;
  random: Random;
  issuer: string;
  refreshTokenTtl?: number | undefined;
  /**
   * Resolves the authenticated resource owner for an authorization request.
   * Login/consent UI is out of scope for this slice; when absent or when it
   * returns null the request fails closed with access_denied.
   */
  authenticate?: ((req: FastifyRequest) => Promise<string | null>) | undefined;
  /**
   * Conformance/test mode only. When set, an unauthenticated authorize request
   * is redirected (302) to this same-origin path instead of failing with
   * access_denied. Never set in normal operation.
   */
  loginPath?: string | undefined;
  /**
   * Conformance/test mode only. When set, consent is granted only if this
   * returns true for (subject, clientId); otherwise the request fails closed
   * with access_denied (no consent UI exists). Absent means no extra check.
   */
  consent?: ((subject: string, clientId: string) => boolean) | undefined;
  /** Epoch seconds at which the request's session authenticated; null when unknown. Feeds auth_time / max_age. */
  authTime?: ((req: FastifyRequest) => number | null) | undefined;
  /** End-user claims for a subject (OIDC Core 5.1). Absent or null means only `sub` is disclosed. */
  userClaims?: ((subject: string) => UserClaims | null) | undefined;
  /** Terminates the request's session (RP-initiated logout). */
  endSession?: ((req: FastifyRequest, reply: FastifyReply) => void) | undefined;
}

export interface UserClaims {
  email?: string | undefined;
  preferred_username?: string | undefined;
}

/** OIDC Core 5.4 scope-to-claim mapping: only claims authorized by the granted scopes are released. */
export function claimsForScope(scope: string, user: UserClaims | null): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!user) return out;
  const scopes = scope.split(' ');
  if (scopes.includes('email') && user.email !== undefined) out.email = user.email;
  if (scopes.includes('profile') && user.preferred_username !== undefined) out.preferred_username = user.preferred_username;
  return out;
}

// RFC 7636 §4.1/§4.2: verifier 43-128 unreserved chars; S256 challenge is 43 base64url chars.
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;

export const sha256Hex = (value: string): string => createHash('sha256').update(value).digest('hex');

/** Read a single-valued parameter. Repeated parameters are rejected (RFC 6749 §3.1); empty means absent. */
export function single(params: URLSearchParams, name: string): string | undefined {
  const all = params.getAll(name);
  if (all.length > 1) throw new OAuthError('invalid_request', `duplicate parameter: ${name}`);
  return all[0] === undefined || all[0] === '' ? undefined : all[0];
}

export function rejectDuplicates(params: URLSearchParams): void {
  const seen = new Set<string>();
  for (const key of params.keys()) {
    if (seen.has(key)) throw new OAuthError('invalid_request', `duplicate parameter: ${key}`);
    seen.add(key);
  }
}

function redirectTo(reply: FastifyReply, redirectUri: string, params: Record<string, string | undefined>) {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) if (value !== undefined) url.searchParams.set(key, value);
  return reply.status(302).header('location', url.toString()).send();
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export function formDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    throw new OAuthError('invalid_client', 'malformed client credentials');
  }
}

export async function authenticateClient(deps: OAuthDeps, req: FastifyRequest, form: URLSearchParams): Promise<ClientRecord> {
  let id = single(form, 'client_id');
  let secret = single(form, 'client_secret');
  const header = req.headers.authorization;
  if (header !== undefined) {
    const match = /^Basic ([A-Za-z0-9+/=]+)$/i.exec(header);
    if (!match) throw new OAuthError('invalid_client', 'unsupported client authentication');
    const decoded = Buffer.from(match[1]!, 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep < 0) throw new OAuthError('invalid_client', 'malformed client credentials');
    const headerId = formDecode(decoded.slice(0, sep));
    if (id !== undefined && id !== headerId) throw new OAuthError('invalid_request', 'client_id does not match credentials');
    if (secret !== undefined) throw new OAuthError('invalid_request', 'multiple client authentication methods');
    id = headerId;
    secret = formDecode(decoded.slice(sep + 1));
  }
  const invalid = new OAuthError('invalid_client', 'client authentication failed');
  if (!id) throw invalid;
  const client = await deps.store.getClient(id);
  if (!client || !client.enabled) {
    // Equalise work so response timing does not reveal which client ids exist.
    if (secret) await verifyClientSecret(secret, await hashClientSecret('dummy-secret'));
    throw invalid;
  }
  if (client.clientSecretHash === null) {
    if (secret) throw invalid; // public clients never authenticate with a secret
    return client;
  }
  if (!secret || !(await verifyClientSecret(secret, client.clientSecretHash))) throw invalid;
  return client;
}

export function bearerToken(req: FastifyRequest): string | undefined {
  const h = req.headers.authorization;
  if (!h) return undefined;
  const m = /^Bearer (.+)$/i.exec(h);
  return m ? m[1] : undefined;
}

/**
 * RFC 8628 §3.4 device token grant. Returns the token reply. On a pending
 * authorization the reply carries the authorization_pending error and a
 * Cache-Control: no-store (RFC 8628 §3.5). A poll faster than the device's
 * interval gets slow_down (+5s).
 */
async function deviceCodeGrant(deps: OAuthDeps, client: ClientRecord, hash: string): Promise<Record<string, unknown>> {
  const now = deps.clock.now();
  const record = await deps.store.getDeviceCode(hash);
  if (!record || record.clientId !== client.clientId) throw new OAuthError('invalid_grant', 'device_code is invalid');
  if (record.expiresAt <= now) throw new OAuthError('expired_token', 'device_code expired');
  if (record.status === 'denied') throw new OAuthError('access_denied', 'end-user denied device authorization');
  if (record.status === 'consumed') throw new OAuthError('invalid_grant', 'device_code already used');

  if (record.status === 'pending') {
    // slow_down when polling before the minimum interval (RFC 8628 §3.5).
    const last = record.lastPolledAt;
    if (last !== null && now - last < record.interval) {
      await deps.store.recordDevicePoll(hash, now, record.interval + 5);
      throw new OAuthError('slow_down', 'client is polling too quickly');
    }
    await deps.store.recordDevicePoll(hash, now, record.interval);
    throw new OAuthError('authorization_pending', 'authorization is pending');
  }

  // approved: consume atomically (one-time).
  const consumed = await deps.store.consumeDeviceCode(hash, now);
  if (!consumed) throw new OAuthError('invalid_grant', 'device_code already used');

  const subject = consumed.subject ?? consumed.clientId;
  const scopes = consumed.scope;
  const scopesList = scopes ? scopes.split(' ') : [];
  const includesOpenid = scopesList.includes('openid');

  const iat = now;
  const atJti = deps.random.token(16);
  const claims: Record<string, unknown> = {
    iss: deps.issuer, sub: subject, aud: client.clientId, client_id: client.clientId,
    iat, exp: iat + ACCESS_TOKEN_TTL_SECONDS, jti: atJti,
  };
  if (scopes !== '') claims.scope = scopes;
  const accessToken = await deps.signer.sign(claims);

  await deps.store.saveAccessToken({
    jti: atJti, clientId: client.clientId, subject, scope: scopes,
    expiresAt: iat + ACCESS_TOKEN_TTL_SECONDS, revokedAt: null, tokenHash: null,
  });

  const body: Record<string, unknown> = {
    access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_TTL_SECONDS,
    ...(scopes !== '' ? { scope: scopes } : {}),
  };

  if (includesOpenid) {
    const idClaims: Record<string, unknown> = {
      iss: deps.issuer, sub: subject, aud: client.clientId,
      iat, exp: iat + ACCESS_TOKEN_TTL_SECONDS, jti: deps.random.token(16),
    };
    body.id_token = await deps.signer.sign(idClaims);
  }

  if (client.grantTypes.includes('refresh_token') && scopesList.length > 0) {
    const rtJti = deps.random.token(24);
    await deps.store.saveRefreshToken({
      jti: rtJti, clientId: client.clientId, subject, scope: scopes, expiresAt: iat + (deps.refreshTokenTtl ?? 86_400),
      family: rtJti, parentJti: null, revokedByReplayAt: null, revokedAt: null,
    });
    body.refresh_token = rtJti;
  }

  return body;
}

export function registerOAuthRoutes(app: FastifyInstance, deps: OAuthDeps): void {
  const refreshTtl = deps.refreshTokenTtl ?? DEFAULT_REFRESH_TOKEN_TTL_SECONDS;

  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    done(null, new URLSearchParams(body as string));
  });

  app.get('/oauth/authorize', async (req, reply) => {
    let params = new URL(req.url, 'http://localhost').searchParams;
    // Until client and redirect_uri are trusted, errors are shown to the user agent and never redirected.
    rejectDuplicates(params);

    // RFC 9126: a request_uri references a previously pushed request. Its stored
    // parameters supply client_id and redirect_uri; fields present on the GET are
    // ignored (RFC 9126 §2/§3).
    const requestUri = single(params, 'request_uri');
    let parClientId: string | undefined;
    let parRedirectUri: string | undefined;
    if (requestUri !== undefined) {
      const pushed = await deps.store.getPar(sha256Hex(requestUri), deps.clock.now());
      if (!pushed) {
        throw new OAuthError('invalid_request_uri', 'request_uri is unknown or expired');
      }
      parClientId = pushed.clientId;
      // RFC 9126 §4: the request_uri is bound to the client that pushed it.
      const presented = single(params, 'client_id');
      if (presented !== undefined && presented !== pushed.clientId) {
        throw new OAuthError('invalid_request', 'request_uri was issued to a different client');
      }
      parRedirectUri = pushed.params.redirect_uri;
      if (parRedirectUri === undefined || parRedirectUri === '') {
        throw new OAuthError('invalid_request', 'pushed request is missing redirect_uri');
      }
      // Merge: pushed params win; the client_id/redirect_uri come from the push.
      const merged = new URLSearchParams();
      for (const [k, v] of Object.entries(pushed.params)) if (k !== 'request_uri') merged.set(k, v);
      for (const [k, v] of params.entries()) if (k !== 'request_uri' && !merged.has(k)) merged.set(k, v);
      params = merged;
    }

    const clientId = single(params, 'client_id') ?? parClientId;
    const redirectUri = single(params, 'redirect_uri') ?? parRedirectUri;
    if (!clientId || !redirectUri) throw new OAuthError('invalid_request', 'client_id and redirect_uri are required');
    const client = await deps.store.getClient(clientId);
    if (!client || !client.enabled) {
      throw new OAuthError('invalid_request', 'unknown client');
    }
    if (!client.redirectUris.includes(redirectUri)) {
      if (requestUri !== undefined) {
        throw new OAuthError('invalid_request', 'redirect_uri not registered for this client');
      }
      throw new OAuthError('invalid_request', 'unknown client or unregistered redirect_uri');
    }

    const state = single(params, 'state');
    const fail = (error: string) => redirectTo(reply, redirectUri, { error, state, iss: deps.issuer });

    if (single(params, 'response_type') !== 'code') return fail('invalid_request');
    if (!client.grantTypes.includes('authorization_code')) return fail('unauthorized_client');
    const challenge = single(params, 'code_challenge');
    if (!challenge || single(params, 'code_challenge_method') !== 'S256' || !CHALLENGE_RE.test(challenge)) {
      return fail('invalid_request');
    }
    const requested = (single(params, 'scope') ?? '').split(' ').filter((s) => s !== '');
    if (requested.some((s) => !client.scopes.includes(s))) return fail('invalid_scope');

    const prompt = (single(params, 'prompt') ?? '').split(' ').filter((p) => p !== '');
    if (prompt.includes('none') && prompt.length > 1) return fail('invalid_request');
    const maxAgeRaw = single(params, 'max_age');
    if (maxAgeRaw !== undefined && !/^\d+$/.test(maxAgeRaw)) return fail('invalid_request');
    const maxAge = maxAgeRaw === undefined ? null : Number(maxAgeRaw);

    let subject = deps.authenticate ? await deps.authenticate(req) : null;
    const authTime = subject && deps.authTime ? deps.authTime(req) : null;
    // OIDC Core 3.1.2.1: prompt=login or a session older than max_age (or of unknown age) must re-authenticate.
    // A login completed within REAUTH_GRACE_SECONDS counts as fresh so the post-login redirect does not loop.
    const age = authTime === null ? null : deps.clock.now() - authTime;
    const needsFresh = prompt.includes('login') || maxAge !== null;
    const limit = (prompt.includes('login') ? 0 : maxAge ?? 0) + (needsFresh ? REAUTH_GRACE_SECONDS : 0);
    if (subject && needsFresh && (age === null || age > limit)) subject = null;
    if (!subject) {
      // prompt=none forbids any interactive login (OIDC Core 3.1.2.1).
      if (prompt.includes('none')) return fail('login_required');
      if (deps.loginPath !== undefined) return reply.status(302).header('location', deps.loginPath).send();
      return fail('access_denied');
    }
    if (deps.consent && !deps.consent(subject, client.clientId)) return fail('access_denied');

    // RFC 9126 §4: a request_uri is single-use; consume it only once the request is about to succeed.
    if (requestUri !== undefined) {
      const used = await deps.store.consumePar(sha256Hex(requestUri), client.clientId, deps.clock.now());
      if (!used) throw new OAuthError('invalid_request_uri', 'request_uri is unknown, expired or already used');
    }

    const nonce = single(params, 'nonce') ?? null;
    const code = deps.random.token(32);
    await deps.store.saveAuthorizationCode({
      codeHash: sha256Hex(code),
      clientId: client.clientId,
      redirectUri,
      subject,
      scope: requested.join(' '),
      codeChallenge: challenge,
      expiresAt: deps.clock.now() + CODE_TTL_SECONDS,
      consumedAt: null,
      nonce,
      // auth_time is claimed when max_age was requested (OIDC Core 2).
      authTime: maxAge !== null ? authTime : null,
    });
    return redirectTo(reply, redirectUri, { code, state, iss: deps.issuer });
  });

  app.post('/oauth/token', async (req, reply) => {
    const form = req.body;
    if (!(form instanceof URLSearchParams)) {
      throw new OAuthError('invalid_request', 'content-type must be application/x-www-form-urlencoded');
    }
    rejectDuplicates(form);
    const grantType = single(form, 'grant_type');
    if (!grantType) throw new OAuthError('invalid_request', 'grant_type is required');

    // -- authorization_code --
    if (grantType === 'authorization_code') {
      const client = await authenticateClient(deps, req, form);
      if (!client.grantTypes.includes('authorization_code')) throw new OAuthError('unauthorized_client');

      const code = single(form, 'code');
      const redirectUri = single(form, 'redirect_uri');
      const verifier = single(form, 'code_verifier');
      if (!code) throw new OAuthError('invalid_request', 'code is required');
      if (!redirectUri) throw new OAuthError('invalid_request', 'redirect_uri is required');
      if (!verifier) throw new OAuthError('invalid_request', 'code_verifier is required');

      // Consume atomically; a code presented by the wrong client is rolled back so it cannot be burned by others.
      const record = await deps.store.transaction(async (tx) => {
        const consumed = await tx.consumeAuthorizationCode(sha256Hex(code), deps.clock.now());
        if (!consumed) return null;
        if (consumed.clientId !== client.clientId) throw new OAuthError('invalid_grant');
        return consumed;
      });
      if (!record) throw new OAuthError('invalid_grant', 'authorization code is invalid, expired or already used');
      if (record.redirectUri !== redirectUri) throw new OAuthError('invalid_grant', 'redirect_uri mismatch');
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      if (!VERIFIER_RE.test(verifier) || !safeEqual(challenge, record.codeChallenge)) {
        throw new OAuthError('invalid_grant', 'PKCE verification failed');
      }

      const iat = deps.clock.now();
      const scopes = record.scope;
      const scopesList = scopes ? scopes.split(' ') : [];
      const includesOpenid = scopesList.includes('openid');

      const atJti = deps.random.token(16);
      const claims: Record<string, unknown> = {
        iss: deps.issuer,
        sub: record.subject,
        aud: client.clientId,
        client_id: client.clientId,
        iat,
        exp: iat + ACCESS_TOKEN_TTL_SECONDS,
        jti: atJti,
      };
      if (scopes !== '') claims.scope = scopes;
      const accessToken = await deps.signer.sign(claims);

      await deps.store.saveAccessToken({
        jti: atJti, clientId: client.clientId, subject: record.subject,
        scope: scopes, expiresAt: iat + ACCESS_TOKEN_TTL_SECONDS, revokedAt: null, tokenHash: null,
      });

      const body: Record<string, unknown> = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        ...(scopes !== '' ? { scope: scopes } : {}),
      };

      // ID token for openid
      if (includesOpenid) {
        const idClaims: Record<string, unknown> = {
          iss: deps.issuer,
          sub: record.subject,
          aud: client.clientId,
          iat,
          exp: iat + ACCESS_TOKEN_TTL_SECONDS,
          jti: deps.random.token(16),
        };
        if (record.nonce) idClaims.nonce = record.nonce;
        if (record.authTime !== null) idClaims.auth_time = record.authTime;
        body.id_token = await deps.signer.sign(idClaims);
      }

      // Refresh token
      if (client.grantTypes.includes('refresh_token') && scopesList.length > 0) {
        const rtJti = deps.random.token(24);
        await deps.store.saveRefreshToken({
          jti: rtJti, clientId: client.clientId, subject: record.subject,
          scope: scopes, expiresAt: iat + refreshTtl,
          family: rtJti, // each auth code creates a new family
          parentJti: null, revokedByReplayAt: null, revokedAt: null,
        });
        body.refresh_token = rtJti;
      }

      return reply.header('pragma', 'no-cache').send(body);
    }

    // -- client_credentials --
    if (grantType === 'client_credentials') {
      const client = await authenticateClient(deps, req, form);
      // public clients may not use client_credentials
      if (client.clientSecretHash === null) throw new OAuthError('invalid_client', 'public clients cannot use client_credentials');
      if (!client.grantTypes.includes('client_credentials')) throw new OAuthError('unauthorized_client');

      const scope = (single(form, 'scope') ?? '').trim();
      const scopesList = scope ? scope.split(' ') : [];
      if (scopesList.some((s) => !client.scopes.includes(s))) throw new OAuthError('invalid_scope');

      const iat = deps.clock.now();
      const atJti = deps.random.token(16);
      const claims: Record<string, unknown> = {
        iss: deps.issuer,
        sub: client.clientId,
        aud: client.clientId,
        client_id: client.clientId,
        iat,
        exp: iat + ACCESS_TOKEN_TTL_SECONDS,
        jti: atJti,
      };
      if (scope) claims.scope = scope;
      const accessToken = await deps.signer.sign(claims);

      await deps.store.saveAccessToken({
        jti: atJti, clientId: client.clientId, subject: client.clientId,
        scope, expiresAt: iat + ACCESS_TOKEN_TTL_SECONDS, revokedAt: null, tokenHash: null,
      });

      return reply.header('pragma', 'no-cache').send({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        ...(scope ? { scope } : {}),
      });
    }

    // -- refresh_token --
    if (grantType === 'refresh_token') {
      const client = await authenticateClient(deps, req, form);
      if (!client.grantTypes.includes('refresh_token')) throw new OAuthError('unauthorized_client');

      const rtValue = single(form, 'refresh_token');
      if (!rtValue) throw new OAuthError('invalid_request', 'refresh_token is required');

      // Check client binding BEFORE consuming (don't burn someone else's token).
      const lookedUp = await deps.store.getRefreshToken(rtValue, deps.clock.now());
      if (!lookedUp || lookedUp.clientId !== client.clientId) {
        throw new OAuthError('invalid_grant', 'refresh token is invalid, expired or already used');
      }

      const consumed = await deps.store.consumeRefreshToken(rtValue, deps.clock.now());
      if (!consumed) throw new OAuthError('invalid_grant', 'refresh token is invalid, expired or already used');

      // Check replay: if the family was revoked by replay, fail.
      if (consumed.revokedByReplayAt !== null) throw new OAuthError('invalid_grant');

      let allowedScope = consumed.scope;
      const requestedScope = single(form, 'scope');
      if (requestedScope !== undefined) {
        const requested = requestedScope.split(' ').filter((s) => s !== '');
        // Cannot escalate
        const originalScopes = new Set(consumed.scope.split(' '));
        if (requested.some((s) => !originalScopes.has(s))) throw new OAuthError('invalid_scope');
        allowedScope = requested.join(' ');
      }

      const iat = deps.clock.now();
      const scopesList = allowedScope ? allowedScope.split(' ') : [];
      const includesOpenid = scopesList.includes('openid');

      const atJti = deps.random.token(16);
      const claims: Record<string, unknown> = {
        iss: deps.issuer,
        sub: consumed.subject,
        aud: client.clientId,
        client_id: client.clientId,
        iat,
        exp: iat + ACCESS_TOKEN_TTL_SECONDS,
        jti: atJti,
      };
      if (allowedScope) claims.scope = allowedScope;
      const accessToken = await deps.signer.sign(claims);

      await deps.store.saveAccessToken({
        jti: atJti, clientId: client.clientId, subject: consumed.subject,
        scope: allowedScope, expiresAt: iat + ACCESS_TOKEN_TTL_SECONDS, revokedAt: null, tokenHash: null,
      });

      const rtJti = deps.random.token(24);
      await deps.store.saveRefreshToken({
        jti: rtJti, clientId: client.clientId, subject: consumed.subject,
        scope: allowedScope, expiresAt: iat + refreshTtl,
        family: consumed.family,
        parentJti: consumed.jti,
        revokedByReplayAt: null, revokedAt: null,
      });

      const body: Record<string, unknown> = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        refresh_token: rtJti,
        ...(allowedScope ? { scope: allowedScope } : {}),
      };

      if (includesOpenid) {
        const idClaims: Record<string, unknown> = {
          iss: deps.issuer, sub: consumed.subject, aud: client.clientId,
          iat, exp: iat + ACCESS_TOKEN_TTL_SECONDS, jti: deps.random.token(16),
        };
        body.id_token = await deps.signer.sign(idClaims);
      }

      return reply.header('pragma', 'no-cache').send(body);
    }

    // -- device_code (RFC 8628 §3.4) --
    if (grantType === 'urn:ietf:params:oauth:grant-type:device_code' || grantType === 'device_code') {
      const client = await authenticateClient(deps, req, form);
      if (!client.clientSecretHash) throw new OAuthError('invalid_client', 'public clients cannot use device_code');
      if (!client.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code') &&
          !client.grantTypes.includes('device_code')) {
        throw new OAuthError('unauthorized_client', 'client is not allowed to use device_code grant');
      }
      const deviceCode = single(form, 'device_code');
      if (!deviceCode) throw new OAuthError('invalid_request', 'device_code is required');
      const hash = sha256Hex(deviceCode);
      return deviceCodeGrant(deps, client, hash);
    }

    throw new OAuthError('unsupported_grant_type');
  });

  // -- Revocation --
  app.post('/oauth/revoke', async (req, reply) => {
    const form = req.body;
    if (!(form instanceof URLSearchParams)) {
      throw new OAuthError('invalid_request', 'content-type must be application/x-www-form-urlencoded');
    }
    const token = single(form, 'token');
    if (!token) {
      return reply.status(200).send(); // RFC 7009 §2.2: 200 even for missing token
    }

    // Require client authentication (RFC 7009 §2.1).
    const client = await authenticateClient(deps, req, form).catch(() => null);
    if (!client) {
      throw new OAuthError('invalid_client', 'revocation requires client authentication');
    }

    const hint = single(form, 'token_type_hint');
    const now = deps.clock.now();

    // RFC 7009 §2.1: the hint is only an optimisation; if the token is not of
    // the hinted type the server MUST extend its search across all types.
    const revokeAccess = async (): Promise<boolean> => {
      const decoded = await verifyAccessJwt(deps, token);
      if (!decoded?.jti) return false;
      const stored = await deps.store.getAccessToken(String(decoded.jti), now);
      if (!stored || stored.clientId !== client.clientId) return false;
      await deps.store.revokeAccessToken(String(decoded.jti), now);
      return true;
    };
    const revokeRefresh = async (): Promise<boolean> => {
      const rt = await deps.store.getRefreshToken(token, now);
      if (!rt || rt.clientId !== client.clientId) return false;
      await deps.store.revokeRefreshToken(token, now);
      return true;
    };
    if (hint === 'refresh_token') {
      if (!(await revokeRefresh())) await revokeAccess();
    } else if (!(await revokeAccess())) {
      await revokeRefresh();
    }

    return reply.status(200).send();
  });

  // -- Introspection --
  app.post('/oauth/introspect', async (req) => {
    const form = req.body;
    if (!(form instanceof URLSearchParams)) {
      throw new OAuthError('invalid_request', 'content-type must be application/x-www-form-urlencoded');
    }
    // Require caller authentication (RFC 7662 §2.1)
    let client: ClientRecord;
    try {
      client = await authenticateClient(deps, req, form);
    } catch {
      throw new OAuthError('invalid_client', 'introspection requires client authentication');
    }

    const token = single(form, 'token');
    if (!token) {
      return { active: false };
    }
    const hint = single(form, 'token_type_hint');
    const now = deps.clock.now();

    const inactive = { active: false };

    // Try access token (JWT) when hint is not explicitly refresh_token.
    if (hint !== 'refresh_token') {
      const decoded = await verifyAccessJwt(deps, token);
      if (decoded && decoded.jti) {
        const stored = await deps.store.getAccessToken(String(decoded.jti), now);
        if (stored) {
          // Cross-client protection: only return details to the owning client.
          if (stored.clientId !== client.clientId) return inactive;

          return {
            active: true,
            scope: stored.scope || undefined,
            client_id: stored.clientId,
            token_type: 'Bearer',
            exp: stored.expiresAt,
            iat: typeof decoded.iat === 'number' ? decoded.iat : undefined,
            jti: stored.jti,
            sub: stored.subject,
          };
        }
      }
    }

    // Refresh tokens: not introspectable per RFC 7662 §2.2.
    return inactive;
  });

  // -- JWKS --
  app.get('/.well-known/jwks.json', async (_req, reply) => {
    const jwks = await deps.signer.publicJwks();
    return reply.header('content-type', 'application/json').send(jwks);
  });

  // -- Discovery --
  const serverMetadata = {
    issuer: deps.issuer,
    authorization_endpoint: `${deps.issuer}/oauth/authorize`,
    token_endpoint: `${deps.issuer}/oauth/token`,
    jwks_uri: `${deps.issuer}/.well-known/jwks.json`,
    userinfo_endpoint: `${deps.issuer}/oauth/userinfo`,
    revocation_endpoint: `${deps.issuer}/oauth/revoke`,
    introspection_endpoint: `${deps.issuer}/oauth/introspect`,
    device_authorization_endpoint: `${deps.issuer}/oauth/device_authorization`,
    pushed_authorization_request_endpoint: `${deps.issuer}/oauth/par`,
    registration_endpoint: `${deps.issuer}/connect/register`,
    scopes_supported: ['openid', 'profile', 'email'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['ES256'],
  } as const;

  app.get('/.well-known/oauth-authorization-server', async (_req, reply) => {
    return reply.header('content-type', 'application/json').send(serverMetadata);
  });

  app.get('/.well-known/openid-configuration', async (_req, reply) => {
    return reply.header('content-type', 'application/json').send(serverMetadata);
  });

  // -- UserInfo --
  app.get('/oauth/userinfo', async (req, reply) => {
    const token = bearerToken(req);
    if (!token) {
      return reply.status(401).header('www-authenticate', 'Bearer').send({ error: 'invalid_token' });
    }

    // Verify the JWT
    const payload = await verifyAccessJwt(deps, token);
    if (!payload) {
      return reply.status(401).header('www-authenticate', 'Bearer error="invalid_token"').send({ error: 'invalid_token' });
    }

    // Verify token is still alive in store (not revoked)
    const jti = payload.jti as string | undefined;
    const stored = jti ? await deps.store.getAccessToken(jti, deps.clock.now()) : null;
    // A client_credentials token represents an application, not an end-user (sub === client_id).
    if (!stored || payload.sub === payload.client_id) {
      return reply.status(401).header('www-authenticate', 'Bearer error="invalid_token"').send({ error: 'invalid_token' });
    }
    const claims = claimsForScope(stored.scope, deps.userClaims?.(stored.subject) ?? null);
    return reply.header('content-type', 'application/json').send({ ...claims, sub: payload.sub });
  });

  // -- RP-initiated logout (OIDC RP-Initiated Logout 1.0 §2) --
  app.get('/oauth/logout', async (req, reply) => {
    const params = new URL(req.url, 'http://localhost').searchParams;
    rejectDuplicates(params);
    const hint = single(params, 'id_token_hint');
    if (hint !== undefined) {
      // The hint must be our own ID token (signature, issuer) addressed to a registered client.
      // Expiry is ignored: RPs commonly present an expired hint.
      let aud: unknown;
      try {
        const payload = await verifyOwnJwt(deps, hint, true);
        aud = payload.aud;
      } catch {
        throw new OAuthError('invalid_request', 'id_token_hint is not a valid ID token');
      }
      const audiences = Array.isArray(aud) ? aud : [aud];
      let registered = false;
      for (const a of audiences) if (typeof a === 'string' && (await deps.store.getClient(a))) registered = true;
      if (!registered) throw new OAuthError('invalid_request', 'id_token_hint audience is not a registered client');
    }
    deps.endSession?.(req, reply);
    return reply.status(200).header('content-type', 'text/plain; charset=utf-8').send('logged out');
  });
}

/**
 * Verify an access-token JWT's signature, issuer and expiry against the
 * server's own key. Returns null for anything unverifiable: claims from an
 * unverified payload must never drive ownership or revocation decisions.
 */
async function verifyAccessJwt(deps: OAuthDeps, token: string): Promise<Record<string, unknown> | null> {
  try {
    const jwks = await deps.signer.publicJwks();
    const { jwtVerify, importJWK } = await import('jose');
    const key = await importJWK(jwks.keys[0] as unknown as import('jose').JWK, 'ES256');
    const result = await jwtVerify(token, key, {
      issuer: deps.issuer,
      algorithms: ['ES256'],
      currentDate: new Date(deps.clock.now() * 1000),
    });
    return result.payload as Record<string, unknown>;
  } catch {
    return null;
  }
}
/** Verify a JWT this server signed (signature and issuer). `ignoreExpiry` is for id_token_hint only. */
async function verifyOwnJwt(deps: OAuthDeps, token: string, ignoreExpiry: boolean): Promise<Record<string, unknown>> {
  const jwks = await deps.signer.publicJwks();
  const { jwtVerify, importJWK } = await import('jose');
  const key = await importJWK(jwks.keys[0] as unknown as import('jose').JWK, 'ES256');
  const result = await jwtVerify(token, key, {
    issuer: deps.issuer,
    algorithms: ['ES256'],
    currentDate: ignoreExpiry ? new Date(0) : new Date(deps.clock.now() * 1000),
  });
  return result.payload as Record<string, unknown>;
}
