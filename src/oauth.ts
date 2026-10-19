import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { hashClientSecret, verifyClientSecret } from './client-auth.js';
import { OAuthError } from './errors.js';
import type { ClientRecord, Clock, Random, Signer, Store } from './ports.js';

export const CODE_TTL_SECONDS = 60;
export const ACCESS_TOKEN_TTL_SECONDS = 3600;
/** Unset unless the caller passes a value. */
const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 86_400; // 24h default

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
}

// RFC 7636 §4.1/§4.2: verifier 43-128 unreserved chars; S256 challenge is 43 base64url chars.
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;

const sha256Hex = (value: string): string => createHash('sha256').update(value).digest('hex');

/** Read a single-valued parameter. Repeated parameters are rejected (RFC 6749 §3.1); empty means absent. */
function single(params: URLSearchParams, name: string): string | undefined {
  const all = params.getAll(name);
  if (all.length > 1) throw new OAuthError('invalid_request', `duplicate parameter: ${name}`);
  return all[0] === undefined || all[0] === '' ? undefined : all[0];
}

function rejectDuplicates(params: URLSearchParams): void {
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

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

function formDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    throw new OAuthError('invalid_client', 'malformed client credentials');
  }
}

async function authenticateClient(deps: OAuthDeps, req: FastifyRequest, form: URLSearchParams): Promise<ClientRecord> {
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

function bearerToken(req: FastifyRequest): string | undefined {
  const h = req.headers.authorization;
  if (!h) return undefined;
  const m = /^Bearer (.+)$/i.exec(h);
  return m ? m[1] : undefined;
}

export function registerOAuthRoutes(app: FastifyInstance, deps: OAuthDeps): void {
  const refreshTtl = deps.refreshTokenTtl ?? DEFAULT_REFRESH_TOKEN_TTL_SECONDS;

  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    done(null, new URLSearchParams(body as string));
  });

  app.get('/oauth/authorize', async (req, reply) => {
    const params = new URL(req.url, 'http://localhost').searchParams;
    // Until client and redirect_uri are trusted, errors are shown to the user agent and never redirected.
    rejectDuplicates(params);
    const clientId = single(params, 'client_id');
    const redirectUri = single(params, 'redirect_uri');
    if (!clientId || !redirectUri) throw new OAuthError('invalid_request', 'client_id and redirect_uri are required');
    const client = await deps.store.getClient(clientId);
    if (!client || !client.enabled || !client.redirectUris.includes(redirectUri)) {
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

    const subject = deps.authenticate ? await deps.authenticate(req) : null;
    if (!subject) {
      if (deps.loginPath !== undefined) return reply.status(302).header('location', deps.loginPath).send();
      return fail('access_denied');
    }
    if (deps.consent && !deps.consent(subject, client.clientId)) return fail('access_denied');

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
      const decoded = decodeJwtSafe(token);
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
      const decoded = decodeJwtSafe(token);
      if (decoded && decoded.jti) {
        const stored = await deps.store.getAccessToken(String(decoded.jti), now);
        if (stored) {
          // Cross-client protection: only return details to the owning client.
          if (stored.clientId !== client.clientId && decoded.aud !== client.clientId) return inactive;

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
    scopes_supported: ['openid', 'profile', 'email'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
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
    let payload: Record<string, unknown>;
    try {
      const jwks = await deps.signer.publicJwks();
      const { jwtVerify: verify, importJWK } = await import('jose');
      const key = await importJWK(jwks.keys[0] as unknown as import('jose').JWK, 'ES256');
      const result = await verify(token, key, { issuer: deps.issuer, currentDate: new Date(deps.clock.now() * 1000) });
      payload = result.payload as Record<string, unknown>;
    } catch {
      return reply.status(401).header('www-authenticate', 'Bearer error="invalid_token"').send({ error: 'invalid_token' });
    }

    // Verify token is still alive in store (not revoked)
    const jti = payload.jti as string | undefined;
    if (jti) {
      const stored = await deps.store.getAccessToken(jti, deps.clock.now());
      if (!stored) {
        return reply.status(401).header('www-authenticate', 'Bearer error="invalid_token"').send({ error: 'invalid_token' });
      }
    } else {
      return reply.status(401).header('www-authenticate', 'Bearer error="invalid_token"').send({ error: 'invalid_token' });
    }

    return reply.header('content-type', 'application/json').send({ sub: payload.sub });
  });
}

/** Safe JWT decode that doesn't throw for malformed tokens. */
function decodeJwtSafe(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1]!, 'base64url').toString('utf8');
    const obj = JSON.parse(payload);
    if (typeof obj !== 'object' || obj === null) return null;
    return obj as Record<string, unknown>;
  } catch {
    return null;
  }
}