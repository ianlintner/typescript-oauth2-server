import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { hashClientSecret, verifyClientSecret } from './client-auth.js';
import { OAuthError } from './errors.js';
import type { ClientRecord, Clock, Random, Signer, Store } from './ports.js';

export const CODE_TTL_SECONDS = 60;
export const ACCESS_TOKEN_TTL_SECONDS = 3600;

export interface OAuthDeps {
  store: Store;
  signer: Signer;
  clock: Clock;
  random: Random;
  issuer: string;
  /**
   * Resolves the authenticated resource owner for an authorization request.
   * Login/consent UI is out of scope for this slice; when absent or when it
   * returns null the request fails closed with access_denied.
   */
  authenticate?: ((req: FastifyRequest) => Promise<string | null>) | undefined;
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

export function registerOAuthRoutes(app: FastifyInstance, deps: OAuthDeps): void {
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    done(null, new URLSearchParams(body as string));
  });

  let dummyHash: Promise<string> | undefined;

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
    if (!subject) return fail('access_denied');

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
    });
    return redirectTo(reply, redirectUri, { code, state, iss: deps.issuer });
  });

  async function authenticateClient(req: FastifyRequest, form: URLSearchParams): Promise<ClientRecord> {
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
      dummyHash ??= hashClientSecret('dummy-secret');
      await verifyClientSecret(secret ?? '', await dummyHash);
      throw invalid;
    }
    if (client.clientSecretHash === null) {
      if (secret) throw invalid; // public clients never authenticate with a secret
      return client;
    }
    if (!secret || !(await verifyClientSecret(secret, client.clientSecretHash))) throw invalid;
    return client;
  }

  app.post('/oauth/token', async (req, reply) => {
    const form = req.body;
    if (!(form instanceof URLSearchParams)) {
      throw new OAuthError('invalid_request', 'content-type must be application/x-www-form-urlencoded');
    }
    rejectDuplicates(form);
    const grantType = single(form, 'grant_type');
    if (!grantType) throw new OAuthError('invalid_request', 'grant_type is required');
    if (grantType !== 'authorization_code') throw new OAuthError('unsupported_grant_type');

    const client = await authenticateClient(req, form);
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
    const claims: Record<string, unknown> = {
      iss: deps.issuer,
      sub: record.subject,
      aud: client.clientId,
      client_id: client.clientId,
      iat,
      exp: iat + ACCESS_TOKEN_TTL_SECONDS,
      jti: deps.random.token(16),
    };
    if (record.scope !== '') claims.scope = record.scope;
    const accessToken = await deps.signer.sign(claims);
    return reply.header('pragma', 'no-cache').send({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      ...(record.scope !== '' ? { scope: record.scope } : {}),
    });
  });
}
