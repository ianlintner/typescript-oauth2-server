import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { OAuthError } from './errors.js';
import { validateJwksUri } from './jwks.js';
import { safeEqual } from './oauth.js';
import type { Clock, Random, Store, TrustedIssuerRecord } from './ports.js';

const ALLOWED_SUBJECT_MAPPINGS = ['sub', 'email'] as const;

export interface AdminTrustedIssuerDeps {
  store: Store;
  random: Random;
  clock: Clock;
  /**
   * Shared secret that authorizes calls to the administrative endpoints.
   * Fail-closed: when undefined, the routes are not registered at all, so an
   * operator who has not configured OAUTH2_ADMIN_TOKEN cannot expose admin
   * management of trusted issuers to the network.
   */
  adminToken: string | undefined;
}

/**
 * Admin registry for trusted issuers backing the RFC 7523 jwt-bearer grant.
 * Endpoints mirror the reference (`GET/POST /admin/trusted-issuers`,
 * `DELETE /admin/trusted-issuers/{id}`). Requests must present
 * `Authorization: Bearer <adminToken>` (constant-time comparison); when no
 * token is configured the module registers nothing, so these routes can never
 * unintentionally become public.
 */
export function registerAdminTrustedIssuerRoutes(app: FastifyInstance, deps: AdminTrustedIssuerDeps): void {
  if (!deps.adminToken) return;
  const authorize = async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const header = req.headers.authorization;
    const token = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
    if (!safeEqual(token, deps.adminToken!)) {
      // 401 with an OAuth-style body; the reference uses the same shape for its
      // Bearer branch (invalid_token / Bearer token is invalid).
      await reply.status(401).send({ error: 'invalid_token', error_description: 'a valid admin token is required' });
    }
  };
  // Register the admin routes in a scoped plugin whose preHandler runs before
  // every handler below, so the auth gate cannot be bypassed by a future route.
  void app.register(async (scope) => {
    scope.addHook('preHandler', authorize);

    // POST /admin/trusted-issuers — register (or upsert) a trusted issuer.
    scope.post('/admin/trusted-issuers', async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as
      | {
          issuer?: unknown; jwks?: unknown; jwks_uri?: unknown;
          allowed_audiences?: unknown; subject_mapping?: unknown; allowed_client_ids?: unknown;
          enabled?: unknown;
        }
      | undefined;
    if (!body || typeof body !== 'object') {
      throw new OAuthError('invalid_request', 'JSON body is required');
    }
    const issuer = typeof body.issuer === 'string' ? body.issuer.trim() : '';
    if (issuer === '') throw new OAuthError('invalid_request', 'issuer is required');

    // At least one key source is required; jwks_uri, when present, is SSRF-guarded.
    const jwks = body.jwks as TrustedIssuerRecord['jwks'] | undefined;
    const jwksUri = typeof body.jwks_uri === 'string' && body.jwks_uri !== '' ? body.jwks_uri : undefined;
    if (jwks === undefined && jwksUri === undefined) {
      throw new OAuthError('invalid_request', 'one of jwks or jwks_uri is required');
    }
    if (jwksUri !== undefined) {
      validateJwksUri(jwksUri);
    }
    if (jwks !== undefined && (!jwks || typeof jwks !== 'object' || !Array.isArray(jwks.keys))) {
      throw new OAuthError('invalid_request', 'jwks must be a JWKS document with a keys array');
    }
    if (jwks !== undefined) {
      // Reject private key material before persisting: this is a public verification-key
      // registry, so RFC 7517 private parameters must never be stored or echoed back.
      for (const k of jwks.keys as unknown[]) {
        if (typeof k !== 'object' || k === null) {
          throw new OAuthError('invalid_request', 'jwks keys must be objects');
        }
        for (const priv of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth']) {
          if (priv in (k as Record<string, unknown>)) {
            throw new OAuthError('invalid_request', 'jwks must contain public keys only');
          }
        }
      }
    }

    if (body.allowed_audiences !== undefined && !Array.isArray(body.allowed_audiences)) {
      throw new OAuthError('invalid_request', 'allowed_audiences must be an array of strings');
    }
    const allowedAudiences = body.allowed_audiences === undefined
      ? []
      : (body.allowed_audiences as unknown[]).map((a) => {
          if (typeof a !== 'string') throw new OAuthError('invalid_request', 'allowed_audiences must be an array of strings');
          return a;
        });
    if (body.allowed_client_ids !== undefined && !Array.isArray(body.allowed_client_ids)) {
      // Fail closed: an invalid restriction must not silently become an unrestricted issuer.
      throw new OAuthError('invalid_request', 'allowed_client_ids must be an array of strings');
    }
    const allowedClientIds = body.allowed_client_ids === undefined
      ? []
      : (body.allowed_client_ids as unknown[]).map((a) => {
          if (typeof a !== 'string') throw new OAuthError('invalid_request', 'allowed_client_ids must be an array of strings');
          return a;
        });
    const subjectMapping = (body.subject_mapping ?? 'sub') as string;
    if (!ALLOWED_SUBJECT_MAPPINGS.includes(subjectMapping as (typeof ALLOWED_SUBJECT_MAPPINGS)[number])) {
      throw new OAuthError('invalid_request', `subject_mapping must be one of: ${ALLOWED_SUBJECT_MAPPINGS.join(', ')}`);
    }
    const enabled = body.enabled === undefined ? true : body.enabled === true;

    const now = deps.clock.now();
    const record: TrustedIssuerRecord = await deps.store.transaction(async (tx) => {
      const existing = await tx.getTrustedIssuer(issuer);
      const built: TrustedIssuerRecord = {
        id: existing?.id ?? deps.random.token(16),
        issuer,
        ...(jwks !== undefined ? { jwks } : {}),
        ...(jwksUri !== undefined ? { jwksUri } : {}),
        allowedAudiences,
        allowedClientIds,
        subjectMapping: subjectMapping as TrustedIssuerRecord['subjectMapping'],
        enabled,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      await tx.saveTrustedIssuer(built);
      // Re-read so the persisted record (which may have won a concurrent INSERT's
      // unique-issuer conflict) is the one echoed to the caller, and its id is usable.
      return (await tx.getTrustedIssuer(issuer)) ?? built;
    });
    return reply.status(201).send({
      id: record.id,
      issuer: record.issuer,
      ...(record.jwks ? { jwks: record.jwks } : {}),
      ...(record.jwksUri ? { jwks_uri: record.jwksUri } : {}),
      allowed_audiences: record.allowedAudiences,
      allowed_client_ids: record.allowedClientIds,
      subject_mapping: record.subjectMapping,
      enabled: record.enabled,
    });
    });

    // GET /admin/trusted-issuers — list all.
    scope.get('/admin/trusted-issuers', async (_req, reply) => {
      const items = await deps.store.listTrustedIssuers();
      return reply.send({
        trusted_issuers: items.map((t) => ({
          id: t.id,
          issuer: t.issuer,
          ...(t.jwks ? { jwks: t.jwks } : {}),
          ...(t.jwksUri ? { jwks_uri: t.jwksUri } : {}),
          allowed_audiences: t.allowedAudiences,
          allowed_client_ids: t.allowedClientIds,
          subject_mapping: t.subjectMapping,
          enabled: t.enabled,
        })),
      });
    });

    // DELETE /admin/trusted-issuers/:id — remove by id.
    scope.delete<{ Params: { id: string } }>('/admin/trusted-issuers/:id', async (req, reply) => {
      const id = req.params.id;
      const removed = await deps.store.deleteTrustedIssuer(id);
      if (!removed) throw new OAuthError('invalid_request', 'unknown trusted issuer id');
      return reply.send({ message: 'Trusted issuer deleted' });
    });
  });
}