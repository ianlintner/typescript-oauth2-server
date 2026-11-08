import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { OAuthError } from './errors.js';
import { validateJwksUri } from './jwks.js';
import type { Clock, Random, Store, TrustedIssuerRecord } from './ports.js';

const ALLOWED_SUBJECT_MAPPINGS = ['sub', 'email'] as const;

export interface AdminTrustedIssuerDeps {
  store: Store;
  random: Random;
  clock: Clock;
}

/**
 * Admin registry for trusted issuers backing the RFC 7523 jwt-bearer grant.
 * Endpoints mirror the reference (`GET/POST /admin/trusted-issuers`,
 * `DELETE /admin/trusted-issuers/{id}`). These are administrative and are only
 * bound to a trusted interface in production; this module registers no auth.
 */
export function registerAdminTrustedIssuerRoutes(app: FastifyInstance, deps: AdminTrustedIssuerDeps): void {
  // POST /admin/trusted-issuers — register (or upsert) a trusted issuer.
  app.post('/admin/trusted-issuers', async (req: FastifyRequest, reply: FastifyReply) => {
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

    const allowedAudiences = Array.isArray(body.allowed_audiences)
      ? body.allowed_audiences.filter((a): a is string => typeof a === 'string')
      : [];
    const allowedClientIds = Array.isArray(body.allowed_client_ids)
      ? body.allowed_client_ids.filter((a): a is string => typeof a === 'string')
      : [];
    const subjectMapping = (body.subject_mapping ?? 'sub') as string;
    if (!ALLOWED_SUBJECT_MAPPINGS.includes(subjectMapping as (typeof ALLOWED_SUBJECT_MAPPINGS)[number])) {
      throw new OAuthError('invalid_request', `subject_mapping must be one of: ${ALLOWED_SUBJECT_MAPPINGS.join(', ')}`);
    }
    const enabled = body.enabled === undefined ? true : body.enabled === true;

    const now = deps.clock.now();
    const existing = await deps.store.getTrustedIssuer(issuer);
    const record: TrustedIssuerRecord = {
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
    await deps.store.saveTrustedIssuer(record);
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
  app.get('/admin/trusted-issuers', async (_req, reply) => {
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
  app.delete<{ Params: { id: string } }>('/admin/trusted-issuers/:id', async (req, reply) => {
    const id = req.params.id;
    const removed = await deps.store.deleteTrustedIssuer(id);
    if (!removed) throw new OAuthError('invalid_request', 'unknown trusted issuer id');
    return reply.send({ message: 'Trusted issuer deleted' });
  });
}