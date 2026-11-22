import { importJWK, jwtVerify, type JWK } from 'jose';
import { OAuthError } from './errors.js';
import type { ClientRecord } from './ports.js';
import type { OAuthDeps } from './oauth.js';

/**
 * RFC 8693 OAuth 2.0 Token Exchange, ported from the Rust reference's
 * `token_exchange.rs`. Only tokens this server issued (and still has on record,
 * unrevoked and unexpired) can be exchanged; the result is narrowed, never widened,
 * in scope, audience, lifetime and sender constraint.
 *
 * RFC 8693 §2.2.2 makes every invalid or policy-unacceptable subject/actor token an
 * `invalid_request`; the reference answers some of these with `invalid_grant`, and
 * the RFC wins here.
 */
export const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const TOKEN_TYPE_ACCESS = 'urn:ietf:params:oauth:token-type:access_token';
export const TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';
const ACCEPTED_TOKEN_TYPES: ReadonlySet<string> = new Set([TOKEN_TYPE_ACCESS, TOKEN_TYPE_JWT]);
const DEFAULT_MAX_DELEGATION_DEPTH = 4;
const SUB_PROFILE_SERVICE = 'service';

/** One level of an RFC 8693 §4.1 `act` chain. */
interface Actor {
  sub: string;
  iss: string;
  sub_profile?: string;
}

interface ResolvedToken {
  sub: string;
  clientId: string;
  scope: string[];
  /** Effective audience; `[clientId]` when the token carries no resource restriction. */
  aud: string[];
  exp: number;
  /** Levels of the carried `act` chain, outermost first. */
  act: Actor[];
  mayAct: unknown;
  /** Grant that produced this token, so downstream exchanges inherit its revocation scope. */
  grant: string | null;
  cnf: Record<string, unknown> | null;
}

const reject = (description: string): never => {
  throw new OAuthError('invalid_request', description);
};

const scopeList = (scope: string | undefined): string[] => (scope ?? '').split(/\s+/).filter((s) => s !== '');

const asStringList = (v: unknown): string[] | null => {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v as string[];
  return null;
};

/**
 * Parse an `act` claim into its levels (outermost first). Iterative on purpose: the
 * nesting is attacker-influenced data, and a level count above `maxDepth` is refused
 * before the walk goes any further.
 */
function parseActChain(value: unknown, maxDepth: number, which: string): Actor[] {
  const levels: Actor[] = [];
  let current: unknown = value;
  while (current !== undefined && current !== null) {
    if (levels.length >= maxDepth) return reject(`${which} act chain exceeds the maximum delegation depth of ${maxDepth}`);
    if (typeof current !== 'object' || Array.isArray(current)) return reject(`${which} carries a malformed act claim`);
    const o = current as Record<string, unknown>;
    if (typeof o.sub !== 'string' || o.sub === '') return reject(`${which} act chain level is missing a string sub`);
    if (typeof o.iss !== 'string' || o.iss === '') return reject(`${which} act chain level is missing a string iss`);
    const level: Actor = { sub: o.sub, iss: o.iss };
    if (o.sub_profile !== undefined && o.sub_profile !== null) {
      if (typeof o.sub_profile !== 'string') return reject(`${which} act chain sub_profile is not a string`);
      level.sub_profile = o.sub_profile;
    }
    levels.push(level);
    current = o.act;
  }
  return levels;
}

/** Rebuild a nested `act` claim from levels (outermost first). */
function actClaim(levels: Actor[]): Record<string, unknown> | undefined {
  let nested: Record<string, unknown> | undefined;
  for (let i = levels.length - 1; i >= 0; i--) nested = { ...levels[i], ...(nested ? { act: nested } : {}) };
  return nested;
}

/** Authenticate a subject/actor token: our own signature, issuer and expiry, and a live (unrevoked) store record. */
async function resolveToken(deps: OAuthDeps, raw: string, which: 'subject' | 'actor', maxDepth: number): Promise<ResolvedToken> {
  let payload: Record<string, unknown>;
  try {
    const jwks = await deps.signer.publicJwks();
    const key = await importJWK(jwks.keys[0] as unknown as JWK, 'ES256');
    payload = (await jwtVerify(raw, key, {
      issuer: deps.issuer,
      algorithms: ['ES256'],
      currentDate: new Date(deps.clock.now() * 1000),
    })).payload as Record<string, unknown>;
  } catch {
    return reject(`${which}_token is not a valid, unexpired access token issued by this server`);
  }
  // A JWT this server signed must also still be on record as an access token: that
  // refuses revoked tokens and anything else we sign (ID tokens carry no such record).
  const record = typeof payload.jti === 'string' ? await deps.store.getAccessToken(payload.jti, deps.clock.now()) : null;
  if (!record) return reject(`${which}_token is not a known, unrevoked access token`);
  if (record.clientId === '' || typeof payload.exp !== 'number') return reject(`${which}_token is not bound to a known client`);

  const aud = asStringList(payload.aud);
  let cnf: Record<string, unknown> | null = null;
  if (payload.cnf !== undefined) {
    if (typeof payload.cnf !== 'object' || payload.cnf === null || Array.isArray(payload.cnf)) return reject(`${which}_token carries a malformed cnf claim`);
    cnf = payload.cnf as Record<string, unknown>;
    // Only DPoP (jkt) binding is implemented; a token bound some other way cannot be proven possessed.
    if (Object.keys(cnf).some((k) => k !== 'jkt')) return reject(`${which}_token is bound by an unsupported confirmation method`);
  }
  return {
    sub: record.subject,
    clientId: record.clientId,
    scope: scopeList(record.scope),
    aud: aud && aud.length > 0 ? aud : [record.clientId],
    exp: payload.exp,
    act: parseActChain(payload.act, maxDepth, `${which}_token`),
    mayAct: payload.may_act,
    grant: record.grant ?? null,
    cnf,
  };
}

/** RFC 8693 §4.4: the subject token's `may_act` names the party permitted to act for it. */
function mayActAllows(mayAct: unknown, actorSub: string, issuer: string): boolean {
  if (typeof mayAct !== 'object' || mayAct === null || Array.isArray(mayAct)) return false;
  const m = mayAct as Record<string, unknown>;
  if (m.sub !== actorSub) return false;
  return m.iss === undefined || m.iss === issuer;
}

const allowsActor = (c: ClientRecord | null, requestingClientId: string): boolean => c?.allowedActors?.includes(requestingClientId) === true;

/** Target resources/audiences must be absolute URIs without a fragment (RFC 8707 §2). */
function validTarget(value: string): boolean {
  if (value.includes('#')) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

export interface TokenExchangeResult {
  body: Record<string, unknown>;
}

/**
 * Handle a token-exchange request for an already-authenticated, grant-authorized,
 * confidential client. `presentedJkt` is the thumbprint of a validated DPoP proof sent
 * with this request, or null.
 */
export async function tokenExchangeGrant(
  deps: OAuthDeps,
  client: ClientRecord,
  form: URLSearchParams,
  presentedJkt: string | null,
  accessTokenTtlSeconds: number,
): Promise<Record<string, unknown>> {
  const maxDepth = deps.maxDelegationDepth ?? DEFAULT_MAX_DELEGATION_DEPTH;
  const get = (name: string): string | undefined => {
    const v = form.get(name);
    return v === null || v.trim() === '' ? undefined : v;
  };

  const subjectToken = get('subject_token');
  const subjectTokenType = get('subject_token_type');
  if (!subjectToken) return reject('subject_token is required');
  if (!subjectTokenType) return reject('subject_token_type is required');
  if (!ACCEPTED_TOKEN_TYPES.has(subjectTokenType)) return reject(`unsupported subject_token_type '${subjectTokenType}'`);

  const actorToken = get('actor_token');
  const actorTokenType = get('actor_token_type');
  if (actorToken && !actorTokenType) return reject('actor_token_type is required with actor_token');
  if (!actorToken && actorTokenType) return reject('actor_token_type must not be sent without actor_token');
  if (actorTokenType && !ACCEPTED_TOKEN_TYPES.has(actorTokenType)) return reject(`unsupported actor_token_type '${actorTokenType}'`);

  const requestedTokenType = get('requested_token_type') ?? TOKEN_TYPE_ACCESS;
  if (!ACCEPTED_TOKEN_TYPES.has(requestedTokenType)) return reject(`unsupported requested_token_type '${requestedTokenType}'`);
  if (get('authorization_details') !== undefined) return reject('authorization_details is not supported by token exchange');

  // RFC 9449 §7: a sender-constrained token may only be exchanged by the holder of its key.
  // Applies to the actor token too: client authentication does not prove possession of its key.
  const requireKeyPossession = (t: ResolvedToken, which: 'subject' | 'actor'): void => {
    const jkt = t.cnf?.jkt;
    if (t.cnf !== null && (typeof jkt !== 'string' || jkt === '' || jkt !== presentedJkt)) {
      reject(`${which}_token is sender-constrained; a matching DPoP proof is required`);
    }
  };

  const subject = await resolveToken(deps, subjectToken, 'subject', maxDepth);
  requireKeyPossession(subject, 'subject');

  let actor: ResolvedToken | null = null;
  if (actorToken) {
    actor = await resolveToken(deps, actorToken, 'actor', maxDepth);
    if (actor.clientId !== client.clientId) return reject('actor_token was not issued to this client');
    requireKeyPossession(actor, 'actor');
  }

  // -- delegation policy and act chain --
  let act: Actor[];
  if (actor === null) {
    // No delegation is recorded, but the exchange still moves a token between clients:
    // the issuing client must have opted this client in through allowedActors.
    if (subject.clientId !== client.clientId && !allowsActor(await deps.store.getClient(subject.clientId), client.clientId)) {
      return reject('client is not authorized to exchange tokens issued to another client');
    }
    act = subject.act;
  } else {
    const allowed = mayActAllows(subject.mayAct, actor.sub, deps.issuer)
      || allowsActor(await deps.store.getClient(subject.clientId), client.clientId);
    if (!allowed) return reject('actor is not authorized to act for the subject');
    act = [{ sub: actor.sub, iss: deps.issuer, sub_profile: SUB_PROFILE_SERVICE }, ...subject.act];
    if (act.length > maxDepth) return reject(`act chain depth ${act.length} exceeds the maximum of ${maxDepth}`);
  }

  // -- target audience: may only narrow what the subject token already carries --
  const requestedTargets = [...new Set([get('resource'), get('audience')].filter((v): v is string => v !== undefined))];
  const subjectUnrestricted = subject.aud.length === 1 && subject.aud[0] === subject.clientId;
  let aud: string[];
  if (requestedTargets.length === 0) {
    aud = subjectUnrestricted ? [client.clientId] : subject.aud;
  } else {
    // No protected-resource registry exists in this port, so an unrestricted subject has no
    // registered target to narrow to: fail closed rather than let a caller name any audience.
    if (!requestedTargets.every(validTarget)) throw new OAuthError('invalid_target', 'resource and audience must be absolute URIs without a fragment');
    if (subjectUnrestricted || !requestedTargets.every((t) => subject.aud.includes(t))) {
      throw new OAuthError('invalid_target', "requested target is not within the subject token's audience");
    }
    aud = requestedTargets;
  }

  // -- scope: requested ⊆ subject ⊆ (and within) exchanging client --
  const requestedScope = scopeList(get('scope'));
  const scope = requestedScope.length > 0 ? requestedScope : subject.scope;
  if (scope.some((s) => !subject.scope.includes(s))) throw new OAuthError('invalid_scope', "requested scope exceeds the subject token's scope");
  if (scope.some((s) => !client.scopes.includes(s))) throw new OAuthError('invalid_scope', 'requested scope exceeds client permissions');

  // -- issue --
  const now = deps.clock.now();
  // The new token never outlives the token it was exchanged from.
  const exp = Math.min(now + accessTokenTtlSeconds, subject.exp);
  const jti = deps.random.token(16);
  const claims: Record<string, unknown> = {
    iss: deps.issuer,
    sub: subject.sub,
    aud: aud.length === 1 ? aud[0] : aud,
    client_id: client.clientId,
    iat: now,
    exp,
    jti,
  };
  if (scope.length > 0) claims.scope = scope.join(' ');
  if (presentedJkt) claims.cnf = { jkt: presentedJkt };
  const issuedAct = actClaim(act);
  if (issuedAct) claims.act = issuedAct;
  const accessToken = await deps.signer.sign(claims);
  await deps.store.saveAccessToken({
    jti, clientId: client.clientId, subject: subject.sub, scope: scope.join(' '),
    expiresAt: exp, revokedAt: null, tokenHash: null, grant: subject.grant,
  });

  // RFC 8693 §2.2.1: delegation is expressed inside the issued token, not as a response member.
  return {
    access_token: accessToken,
    issued_token_type: requestedTokenType,
    token_type: presentedJkt ? 'DPoP' : 'Bearer',
    expires_in: exp - now,
    ...(scope.length > 0 ? { scope: scope.join(' ') } : {}),
  };
}
