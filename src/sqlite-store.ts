import { DatabaseSync } from 'node:sqlite';
import type {
  AccessTokenRecord, AuthorizationCodeRecord, ClientRecord, DeviceCodeRecord, DeviceCodeStatus, ParRecord, RefreshTokenRecord, Store,
  TrustedIssuerRecord, WindowCount,
} from './ports.js';
import { REFRESH_ID_PREFIX } from './token-digest.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,
  redirect_uris TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  scopes TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  registration TEXT,
  token_endpoint_auth_method TEXT,
  client_secret_key TEXT,
  jwks TEXT,
  jwks_uri TEXT,
  resources TEXT,
  allowed_actors TEXT,
  require_signed_request_object INTEGER,
  authorization_details_types TEXT,
  post_logout_redirect_uris TEXT,
  backchannel_logout_uri TEXT,
  backchannel_logout_session_required INTEGER,
  frontchannel_logout_uri TEXT,
  frontchannel_logout_session_required INTEGER
);
CREATE TABLE IF NOT EXISTS authorization_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(client_id),
  redirect_uri TEXT NOT NULL,
  subject TEXT NOT NULL,
  scope TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  nonce TEXT,
  auth_time INTEGER,
  authorization_details TEXT
);
CREATE TABLE IF NOT EXISTS access_tokens (
  jti TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  token_hash TEXT,
  grant_id TEXT
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  jti TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  family TEXT NOT NULL,
  parent_jti TEXT,
  consumed_at INTEGER,
  revoked_at INTEGER,
  revoked_by_replay_at INTEGER,
  dpop_jkt TEXT,
  resource TEXT,
  authorization_details TEXT
);
CREATE TABLE IF NOT EXISTS device_codes (
  device_code_hash TEXT PRIMARY KEY,
  user_code_hash TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  interval INTEGER NOT NULL,
  last_polled_at INTEGER,
  status TEXT NOT NULL,
  subject TEXT
);
CREATE TABLE IF NOT EXISTS par_requests (
  request_uri_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS dpop_proofs (
  key TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_windows (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires ON authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON device_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_codes_client ON device_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_par_requests_expires ON par_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_par_requests_client ON par_requests(client_id);
CREATE INDEX IF NOT EXISTS idx_dpop_proofs_expires ON dpop_proofs(expires_at);
CREATE INDEX IF NOT EXISTS idx_rate_windows_expires ON rate_windows(expires_at);
CREATE TABLE IF NOT EXISTS trusted_issuers (
  id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL UNIQUE,
  jwks TEXT,
  jwks_uri TEXT,
  allowed_audiences TEXT NOT NULL,
  subject_mapping TEXT NOT NULL,
  allowed_client_ids TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);`;

interface ClientRow {
  client_id: string;
  client_secret_hash: string | null;
  redirect_uris: string;
  grant_types: string;
  scopes: string;
  enabled: number;
  registration: string | null;
  token_endpoint_auth_method: string | null;
  client_secret_key: string | null;
  jwks: string | null;
  jwks_uri: string | null;
  resources: string | null;
  allowed_actors: string | null;
  require_signed_request_object: number | null;
  authorization_details_types: string | null;
  post_logout_redirect_uris: string | null;
  backchannel_logout_uri: string | null;
  backchannel_logout_session_required: number | null;
  frontchannel_logout_uri: string | null;
  frontchannel_logout_session_required: number | null;
}

interface DeviceRow {
  device_code_hash: string;
  user_code_hash: string;
  client_id: string;
  scope: string;
  expires_at: number;
  interval: number;
  last_polled_at: number | null;
  status: string;
  subject: string | null;
}

interface ParRow {
  request_uri_hash: string;
  client_id: string;
  params: string;
  expires_at: number;
  consumed_at: number | null;
}

interface TrustedIssuerRow {
  id: string;
  issuer: string;
  jwks: string | null;
  jwks_uri: string | null;
  allowed_audiences: string;
  subject_mapping: string;
  allowed_client_ids: string;
  enabled: number;
  created_at: number;
  updated_at: number;
}

function rowToTrustedIssuer(r: TrustedIssuerRow): TrustedIssuerRecord {
  return {
    id: r.id,
    issuer: r.issuer,
    ...(r.jwks ? { jwks: JSON.parse(r.jwks) as TrustedIssuerRecord['jwks'] } : {}),
    ...(r.jwks_uri ? { jwksUri: r.jwks_uri } : {}),
    allowedAudiences: JSON.parse(r.allowed_audiences) as string[],
    subjectMapping: r.subject_mapping as 'sub' | 'email',
    allowedClientIds: JSON.parse(r.allowed_client_ids) as string[],
    enabled: r.enabled === 1,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function rowToDevice(r: DeviceRow): DeviceCodeRecord {
  return {
    deviceCodeHash: r.device_code_hash, userCodeHash: r.user_code_hash, clientId: r.client_id, scope: r.scope,
    expiresAt: r.expires_at, interval: r.interval, lastPolledAt: r.last_polled_at,
    status: r.status as DeviceCodeStatus, subject: r.subject,
  };
}

function rowToPar(r: ParRow): ParRecord {
  return {
    requestUriHash: r.request_uri_hash, clientId: r.client_id, params: JSON.parse(r.params) as Record<string, string>,
    expiresAt: r.expires_at, consumedAt: r.consumed_at,
  };
}

interface CodeRow {
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  subject: string;
  scope: string;
  code_challenge: string;
  expires_at: number;
  consumed_at: number | null;
  nonce: string | null;
  auth_time: number | null;
  authorization_details: string | null;
}

interface AccessTokenRow {
  jti: string;
  client_id: string;
  subject: string;
  scope: string;
  expires_at: number;
  revoked_at: number | null;
  token_hash: string | null;
  grant_id: string | null;
}

interface RefreshTokenRow {
  jti: string;
  client_id: string;
  subject: string;
  scope: string;
  expires_at: number;
  family: string;
  parent_jti: string | null;
  consumed_at: number | null;
  revoked_at: number | null;
  revoked_by_replay_at: number | null;
  dpop_jkt: string | null;
  resource: string | null;
  authorization_details: string | null;
}

function rowToAccessToken(r: AccessTokenRow): AccessTokenRecord {
  return {
    jti: r.jti,
    clientId: r.client_id,
    subject: r.subject,
    scope: r.scope,
    expiresAt: r.expires_at,
    revokedAt: r.revoked_at,
    tokenHash: r.token_hash,
    grant: r.grant_id,
  };
}

function rowToRefreshToken(r: RefreshTokenRow): RefreshTokenRecord {
  return {
    jti: r.jti,
    clientId: r.client_id,
    subject: r.subject,
    scope: r.scope,
    expiresAt: r.expires_at,
    family: r.family,
    parentJti: r.parent_jti,
    revokedByReplayAt: r.revoked_by_replay_at,
    revokedAt: r.revoked_at,
    dpopJkt: r.dpop_jkt,
    resource: r.resource,
    authorizationDetails: r.authorization_details === null ? undefined : JSON.parse(r.authorization_details) as unknown[],
  };
}

/** Statement-level operations on one connection. Stateless apart from the db it is handed. */
const ops = {
  health(db: DatabaseSync): void {
    db.prepare('SELECT 1').get();
  },

  saveClient(db: DatabaseSync, c: ClientRecord): void {
    db.prepare(
      `INSERT INTO clients (client_id, client_secret_hash, redirect_uris, grant_types, scopes, enabled, registration, token_endpoint_auth_method, client_secret_key, jwks, jwks_uri, resources, allowed_actors, require_signed_request_object, authorization_details_types, post_logout_redirect_uris, backchannel_logout_uri, backchannel_logout_session_required, frontchannel_logout_uri, frontchannel_logout_session_required)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(client_id) DO UPDATE SET client_secret_hash=excluded.client_secret_hash,
         redirect_uris=excluded.redirect_uris, grant_types=excluded.grant_types,
         scopes=excluded.scopes, enabled=excluded.enabled, registration=excluded.registration,
         token_endpoint_auth_method=excluded.token_endpoint_auth_method, client_secret_key=excluded.client_secret_key, jwks=excluded.jwks, jwks_uri=excluded.jwks_uri,
         resources=excluded.resources, allowed_actors=excluded.allowed_actors, require_signed_request_object=excluded.require_signed_request_object,
         authorization_details_types=excluded.authorization_details_types,
         post_logout_redirect_uris=excluded.post_logout_redirect_uris, backchannel_logout_uri=excluded.backchannel_logout_uri,
         backchannel_logout_session_required=excluded.backchannel_logout_session_required,
         frontchannel_logout_uri=excluded.frontchannel_logout_uri, frontchannel_logout_session_required=excluded.frontchannel_logout_session_required`,
    ).run(
      c.clientId, c.clientSecretHash, JSON.stringify(c.redirectUris), JSON.stringify(c.grantTypes), JSON.stringify(c.scopes),
      c.enabled ? 1 : 0, c.registration ? JSON.stringify(c.registration) : null,
      c.tokenEndpointAuthMethod ?? null, c.clientSecretKey ?? null, c.jwks ? JSON.stringify(c.jwks) : null, c.jwksUri ?? null,
      c.resources && c.resources.length > 0 ? JSON.stringify(c.resources) : null,
      c.allowedActors ? JSON.stringify(c.allowedActors) : null,
      c.requireSignedRequestObject === undefined ? null : (c.requireSignedRequestObject ? 1 : 0),
      c.authorizationDetailsTypesSupported ? JSON.stringify(c.authorizationDetailsTypesSupported) : null,
      c.postLogoutRedirectUris ? JSON.stringify(c.postLogoutRedirectUris) : null,
      c.backchannelLogoutUri ?? null,
      c.backchannelLogoutSessionRequired === undefined ? null : (c.backchannelLogoutSessionRequired ? 1 : 0),
      c.frontchannelLogoutUri ?? null,
      c.frontchannelLogoutSessionRequired === undefined ? null : (c.frontchannelLogoutSessionRequired ? 1 : 0),
    );
  },

  deleteClient(db: DatabaseSync, clientId: string): boolean {
    for (const table of ['authorization_codes', 'access_tokens', 'refresh_tokens', 'device_codes', 'par_requests']) {
      db.prepare(`DELETE FROM ${table} WHERE client_id = ?`).run(clientId);
    }
    return Number(db.prepare('DELETE FROM clients WHERE client_id = ?').run(clientId).changes) > 0;
  },

  saveDeviceCode(db: DatabaseSync, d: DeviceCodeRecord): void {
    db.prepare(
      `INSERT INTO device_codes (device_code_hash, user_code_hash, client_id, scope, expires_at, interval, last_polled_at, status, subject)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(d.deviceCodeHash, d.userCodeHash, d.clientId, d.scope, d.expiresAt, d.interval, d.lastPolledAt, d.status, d.subject);
  },

  getDeviceCode(db: DatabaseSync, hash: string): DeviceCodeRecord | null {
    const r = db.prepare('SELECT * FROM device_codes WHERE device_code_hash = ?').get(hash) as unknown as DeviceRow | undefined;
    return r ? rowToDevice(r) : null;
  },

  recordDevicePoll(db: DatabaseSync, hash: string, now: number, interval: number): void {
    db.prepare('UPDATE device_codes SET last_polled_at = ?, interval = ? WHERE device_code_hash = ?').run(now, interval, hash);
  },

  resolveDeviceCode(db: DatabaseSync, userCodeHash: string, status: 'approved' | 'denied', subject: string, now: number): boolean {
    const r = db
      .prepare(
        `UPDATE device_codes SET status = ?, subject = ?
         WHERE user_code_hash = ? AND status = 'pending' AND expires_at > ? RETURNING device_code_hash`,
      )
      .get(status, subject, userCodeHash, now);
    return r !== undefined;
  },

  consumeDeviceCode(db: DatabaseSync, hash: string, now: number): DeviceCodeRecord | null {
    const r = db
      .prepare(
        `UPDATE device_codes SET status = 'consumed'
         WHERE device_code_hash = ? AND status = 'approved' AND expires_at > ? RETURNING *`,
      )
      .get(hash, now) as unknown as DeviceRow | undefined;
    return r ? { ...rowToDevice(r), status: 'approved' } : null;
  },

  savePar(db: DatabaseSync, p: ParRecord): void {
    db.prepare('INSERT INTO par_requests (request_uri_hash, client_id, params, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?)')
      .run(p.requestUriHash, p.clientId, JSON.stringify(p.params), p.expiresAt, p.consumedAt);
  },

  getPar(db: DatabaseSync, hash: string, now: number): ParRecord | null {
    const r = db
      .prepare('SELECT * FROM par_requests WHERE request_uri_hash = ? AND consumed_at IS NULL AND expires_at > ?')
      .get(hash, now) as unknown as ParRow | undefined;
    return r ? rowToPar(r) : null;
  },

  consumePar(db: DatabaseSync, hash: string, clientId: string, now: number): ParRecord | null {
    const r = db
      .prepare(
        `UPDATE par_requests SET consumed_at = ?
         WHERE request_uri_hash = ? AND client_id = ? AND consumed_at IS NULL AND expires_at > ? RETURNING *`,
      )
      .get(now, hash, clientId, now) as unknown as ParRow | undefined;
    return r ? { ...rowToPar(r), consumedAt: now } : null;
  },

  getClient(db: DatabaseSync, clientId: string): ClientRecord | null {
    const r = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId) as unknown as ClientRow | undefined;
    if (!r) return null;
    return {
      clientId: r.client_id,
      clientSecretHash: r.client_secret_hash,
      redirectUris: JSON.parse(r.redirect_uris) as string[],
      grantTypes: JSON.parse(r.grant_types) as string[],
      scopes: JSON.parse(r.scopes) as string[],
      enabled: r.enabled === 1,
      ...(r.token_endpoint_auth_method ? { tokenEndpointAuthMethod: r.token_endpoint_auth_method } : {}),
      ...(r.client_secret_key ? { clientSecretKey: r.client_secret_key } : {}),
      ...(r.jwks ? { jwks: JSON.parse(r.jwks) as ClientRecord['jwks'] } : {}),
      ...(r.jwks_uri ? { jwksUri: r.jwks_uri } : {}),
      ...(r.resources ? { resources: JSON.parse(r.resources) as string[] } : {}),
      ...(r.allowed_actors ? { allowedActors: JSON.parse(r.allowed_actors) as string[] } : {}),
      ...(r.require_signed_request_object === 1 ? { requireSignedRequestObject: true } : {}),
      ...(r.authorization_details_types ? { authorizationDetailsTypesSupported: JSON.parse(r.authorization_details_types) as string[] } : {}),
      ...(r.registration ? { registration: JSON.parse(r.registration) as ClientRecord['registration'] } : {}),
      ...(r.post_logout_redirect_uris ? { postLogoutRedirectUris: JSON.parse(r.post_logout_redirect_uris) as string[] } : {}),
      ...(r.backchannel_logout_uri ? { backchannelLogoutUri: r.backchannel_logout_uri } : {}),
      ...(r.backchannel_logout_session_required === null ? {} : { backchannelLogoutSessionRequired: r.backchannel_logout_session_required === 1 }),
      ...(r.frontchannel_logout_uri ? { frontchannelLogoutUri: r.frontchannel_logout_uri } : {}),
      ...(r.frontchannel_logout_session_required === null ? {} : { frontchannelLogoutSessionRequired: r.frontchannel_logout_session_required === 1 }),
    };
  },

  // -- trusted issuers --

  saveTrustedIssuer(db: DatabaseSync, t: TrustedIssuerRecord): void {
    db.prepare(
      `INSERT INTO trusted_issuers (id, issuer, jwks, jwks_uri, allowed_audiences, subject_mapping, allowed_client_ids, enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(issuer) DO UPDATE SET jwks=excluded.jwks, jwks_uri=excluded.jwks_uri,
         allowed_audiences=excluded.allowed_audiences, subject_mapping=excluded.subject_mapping,
         allowed_client_ids=excluded.allowed_client_ids, enabled=excluded.enabled,
         updated_at=excluded.updated_at`,
    ).run(
      t.id, t.issuer, t.jwks ? JSON.stringify(t.jwks) : null, t.jwksUri ?? null,
      JSON.stringify(t.allowedAudiences), t.subjectMapping, JSON.stringify(t.allowedClientIds),
      t.enabled ? 1 : 0, t.createdAt, t.updatedAt,
    );
  },

  getTrustedIssuer(db: DatabaseSync, issuer: string): TrustedIssuerRecord | null {
    const r = db.prepare('SELECT * FROM trusted_issuers WHERE issuer = ?').get(issuer) as unknown as TrustedIssuerRow | undefined;
    return r ? rowToTrustedIssuer(r) : null;
  },

  listTrustedIssuers(db: DatabaseSync): TrustedIssuerRecord[] {
    const rows = db.prepare('SELECT * FROM trusted_issuers ORDER BY created_at').all() as unknown as TrustedIssuerRow[];
    return rows.map(rowToTrustedIssuer);
  },

  deleteTrustedIssuer(db: DatabaseSync, id: string): boolean {
    return Number(db.prepare('DELETE FROM trusted_issuers WHERE id = ?').run(id).changes) > 0;
  },

  saveCode(db: DatabaseSync, c: AuthorizationCodeRecord): void {
    db.prepare(
      `INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, subject, scope, code_challenge, expires_at, consumed_at, nonce, auth_time, authorization_details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(c.codeHash, c.clientId, c.redirectUri, c.subject, c.scope, c.codeChallenge, c.expiresAt,
      c.consumedAt, c.nonce ?? null, c.authTime ?? null,
      c.authorizationDetails === undefined || c.authorizationDetails === null ? null : JSON.stringify(c.authorizationDetails));
  },

  // Single conditional UPDATE ... RETURNING: the database decides the winner of a race.
  consumeCode(db: DatabaseSync, codeHash: string, now: number): AuthorizationCodeRecord | null {
    const r = db
      .prepare(
        `UPDATE authorization_codes SET consumed_at = ?
         WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?
         RETURNING *`,
      )
      .get(now, codeHash, now) as unknown as CodeRow | undefined;
    if (!r) return null;
    return {
      codeHash: r.code_hash,
      clientId: r.client_id,
      redirectUri: r.redirect_uri,
      subject: r.subject,
      scope: r.scope,
      codeChallenge: r.code_challenge,
      expiresAt: r.expires_at,
      consumedAt: r.consumed_at,
      nonce: r.nonce,
      authTime: r.auth_time,
      ...(r.authorization_details ? { authorizationDetails: JSON.parse(r.authorization_details) as unknown[] } : {}),
    };
  },

  // -- access tokens --

  saveAccessToken(db: DatabaseSync, t: AccessTokenRecord): void {
    db.prepare(
      `INSERT INTO access_tokens (jti, client_id, subject, scope, expires_at, revoked_at, token_hash, grant_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(t.jti, t.clientId, t.subject, t.scope, t.expiresAt, t.revokedAt, t.tokenHash, t.grant ?? null);
  },

  getAccessToken(db: DatabaseSync, jti: string, now: number): AccessTokenRecord | null {
    const r = db.prepare(
      'SELECT * FROM access_tokens WHERE jti = ? AND revoked_at IS NULL AND expires_at > ?',
    ).get(jti, now) as unknown as AccessTokenRow | undefined;
    return r ? rowToAccessToken(r) : null;
  },

  revokeAccessToken(db: DatabaseSync, jti: string, now: number): boolean {
    const res = db.prepare(
      'UPDATE access_tokens SET revoked_at = ? WHERE jti = ?',
    ).run(now, jti);
    return res.changes > 0;
  },

  // -- refresh tokens --

  saveRefreshToken(db: DatabaseSync, t: RefreshTokenRecord): void {
    db.prepare(
      `INSERT INTO refresh_tokens (jti, client_id, subject, scope, expires_at, family, parent_jti, consumed_at, revoked_at, revoked_by_replay_at, dpop_jkt, resource, authorization_details)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`,
    ).run(t.jti, t.clientId, t.subject, t.scope, t.expiresAt, t.family, t.parentJti, t.revokedAt, t.revokedByReplayAt, t.dpopJkt ?? null,
      t.resource ?? null,
      t.authorizationDetails === undefined || t.authorizationDetails === null ? null : JSON.stringify(t.authorizationDetails));
  },

  // INSERT OR IGNORE on the primary key: the database decides the winner across connections and processes.
  consumeDpopJti(db: DatabaseSync, key: string, expiresAt: number, now: number): boolean {
    db.prepare('DELETE FROM dpop_proofs WHERE expires_at <= ?').run(now);
    return Number(db.prepare('INSERT OR IGNORE INTO dpop_proofs (key, expires_at) VALUES (?, ?)').run(key, expiresAt).changes) === 1;
  },

  // One upsert: the database serializes concurrent hits, so no increment is lost across processes.
  recordWindowHit(db: DatabaseSync, key: string, windowSeconds: number, now: number): WindowCount {
    const r = db.prepare(
      `INSERT INTO rate_windows (key, count, expires_at) VALUES (?, 1, ?)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN rate_windows.expires_at <= ? THEN 1 ELSE rate_windows.count + 1 END,
         expires_at = CASE WHEN rate_windows.expires_at <= ? THEN excluded.expires_at ELSE rate_windows.expires_at END
       RETURNING count, expires_at`,
    ).get(key, now + windowSeconds, now, now) as unknown as { count: number; expires_at: number };
    return { count: Number(r.count), resetAt: Number(r.expires_at) };
  },

  peekWindow(db: DatabaseSync, key: string, now: number): WindowCount | null {
    const r = db.prepare('SELECT count, expires_at FROM rate_windows WHERE key = ? AND expires_at > ?')
      .get(key, now) as unknown as { count: number; expires_at: number } | undefined;
    return r ? { count: Number(r.count), resetAt: Number(r.expires_at) } : null;
  },

  countLiveRecords(db: DatabaseSync, kind: 'par' | 'device', now: number, clientId?: string): number {
    const table = kind === 'par' ? 'par_requests' : 'device_codes';
    const r = (clientId === undefined
      ? db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE expires_at > ?`).get(now)
      : db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE expires_at > ? AND client_id = ?`).get(now, clientId)) as unknown as { n: number };
    return Number(r.n);
  },

  sweepExpired(db: DatabaseSync, now: number): number {
    let removed = 0;
    for (const table of ['authorization_codes', 'access_tokens', 'refresh_tokens', 'device_codes', 'par_requests', 'dpop_proofs', 'rate_windows']) {
      removed += Number(db.prepare(`DELETE FROM ${table} WHERE expires_at <= ?`).run(now).changes);
    }
    return removed;
  },

  consumeRefreshToken(db: DatabaseSync, jti: string, now: number): RefreshTokenRecord | null {
    // First, check if this token exists and its state (without marking).
    const existing = db.prepare(
      'SELECT * FROM refresh_tokens WHERE jti = ?',
    ).get(jti) as unknown as RefreshTokenRow | undefined;

    if (!existing) return null;

    // If expired or revoked, not consumable.
    if (existing.expires_at <= now || existing.revoked_at !== null || existing.revoked_by_replay_at !== null) {
      return null;
    }

    // If already consumed, this is a replay. Revoke the family.
    if (existing.consumed_at !== null) {
      db.prepare(
        `UPDATE refresh_tokens SET revoked_by_replay_at = ?
         WHERE family = ? AND revoked_by_replay_at IS NULL AND revoked_at IS NULL`,
      ).run(now, existing.family);
      return null;
    }

    // Mark consumed.
    const r = db.prepare(
      `UPDATE refresh_tokens SET consumed_at = ?
       WHERE jti = ? AND consumed_at IS NULL AND revoked_at IS NULL AND revoked_by_replay_at IS NULL AND expires_at > ?
       RETURNING *`,
    ).get(now, jti, now) as unknown as RefreshTokenRow | undefined;
    if (!r) return null;

    // Ancestors of a rotated token are always consumed, so only the presented
    // token's own consumed state signals a replay (handled above).
    return rowToRefreshToken(r);
  },

  getRefreshToken(db: DatabaseSync, jti: string, now: number): RefreshTokenRecord | null {
    const row = db.prepare(
      'SELECT * FROM refresh_tokens WHERE jti = ?',
    ).get(jti) as unknown as RefreshTokenRow | undefined;
    if (!row) return null;
    if (row.expires_at <= now || row.revoked_at !== null || row.revoked_by_replay_at !== null) return null;
    return rowToRefreshToken(row);
  },

  revokeRefreshToken(db: DatabaseSync, jti: string, now: number): boolean {
    const res = db.prepare(
      'UPDATE refresh_tokens SET revoked_at = ? WHERE jti = ?',
    ).run(now, jti);
    return res.changes > 0;
  },

  revokeGrant(db: DatabaseSync, grant: string, now: number, clientId?: string): number {
    const client = clientId === undefined ? '' : ' AND client_id = ?';
    const extra = clientId === undefined ? [] : [clientId];
    db.prepare(
      `UPDATE access_tokens SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL${client}`,
    ).run(now, grant, ...extra);
    const res = db.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE family = ? AND revoked_at IS NULL AND revoked_by_replay_at IS NULL${client}`,
    ).run(now, grant, ...extra);
    return Number(res.changes);
  },

  countLegacyRefreshTokens(db: DatabaseSync): number {
    const r = db.prepare(`SELECT COUNT(*) AS n FROM refresh_tokens WHERE substr(jti, 1, ${REFRESH_ID_PREFIX.length}) != ?`)
      .get(REFRESH_ID_PREFIX) as unknown as { n: number };
    return Number(r.n);
  },

  purgeLegacyRefreshTokens(db: DatabaseSync): number {
    return Number(db.prepare(`DELETE FROM refresh_tokens WHERE substr(jti, 1, ${REFRESH_ID_PREFIX.length}) != ?`)
      .run(REFRESH_ID_PREFIX).changes);
  },
};

/**
 * Handle passed to a transaction callback. It is only valid until the
 * transaction commits or rolls back; afterwards every call rejects, so a leaked
 * handle can never write outside (or inside someone else's) transaction.
 */
class TxStore implements Store {
  #db: DatabaseSync | null;

  constructor(db: DatabaseSync) {
    this.#db = db;
  }

  end(): void {
    this.#db = null;
  }

  #use<T>(fn: (db: DatabaseSync) => T): Promise<T> {
    return Promise.resolve().then(() => {
      if (!this.#db) throw new Error('transaction has ended');
      return fn(this.#db);
    });
  }

  init(): Promise<void> {
    return Promise.reject(new Error('not available inside a transaction'));
  }
  close(): Promise<void> {
    return Promise.reject(new Error('not available inside a transaction'));
  }
  transaction<T>(): Promise<T> {
    return Promise.reject(new Error('nested transactions are not supported'));
  }
  healthcheck(): Promise<void> {
    return this.#use(ops.health);
  }
  saveClient(c: ClientRecord): Promise<void> {
    return this.#use((db) => ops.saveClient(db, c));
  }
  getClient(id: string): Promise<ClientRecord | null> {
    return this.#use((db) => ops.getClient(db, id));
  }
  deleteClient(id: string): Promise<boolean> {
    return this.#use((db) => ops.deleteClient(db, id));
  }
  saveTrustedIssuer(t: TrustedIssuerRecord): Promise<void> {
    return this.#use((db) => ops.saveTrustedIssuer(db, t));
  }
  getTrustedIssuer(issuer: string): Promise<TrustedIssuerRecord | null> {
    return this.#use((db) => ops.getTrustedIssuer(db, issuer));
  }
  listTrustedIssuers(): Promise<TrustedIssuerRecord[]> {
    return this.#use((db) => ops.listTrustedIssuers(db));
  }
  deleteTrustedIssuer(id: string): Promise<boolean> {
    return this.#use((db) => ops.deleteTrustedIssuer(db, id));
  }
  saveDeviceCode(d: DeviceCodeRecord): Promise<void> {
    return this.#use((db) => ops.saveDeviceCode(db, d));
  }
  getDeviceCode(h: string): Promise<DeviceCodeRecord | null> {
    return this.#use((db) => ops.getDeviceCode(db, h));
  }
  recordDevicePoll(h: string, now: number, interval: number): Promise<void> {
    return this.#use((db) => ops.recordDevicePoll(db, h, now, interval));
  }
  resolveDeviceCode(u: string, status: 'approved' | 'denied', subject: string, now: number): Promise<boolean> {
    return this.#use((db) => ops.resolveDeviceCode(db, u, status, subject, now));
  }
  consumeDeviceCode(h: string, now: number): Promise<DeviceCodeRecord | null> {
    return this.#use((db) => ops.consumeDeviceCode(db, h, now));
  }
  savePar(p: ParRecord): Promise<void> {
    return this.#use((db) => ops.savePar(db, p));
  }
  getPar(h: string, now: number): Promise<ParRecord | null> {
    return this.#use((db) => ops.getPar(db, h, now));
  }
  consumePar(h: string, c: string, now: number): Promise<ParRecord | null> {
    return this.#use((db) => ops.consumePar(db, h, c, now));
  }
  saveAuthorizationCode(c: AuthorizationCodeRecord): Promise<void> {
    return this.#use((db) => ops.saveCode(db, c));
  }
  consumeAuthorizationCode(codeHash: string, now: number): Promise<AuthorizationCodeRecord | null> {
    return this.#use((db) => ops.consumeCode(db, codeHash, now));
  }
  saveAccessToken(t: AccessTokenRecord): Promise<void> {
    return this.#use((db) => ops.saveAccessToken(db, t));
  }
  getAccessToken(jti: string, now: number): Promise<AccessTokenRecord | null> {
    return this.#use((db) => ops.getAccessToken(db, jti, now));
  }
  revokeAccessToken(jti: string, now: number): Promise<boolean> {
    return this.#use((db) => ops.revokeAccessToken(db, jti, now));
  }
  saveRefreshToken(t: RefreshTokenRecord): Promise<void> {
    return this.#use((db) => ops.saveRefreshToken(db, t));
  }
  consumeRefreshToken(jti: string, now: number): Promise<RefreshTokenRecord | null> {
    return this.#use((db) => ops.consumeRefreshToken(db, jti, now));
  }
  getRefreshToken(jti: string, now: number): Promise<RefreshTokenRecord | null> {
    return this.#use((db) => ops.getRefreshToken(db, jti, now));
  }
  revokeRefreshToken(jti: string, now: number): Promise<boolean> {
    return this.#use((db) => ops.revokeRefreshToken(db, jti, now));
  }
  consumeDpopJti(key: string, expiresAt: number, now: number): Promise<boolean> {
    return this.#use((db) => ops.consumeDpopJti(db, key, expiresAt, now));
  }
  revokeGrant(grant: string, now: number, clientId?: string): Promise<number> {
    return this.#use((db) => ops.revokeGrant(db, grant, now, clientId));
  }
  recordWindowHit(key: string, windowSeconds: number, now: number): Promise<WindowCount> {
    return this.#use((db) => ops.recordWindowHit(db, key, windowSeconds, now));
  }
  peekWindow(key: string, now: number): Promise<WindowCount | null> {
    return this.#use((db) => ops.peekWindow(db, key, now));
  }
  countLiveRecords(kind: 'par' | 'device', now: number, clientId?: string): Promise<number> {
    return this.#use((db) => ops.countLiveRecords(db, kind, now, clientId));
  }
  sweepExpired(now: number): Promise<number> {
    return this.#use((db) => ops.sweepExpired(db, now));
  }
  countLegacyRefreshTokens(): Promise<number> {
    return this.#use((db) => ops.countLegacyRefreshTokens(db));
  }
  purgeLegacyRefreshTokens(): Promise<number> {
    return this.#use((db) => ops.purgeLegacyRefreshTokens(db));
  }
}

/**
 * SQLite adapter (node:sqlite, one synchronous connection). Every root-store
 * operation and every transaction is serialized through one queue, and a
 * transaction holds its turn until COMMIT/ROLLBACK. A root call made while a
 * transaction is open therefore waits for it instead of running inside the
 * BEGIN and being discarded by a rollback.
 */
export class SqliteStore implements Store {
  #db: DatabaseSync | null = null;
  #queue: Promise<unknown> = Promise.resolve();
  readonly #path: string;

  constructor(path: string) {
    this.#path = path;
  }

  #enqueue<T>(fn: (db: DatabaseSync) => T | Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      if (!this.#db) throw new Error('store is not open');
      return fn(this.#db);
    };
    const next = this.#queue.then(run, run);
    this.#queue = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  async init(): Promise<void> {
    const db = new DatabaseSync(this.#path);
    db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    db.exec(SCHEMA);
    // Databases created before dynamic registration lack the column.
    const cols = db.prepare('PRAGMA table_info(clients)').all() as unknown as Array<{ name: string }>;
    if (!cols.some((c) => c.name === 'registration')) db.exec('ALTER TABLE clients ADD COLUMN registration TEXT');
    // Databases created before private_key_jwt (RFC 7523 §2.2) lack the client key columns.
    for (const col of ['token_endpoint_auth_method', 'jwks', 'jwks_uri', 'resources']) {
      if (!cols.some((c) => c.name === col)) db.exec(`ALTER TABLE clients ADD COLUMN ${col} TEXT`);
    }
    // Databases created before client_secret_jwt lack the sealed client key column.
    if (!cols.some((c) => c.name === 'client_secret_key')) db.exec('ALTER TABLE clients ADD COLUMN client_secret_key TEXT');
    // Databases created before RFC 8693 token exchange lack the delegation allow-list column.
    if (!cols.some((c) => c.name === 'allowed_actors')) db.exec('ALTER TABLE clients ADD COLUMN allowed_actors TEXT');
    // Databases created before RFC 9101/9396 lack the JAR/RAR client columns.
    if (!cols.some((c) => c.name === 'require_signed_request_object')) db.exec('ALTER TABLE clients ADD COLUMN require_signed_request_object INTEGER');
    if (!cols.some((c) => c.name === 'authorization_details_types')) db.exec('ALTER TABLE clients ADD COLUMN authorization_details_types TEXT');
    // Databases created before OIDC logout client registration lack the five metadata columns.
    for (const [col, type] of [
      ['post_logout_redirect_uris', 'TEXT'],
      ['backchannel_logout_uri', 'TEXT'],
      ['backchannel_logout_session_required', 'INTEGER'],
      ['frontchannel_logout_uri', 'TEXT'],
      ['frontchannel_logout_session_required', 'INTEGER'],
    ] as const) {
      if (!cols.some((c) => c.name === col)) db.exec(`ALTER TABLE clients ADD COLUMN ${col} ${type}`);
    }
    const codeCols = db.prepare('PRAGMA table_info(authorization_codes)').all() as unknown as Array<{ name: string }>;
    if (!codeCols.some((c) => c.name === 'authorization_details')) db.exec('ALTER TABLE authorization_codes ADD COLUMN authorization_details TEXT');
    // Databases created before DPoP (RFC 9449) support lack the refresh-token binding column.
    const rtCols = db.prepare('PRAGMA table_info(refresh_tokens)').all() as unknown as Array<{ name: string }>;
    if (!rtCols.some((c) => c.name === 'dpop_jkt')) db.exec('ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt TEXT');
    if (!rtCols.some((c) => c.name === 'resource')) db.exec('ALTER TABLE refresh_tokens ADD COLUMN resource TEXT');
    // Databases created before RFC 9396 support lack the RAR refresh-token column.
    if (!rtCols.some((c) => c.name === 'authorization_details')) db.exec('ALTER TABLE refresh_tokens ADD COLUMN authorization_details TEXT');
    // Databases created before grant linking lack the access-token grant column.
    const atCols = db.prepare('PRAGMA table_info(access_tokens)').all() as unknown as Array<{ name: string }>;
    if (!atCols.some((c) => c.name === 'grant_id')) db.exec('ALTER TABLE access_tokens ADD COLUMN grant_id TEXT');
    // Indexed after the migration: an older database has no grant_id when SCHEMA runs.
    db.exec('CREATE INDEX IF NOT EXISTS idx_access_tokens_grant ON access_tokens(grant_id);');
    this.#db = db;
  }

  async close(): Promise<void> {
    // Waits for queued work (including open transactions) before closing.
    await this.#enqueue((db) => {
      db.close();
      this.#db = null;
    }).catch(() => undefined);
  }

  healthcheck(): Promise<void> {
    return this.#enqueue(ops.health);
  }
  saveClient(c: ClientRecord): Promise<void> {
    return this.#enqueue((db) => ops.saveClient(db, c));
  }
  getClient(id: string): Promise<ClientRecord | null> {
    return this.#enqueue((db) => ops.getClient(db, id));
  }
  deleteClient(id: string): Promise<boolean> {
    return this.#enqueue((db) => ops.deleteClient(db, id));
  }
  saveTrustedIssuer(t: TrustedIssuerRecord): Promise<void> {
    return this.#enqueue((db) => ops.saveTrustedIssuer(db, t));
  }
  getTrustedIssuer(issuer: string): Promise<TrustedIssuerRecord | null> {
    return this.#enqueue((db) => ops.getTrustedIssuer(db, issuer));
  }
  listTrustedIssuers(): Promise<TrustedIssuerRecord[]> {
    return this.#enqueue((db) => ops.listTrustedIssuers(db));
  }
  deleteTrustedIssuer(id: string): Promise<boolean> {
    return this.#enqueue((db) => ops.deleteTrustedIssuer(db, id));
  }
  saveDeviceCode(d: DeviceCodeRecord): Promise<void> {
    return this.#enqueue((db) => ops.saveDeviceCode(db, d));
  }
  getDeviceCode(h: string): Promise<DeviceCodeRecord | null> {
    return this.#enqueue((db) => ops.getDeviceCode(db, h));
  }
  recordDevicePoll(h: string, now: number, interval: number): Promise<void> {
    return this.#enqueue((db) => ops.recordDevicePoll(db, h, now, interval));
  }
  resolveDeviceCode(u: string, status: 'approved' | 'denied', subject: string, now: number): Promise<boolean> {
    return this.#enqueue((db) => ops.resolveDeviceCode(db, u, status, subject, now));
  }
  consumeDeviceCode(h: string, now: number): Promise<DeviceCodeRecord | null> {
    return this.#enqueue((db) => ops.consumeDeviceCode(db, h, now));
  }
  savePar(p: ParRecord): Promise<void> {
    return this.#enqueue((db) => ops.savePar(db, p));
  }
  getPar(h: string, now: number): Promise<ParRecord | null> {
    return this.#enqueue((db) => ops.getPar(db, h, now));
  }
  consumePar(h: string, c: string, now: number): Promise<ParRecord | null> {
    return this.#enqueue((db) => ops.consumePar(db, h, c, now));
  }
  saveAuthorizationCode(c: AuthorizationCodeRecord): Promise<void> {
    return this.#enqueue((db) => ops.saveCode(db, c));
  }
  consumeAuthorizationCode(codeHash: string, now: number): Promise<AuthorizationCodeRecord | null> {
    return this.#enqueue((db) => ops.consumeCode(db, codeHash, now));
  }
  saveAccessToken(t: AccessTokenRecord): Promise<void> {
    return this.#enqueue((db) => ops.saveAccessToken(db, t));
  }
  getAccessToken(jti: string, now: number): Promise<AccessTokenRecord | null> {
    return this.#enqueue((db) => ops.getAccessToken(db, jti, now));
  }
  revokeAccessToken(jti: string, now: number): Promise<boolean> {
    return this.#enqueue((db) => ops.revokeAccessToken(db, jti, now));
  }
  saveRefreshToken(t: RefreshTokenRecord): Promise<void> {
    return this.#enqueue((db) => ops.saveRefreshToken(db, t));
  }
  consumeRefreshToken(jti: string, now: number): Promise<RefreshTokenRecord | null> {
    return this.#enqueue((db) => ops.consumeRefreshToken(db, jti, now));
  }
  getRefreshToken(jti: string, now: number): Promise<RefreshTokenRecord | null> {
    return this.#enqueue((db) => ops.getRefreshToken(db, jti, now));
  }
  revokeRefreshToken(jti: string, now: number): Promise<boolean> {
    return this.#enqueue((db) => ops.revokeRefreshToken(db, jti, now));
  }
  consumeDpopJti(key: string, expiresAt: number, now: number): Promise<boolean> {
    return this.#enqueue((db) => ops.consumeDpopJti(db, key, expiresAt, now));
  }
  revokeGrant(grant: string, now: number, clientId?: string): Promise<number> {
    return this.#enqueue((db) => ops.revokeGrant(db, grant, now, clientId));
  }
  recordWindowHit(key: string, windowSeconds: number, now: number): Promise<WindowCount> {
    return this.#enqueue((db) => ops.recordWindowHit(db, key, windowSeconds, now));
  }
  peekWindow(key: string, now: number): Promise<WindowCount | null> {
    return this.#enqueue((db) => ops.peekWindow(db, key, now));
  }
  countLiveRecords(kind: 'par' | 'device', now: number, clientId?: string): Promise<number> {
    return this.#enqueue((db) => ops.countLiveRecords(db, kind, now, clientId));
  }
  sweepExpired(now: number): Promise<number> {
    return this.#enqueue((db) => ops.sweepExpired(db, now));
  }
  countLegacyRefreshTokens(): Promise<number> {
    return this.#enqueue((db) => ops.countLegacyRefreshTokens(db));
  }
  purgeLegacyRefreshTokens(): Promise<number> {
    return this.#enqueue((db) => ops.purgeLegacyRefreshTokens(db));
  }

  transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T> {
    return this.#enqueue(async (db) => {
      db.exec('BEGIN IMMEDIATE');
      const tx = new TxStore(db);
      try {
        const result = await fn(tx);
        db.exec('COMMIT');
        return result;
      } catch (err) {
        try {
          db.exec('ROLLBACK');
        } catch {
          // Keep the original failure; a failed rollback must not mask it.
        }
        throw err;
      } finally {
        tx.end();
      }
    });
  }
}