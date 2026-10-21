import { DatabaseSync } from 'node:sqlite';
import type {
  AccessTokenRecord, AuthorizationCodeRecord, ClientRecord, DeviceCodeRecord, DeviceCodeStatus, ParRecord, RefreshTokenRecord, Store,
} from './ports.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,
  redirect_uris TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  scopes TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  registration TEXT
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
  auth_time INTEGER
);
CREATE TABLE IF NOT EXISTS access_tokens (
  jti TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  token_hash TEXT
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
  revoked_by_replay_at INTEGER
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
);`;

interface ClientRow {
  client_id: string;
  client_secret_hash: string | null;
  redirect_uris: string;
  grant_types: string;
  scopes: string;
  enabled: number;
  registration: string | null;
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
}

interface AccessTokenRow {
  jti: string;
  client_id: string;
  subject: string;
  scope: string;
  expires_at: number;
  revoked_at: number | null;
  token_hash: string | null;
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
  };
}

/** Statement-level operations on one connection. Stateless apart from the db it is handed. */
const ops = {
  health(db: DatabaseSync): void {
    db.prepare('SELECT 1').get();
  },

  saveClient(db: DatabaseSync, c: ClientRecord): void {
    db.prepare(
      `INSERT INTO clients (client_id, client_secret_hash, redirect_uris, grant_types, scopes, enabled, registration)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(client_id) DO UPDATE SET client_secret_hash=excluded.client_secret_hash,
         redirect_uris=excluded.redirect_uris, grant_types=excluded.grant_types,
         scopes=excluded.scopes, enabled=excluded.enabled, registration=excluded.registration`,
    ).run(
      c.clientId, c.clientSecretHash, JSON.stringify(c.redirectUris), JSON.stringify(c.grantTypes), JSON.stringify(c.scopes),
      c.enabled ? 1 : 0, c.registration ? JSON.stringify(c.registration) : null,
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
      ...(r.registration ? { registration: JSON.parse(r.registration) as ClientRecord['registration'] } : {}),
    };
  },

  saveCode(db: DatabaseSync, c: AuthorizationCodeRecord): void {
    db.prepare(
      `INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, subject, scope, code_challenge, expires_at, consumed_at, nonce, auth_time)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(c.codeHash, c.clientId, c.redirectUri, c.subject, c.scope, c.codeChallenge, c.expiresAt, c.consumedAt, c.nonce ?? null, c.authTime ?? null);
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
    };
  },

  // -- access tokens --

  saveAccessToken(db: DatabaseSync, t: AccessTokenRecord): void {
    db.prepare(
      `INSERT INTO access_tokens (jti, client_id, subject, scope, expires_at, revoked_at, token_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(t.jti, t.clientId, t.subject, t.scope, t.expiresAt, t.revokedAt, t.tokenHash);
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
      `INSERT INTO refresh_tokens (jti, client_id, subject, scope, expires_at, family, parent_jti, consumed_at, revoked_at, revoked_by_replay_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
    ).run(t.jti, t.clientId, t.subject, t.scope, t.expiresAt, t.family, t.parentJti, t.revokedAt, t.revokedByReplayAt);
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

    // Check for sibling replay: if another token in this family was already consumed
    // that is NOT the direct parent (parent consumption is legitimate — it happened
    // during the prior rotation), this is a replay attack by a stale bearer.
    const parentJti = r.parent_jti;
    const sibling = db.prepare(
      `SELECT jti FROM refresh_tokens
       WHERE family = ? AND jti != ? AND consumed_at IS NOT NULL
         AND (? IS NULL OR jti != ?)
         AND revoked_at IS NULL AND revoked_by_replay_at IS NULL
       LIMIT 1`,
    ).get(r.family, r.jti, parentJti, parentJti) as { jti: string } | undefined;

    if (sibling) {
      // Replay attack: revoke the entire family.
      db.prepare(
        `UPDATE refresh_tokens SET revoked_by_replay_at = ?
         WHERE family = ? AND revoked_by_replay_at IS NULL AND revoked_at IS NULL`,
      ).run(now, r.family);
    }

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

  revokeTokenFamily(db: DatabaseSync, family: string, now: number): number {
    const res = db.prepare(
      `UPDATE refresh_tokens SET revoked_at = ?
       WHERE family = ? AND revoked_at IS NULL AND revoked_by_replay_at IS NULL`,
    ).run(now, family);
    return Number(res.changes);
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
  revokeTokenFamily(family: string, now: number): Promise<number> {
    return this.#use((db) => ops.revokeTokenFamily(db, family, now));
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
  revokeTokenFamily(family: string, now: number): Promise<number> {
    return this.#enqueue((db) => ops.revokeTokenFamily(db, family, now));
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