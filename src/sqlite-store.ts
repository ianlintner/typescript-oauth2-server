import { DatabaseSync } from 'node:sqlite';
import type { AuthorizationCodeRecord, ClientRecord, Store } from './ports.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,
  redirect_uris TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  scopes TEXT NOT NULL,
  enabled INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS authorization_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(client_id),
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
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
}

interface CodeRow {
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  expires_at: number;
  consumed_at: number | null;
}

/**
 * SQLite adapter for tests and local operation. node:sqlite is synchronous, so
 * individual statements are atomic; transactions are serialized through a queue
 * so concurrent callers never interleave inside one BEGIN/COMMIT.
 */
export class SqliteStore implements Store {
  #db: DatabaseSync | null = null;
  #queue: Promise<unknown> = Promise.resolve();
  readonly #path: string;
  readonly #inTx: boolean;
  readonly #shared: { db: () => DatabaseSync } | null;

  constructor(path: string, shared: { db: () => DatabaseSync } | null = null) {
    this.#path = path;
    this.#shared = shared;
    this.#inTx = shared !== null;
  }

  get #conn(): DatabaseSync {
    const db = this.#shared ? this.#shared.db() : this.#db;
    if (!db) throw new Error('store is not open');
    return db;
  }

  async init(): Promise<void> {
    const db = new DatabaseSync(this.#path);
    db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
    db.exec(SCHEMA);
    this.#db = db;
  }

  async close(): Promise<void> {
    await this.#queue.catch(() => undefined);
    this.#db?.close();
    this.#db = null;
  }

  async healthcheck(): Promise<void> {
    this.#conn.prepare('SELECT 1').get();
  }

  async saveClient(c: ClientRecord): Promise<void> {
    this.#conn
      .prepare(
        `INSERT INTO clients (client_id, client_secret_hash, redirect_uris, grant_types, scopes, enabled)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET client_secret_hash=excluded.client_secret_hash,
           redirect_uris=excluded.redirect_uris, grant_types=excluded.grant_types,
           scopes=excluded.scopes, enabled=excluded.enabled`,
      )
      .run(c.clientId, c.clientSecretHash, JSON.stringify(c.redirectUris), JSON.stringify(c.grantTypes), JSON.stringify(c.scopes), c.enabled ? 1 : 0);
  }

  async getClient(clientId: string): Promise<ClientRecord | null> {
    const r = this.#conn.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId) as unknown as ClientRow | undefined;
    if (!r) return null;
    return {
      clientId: r.client_id,
      clientSecretHash: r.client_secret_hash,
      redirectUris: JSON.parse(r.redirect_uris) as string[],
      grantTypes: JSON.parse(r.grant_types) as string[],
      scopes: JSON.parse(r.scopes) as string[],
      enabled: r.enabled === 1,
    };
  }

  async saveAuthorizationCode(c: AuthorizationCodeRecord): Promise<void> {
    this.#conn
      .prepare(
        `INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, scope, code_challenge, expires_at, consumed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(c.codeHash, c.clientId, c.redirectUri, c.scope, c.codeChallenge, c.expiresAt, c.consumedAt);
  }

  async consumeAuthorizationCode(codeHash: string, now: number): Promise<AuthorizationCodeRecord | null> {
    // Single conditional UPDATE ... RETURNING: the winner of a race is decided by the database.
    const r = this.#conn
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
      scope: r.scope,
      codeChallenge: r.code_challenge,
      expiresAt: r.expires_at,
      consumedAt: r.consumed_at,
    };
  }

  transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T> {
    if (this.#inTx) return Promise.reject(new Error('nested transactions are not supported'));
    const run = async (): Promise<T> => {
      const db = this.#conn;
      db.exec('BEGIN IMMEDIATE');
      try {
        const result = await fn(new SqliteStore(this.#path, { db: () => db }));
        db.exec('COMMIT');
        return result;
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    };
    const next = this.#queue.then(run, run);
    this.#queue = next.catch(() => undefined);
    return next;
  }
}
