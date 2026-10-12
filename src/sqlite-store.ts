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
  subject TEXT NOT NULL,
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
  subject: string;
  scope: string;
  code_challenge: string;
  expires_at: number;
  consumed_at: number | null;
}

/** Statement-level operations on one connection. Stateless apart from the db it is handed. */
const ops = {
  health(db: DatabaseSync): void {
    db.prepare('SELECT 1').get();
  },

  saveClient(db: DatabaseSync, c: ClientRecord): void {
    db.prepare(
      `INSERT INTO clients (client_id, client_secret_hash, redirect_uris, grant_types, scopes, enabled)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(client_id) DO UPDATE SET client_secret_hash=excluded.client_secret_hash,
         redirect_uris=excluded.redirect_uris, grant_types=excluded.grant_types,
         scopes=excluded.scopes, enabled=excluded.enabled`,
    ).run(c.clientId, c.clientSecretHash, JSON.stringify(c.redirectUris), JSON.stringify(c.grantTypes), JSON.stringify(c.scopes), c.enabled ? 1 : 0);
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
    };
  },

  saveCode(db: DatabaseSync, c: AuthorizationCodeRecord): void {
    db.prepare(
      `INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, subject, scope, code_challenge, expires_at, consumed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(c.codeHash, c.clientId, c.redirectUri, c.subject, c.scope, c.codeChallenge, c.expiresAt, c.consumedAt);
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
    };
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
  saveAuthorizationCode(c: AuthorizationCodeRecord): Promise<void> {
    return this.#use((db) => ops.saveCode(db, c));
  }
  consumeAuthorizationCode(codeHash: string, now: number): Promise<AuthorizationCodeRecord | null> {
    return this.#use((db) => ops.consumeCode(db, codeHash, now));
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
  saveAuthorizationCode(c: AuthorizationCodeRecord): Promise<void> {
    return this.#enqueue((db) => ops.saveCode(db, c));
  }
  consumeAuthorizationCode(codeHash: string, now: number): Promise<AuthorizationCodeRecord | null> {
    return this.#enqueue((db) => ops.consumeCode(db, codeHash, now));
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
