import pg from 'pg';
import type { Store } from './ports.js';
import { DocumentStore, TransactionDocuments, type Documents } from './document-store.js';

/** Namespace separates independent test/tenant databases; identifiers never enter SQL text. */
export class PostgresStore extends DocumentStore {
  private readonly pool: pg.Pool;
  private open = false;
  constructor(url: string, private readonly namespace = 'oauth2') {
    super(); this.pool = new pg.Pool({ connectionString: url });
  }
  async init(): Promise<void> {
    await this.pool.query(`CREATE TABLE IF NOT EXISTS oauth2_documents (
      namespace TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, data JSONB NOT NULL,
      PRIMARY KEY (namespace, kind, id))`);
    this.open = true;
  }
  async close(): Promise<void> { this.open = false; await this.pool.end(); }
  protected run<T>(fn: (db: Documents) => Promise<T>): Promise<T> { return this.transaction(tx => fn((tx as TransactionDocuments).documents())); }
  // Root operations are dispatched through the transaction handle instead of a shared mutable connection.
  async transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T> {
    if (!this.open) throw new Error('store is not open');
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Serializes all writes and reads of one namespace across server replicas.
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [this.namespace]);
      const args = [this.namespace];
      const db: Documents = {
        health: async () => { await client.query('SELECT 1'); },
        get: async <R>(kind: string, id: string): Promise<R | null> => {
          const result = await client.query<{ data: R }>('SELECT data FROM oauth2_documents WHERE namespace=$1 AND kind=$2 AND id=$3', [...args, kind, id]);
          return result.rows[0]?.data ?? null;
        },
        insert: async (kind, id, data) => { await client.query('INSERT INTO oauth2_documents VALUES ($1,$2,$3,$4::jsonb)', [...args, kind, id, JSON.stringify(data)]); },
        put: async (kind, id, data) => { await client.query(`INSERT INTO oauth2_documents VALUES ($1,$2,$3,$4::jsonb)
          ON CONFLICT(namespace,kind,id) DO UPDATE SET data=excluded.data`, [...args, kind, id, JSON.stringify(data)]); },
        remove: async (kind, id) => { await client.query('DELETE FROM oauth2_documents WHERE namespace=$1 AND kind=$2 AND id=$3', [...args, kind, id]); },
        list: async <R>(kind: string): Promise<R[]> => {
          const result = await client.query<{ data: R }>('SELECT data FROM oauth2_documents WHERE namespace=$1 AND kind=$2', [...args, kind]);
          return result.rows.map(r => r.data);
        },
      };
      const tx = new TransactionDocuments(db);
      try {
        const result = await fn(tx);
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK'); throw err;
      } finally { tx.end(); }
    } finally { client.release(); }
  }
}
