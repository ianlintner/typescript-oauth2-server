import { MongoClient, type ClientSession, type Collection } from 'mongodb';
import type { Store } from './ports.js';
import { DocumentStore, TransactionDocuments, type Documents } from './document-store.js';

type Row = { _id: string; namespace: string; kind: string; id: string; data: unknown };
/** Requires a replica set: standalone MongoDB cannot provide multi-document rollback. */
export class MongoStore extends DocumentStore {
  private readonly client: MongoClient;
  private collection: Collection<Row> | null = null;
  constructor(url: string, private readonly namespace = 'oauth2', database = 'oauth2') {
    super(); this.client = new MongoClient(url); this.database = database;
  }
  private readonly database: string;
  async init(): Promise<void> {
    await this.client.connect();
    // Fail closed on standalone servers; no silent best-effort writes.
    const hello = await this.client.db('admin').command({ hello: 1 });
    if (!hello.setName) { await this.client.close(); throw new Error('MongoDB replica set required for atomic transactions'); }
    this.collection = this.client.db(this.database).collection<Row>('oauth2_documents');
    await this.collection.createIndex({ namespace: 1, kind: 1, id: 1 }, { unique: true });
  }
  async close(): Promise<void> { this.collection = null; await this.client.close(); }
  protected run<T>(fn: (db: Documents) => Promise<T>): Promise<T> { return this.transaction(tx => fn((tx as TransactionDocuments).documents())); }
  async transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T> {
    const collection = this.collection;
    if (!collection) throw new Error('store is not open');
    const session = this.client.startSession();
    try {
      return await session.withTransaction(async () => {
        // Every transaction writes the same guard document: concurrent snapshots
        // conflict, and the driver retries the whole callback against fresh state.
        await collection.updateOne({ _id: `${this.namespace}:guard` },
          { $inc: { 'data.version': 1 }, $setOnInsert: { namespace: this.namespace, kind: 'guard', id: 'guard' } },
          { upsert: true, session });
        const db = this.documents(collection, session);
        const tx = new TransactionDocuments(db);
        try { return await fn(tx); } finally { tx.end(); }
      });
    } finally { await session.endSession(); }
  }
  private documents(collection: Collection<Row>, session: ClientSession): Documents {
    const filter = (kind: string, id: string) => ({ _id: `${this.namespace}:${kind}:${id}` });
    return {
      health: async () => { await collection.findOne({ _id: `${this.namespace}:guard` }, { session }); },
      get: async <T>(kind: string, id: string): Promise<T | null> => {
        const r = await collection.findOne(filter(kind, id), { session });
        return r ? r.data as T : null;
      },
      insert: async (kind, id, data) => { await collection.insertOne({ ...filter(kind, id), namespace: this.namespace, kind, id, data }, { session }); },
      put: async (kind, id, data) => { await collection.updateOne(filter(kind, id),
        { $set: { namespace: this.namespace, kind, id, data } }, { upsert: true, session }); },
      remove: async (kind, id) => { await collection.deleteOne(filter(kind, id), { session }); },
      list: async <T>(kind: string): Promise<T[]> => {
        const rows = await collection.find({ namespace: this.namespace, kind }, { session }).toArray();
        return rows.map(r => r.data as T);
      },
    };
  }
}
