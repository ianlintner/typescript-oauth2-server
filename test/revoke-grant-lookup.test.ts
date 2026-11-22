import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DocumentStore, type Documents } from '../src/document-store.js';
import type { Store } from '../src/ports.js';

/** A DocumentStore whose Documents primitive records which lookups a method uses. */
class SpyStore extends DocumentStore {
  calls: Array<[string, ...unknown[]]> = [];
  data = new Map<string, Record<string, unknown>>();
  async init(): Promise<void> {}
  async close(): Promise<void> {}
  protected run<T>(fn: (db: Documents) => Promise<T>): Promise<T> { return fn(this.documents()); }
  async transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T> { return fn(this); }
  private documents(): Documents {
    const key = (kind: string, id: string) => `${kind}:${id}`;
    return {
      get: async <T>(kind: string, id: string) => (this.data.get(key(kind, id)) as T | undefined) ?? null,
      insert: async <T>(kind: string, id: string, value: T) => { this.data.set(key(kind, id), value as Record<string, unknown>); },
      put: async <T>(kind: string, id: string, value: T) => { this.data.set(key(kind, id), value as Record<string, unknown>); },
      remove: async (kind: string, id: string) => { this.data.delete(key(kind, id)); },
      list: async <T>(kind: string) => { this.calls.push(['list', kind]); return [...this.data.entries()]
        .filter(([k]) => k.startsWith(`${kind}:`)).map(([, v]) => v as T); },
      find: async <T>(kind: string, field: string, value: string) => { this.calls.push(['find', kind, field, value]); return [...this.data.entries()]
        .filter(([k, v]) => k.startsWith(`${kind}:`) && v[field] === value).map(([, v]) => v as T); },
      purge: async () => 0,
      countLive: async () => 0,
      health: async () => {},
    };
  }
}

test('revokeGrant uses indexed field lookups and never scans a whole kind', async () => {
  const s = new SpyStore();
  await s.saveAccessToken({ jti: 'at-1', clientId: 'c', subject: 'u', scope: 'read',
    expiresAt: 100, revokedAt: null, tokenHash: null, grant: 'g-1' });
  await s.saveRefreshToken({ jti: 'rt-1', clientId: 'c', subject: 'u', scope: 'read',
    expiresAt: 100, family: 'g-1', parentJti: null, revokedAt: null, revokedByReplayAt: null });
  s.calls.length = 0;
  assert.equal(await s.revokeGrant('g-1', 50), 1);
  assert.deepEqual(s.calls, [
    ['find', 'access', 'grant', 'g-1'],
    ['find', 'refresh', 'family', 'g-1'],
  ]);
});
