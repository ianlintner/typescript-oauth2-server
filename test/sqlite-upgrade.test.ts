import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { SqliteStore } from '../src/sqlite-store.js';

test('init() upgrades a database created with main (no access_tokens.grant_id)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oauth-sqlite-upgrade-'));
  const path = join(dir, 'old.db');
  const legacy = new DatabaseSync(path);
  // Shape of access_tokens before grant linking was introduced on main.
  legacy.exec(`CREATE TABLE access_tokens (
    jti TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    token_hash TEXT
  );`);
  legacy.close();

  const store = new SqliteStore(path);
  try {
    await store.init();
    const db = new DatabaseSync(path);
    const cols = db.prepare('PRAGMA table_info(access_tokens)').all() as unknown as Array<{ name: string }>;
    assert.ok(cols.some((c) => c.name === 'grant_id'), 'grant_id migration ran');
    const indexes = db.prepare('PRAGMA index_list(access_tokens)').all() as unknown as Array<{ name: string }>;
    assert.ok(indexes.some((i) => i.name === 'idx_access_tokens_grant'), 'grant index exists after upgrade');
    db.close();
  } finally {
    await store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
