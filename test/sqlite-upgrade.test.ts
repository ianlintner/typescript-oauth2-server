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

test('init() upgrades a pre-logout clients table with the five metadata columns (idempotently)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sqlite-logout-upgrade-'));
  const path = join(dir, 'legacy.db');
  const legacy = new DatabaseSync(path);
  legacy.exec(`
    CREATE TABLE clients (
      client_id TEXT PRIMARY KEY, client_secret_hash TEXT,
      redirect_uris TEXT NOT NULL, grant_types TEXT NOT NULL, scopes TEXT NOT NULL,
      enabled INTEGER NOT NULL, registration TEXT, token_endpoint_auth_method TEXT,
      client_secret_key TEXT, jwks TEXT, jwks_uri TEXT, allowed_actors TEXT,
      require_signed_request_object INTEGER, authorization_details_types TEXT
    );
    INSERT INTO clients (client_id, client_secret_hash, redirect_uris, grant_types, scopes, enabled)
      VALUES ('legacy', NULL, '[]', '[]', '[]', 1);
  `);
  legacy.close();
  const store = new SqliteStore(path);
  try {
    await store.init();
    await store.init(); // re-running init on the upgraded DB must not re-ALTER
    const db = new DatabaseSync(path);
    const columns = db.prepare('PRAGMA table_info(clients)').all() as Array<{ name: string }>;
    db.close();
    for (const col of ['post_logout_redirect_uris', 'backchannel_logout_uri', 'backchannel_logout_session_required', 'frontchannel_logout_uri', 'frontchannel_logout_session_required']) {
      assert.equal(columns.filter((c) => c.name === col).length, 1, `${col} appears exactly once`);
    }
    const oldClient = await store.getClient('legacy');
    assert.ok(oldClient);
    assert.equal(oldClient.postLogoutRedirectUris, undefined);
    await store.saveClient({
      clientId: 'logout', clientSecretHash: null, redirectUris: [], grantTypes: [], scopes: [], enabled: true,
      postLogoutRedirectUris: ['https://client.example/out'],
      backchannelLogoutUri: 'https://client.example/bcl', backchannelLogoutSessionRequired: true,
      frontchannelLogoutUri: 'https://client.example/fcl', frontchannelLogoutSessionRequired: true,
    });
    const upgraded = await store.getClient('logout');
    assert.deepEqual(upgraded?.postLogoutRedirectUris, ['https://client.example/out']);
    assert.equal(upgraded?.backchannelLogoutUri, 'https://client.example/bcl');
    assert.equal(upgraded?.backchannelLogoutSessionRequired, true);
    assert.equal(upgraded?.frontchannelLogoutUri, 'https://client.example/fcl');
    assert.equal(upgraded?.frontchannelLogoutSessionRequired, true);
  } finally {
    await store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
