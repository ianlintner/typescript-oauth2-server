import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { ClientRecord, Store } from '../src/ports.js';
import { SqliteStore } from '../src/sqlite-store.js';

const client: ClientRecord = {
  clientId: 'c1',
  clientSecretHash: null,
  redirectUris: ['https://app.example/cb'],
  grantTypes: ['authorization_code'],
  scopes: ['openid'],
  enabled: true,
};
const code = {
  codeHash: 'h1',
  clientId: 'c1',
  redirectUri: 'https://app.example/cb',
  scope: 'openid',
  codeChallenge: 'chal',
  expiresAt: 2000,
  consumedAt: null,
};

async function withStore(fn: (s: Store) => Promise<void>) {
  const s = new SqliteStore(':memory:');
  await s.init();
  try {
    await fn(s);
  } finally {
    await s.close();
  }
}

test('client round trip and unknown client returns null', () =>
  withStore(async (s) => {
    assert.equal(await s.getClient('c1'), null);
    await s.saveClient(client);
    assert.deepEqual(await s.getClient('c1'), client);
  }));

test('authorization code is consumable exactly once', () =>
  withStore(async (s) => {
    await s.saveClient(client);
    await s.saveAuthorizationCode(code);
    const first = await s.consumeAuthorizationCode('h1', 1000);
    assert.equal(first?.clientId, 'c1');
    assert.equal(await s.consumeAuthorizationCode('h1', 1001), null);
  }));

test('expired and unknown codes are not consumable', () =>
  withStore(async (s) => {
    await s.saveClient(client);
    await s.saveAuthorizationCode(code);
    assert.equal(await s.consumeAuthorizationCode('h1', 2000), null);
    assert.equal(await s.consumeAuthorizationCode('nope', 1), null);
  }));

test('concurrent consumption yields a single winner', () =>
  withStore(async (s) => {
    await s.saveClient(client);
    await s.saveAuthorizationCode(code);
    const results = await Promise.all(Array.from({ length: 10 }, () => s.consumeAuthorizationCode('h1', 1000)));
    assert.equal(results.filter((r) => r !== null).length, 1);
  }));

test('code referencing unknown client is rejected by foreign key', () =>
  withStore(async (s) => {
    await assert.rejects(s.saveAuthorizationCode(code));
  }));

test('transaction commits on success', () =>
  withStore(async (s) => {
    await s.transaction(async (tx) => {
      await tx.saveClient(client);
    });
    assert.notEqual(await s.getClient('c1'), null);
  }));

test('transaction rolls back on error and rethrows', () =>
  withStore(async (s) => {
    await assert.rejects(
      s.transaction(async (tx) => {
        await tx.saveClient(client);
        throw new Error('boom');
      }),
      /boom/,
    );
    assert.equal(await s.getClient('c1'), null);
  }));

test('concurrent transactions are serialized, not interleaved', () =>
  withStore(async (s) => {
    const order: string[] = [];
    const slow = s.transaction(async (tx) => {
      order.push('a:start');
      await tx.saveClient(client);
      await new Promise((r) => setTimeout(r, 20));
      order.push('a:end');
    });
    const fast = s.transaction(async (tx) => {
      order.push('b:start');
      await tx.saveClient({ ...client, clientId: 'c2' });
      order.push('b:end');
    });
    await Promise.all([slow, fast]);
    assert.deepEqual(order, ['a:start', 'a:end', 'b:start', 'b:end']);
  }));

test('nested transaction is rejected', () =>
  withStore(async (s) => {
    await assert.rejects(
      s.transaction(async (tx) => {
        await tx.transaction(async () => {});
      }),
      /nested/i,
    );
  }));

test('data persists across close and reopen of a file database', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oauth2-store-'));
  const path = join(dir, 'db.sqlite');
  try {
    const a = new SqliteStore(path);
    await a.init();
    await a.saveClient(client);
    await a.saveAuthorizationCode(code);
    await a.consumeAuthorizationCode('h1', 1000);
    await a.close();

    const b = new SqliteStore(path);
    await b.init();
    assert.deepEqual(await b.getClient('c1'), client);
    assert.equal(await b.consumeAuthorizationCode('h1', 1001), null, 'consumption survives restart');
    await b.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('healthcheck succeeds when open and fails after close', async () => {
  const s = new SqliteStore(':memory:');
  await s.init();
  await s.healthcheck();
  await s.close();
  await assert.rejects(s.healthcheck());
});
