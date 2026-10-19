import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { AccessTokenRecord, RefreshTokenRecord, Store } from '../src/ports.js';
import { SqliteStore } from '../src/sqlite-store.js';

const client = {
  clientId: 'c1',
  clientSecretHash: null,
  redirectUris: ['https://app.example/cb'],
  grantTypes: ['authorization_code', 'refresh_token'],
  scopes: ['openid', 'read'],
  enabled: true,
};

const at: AccessTokenRecord = {
  jti: 'at-001',
  clientId: 'c1',
  subject: 'u1',
  scope: 'read',
  expiresAt: 2000,
  revokedAt: null,
  tokenHash: null,
};

const rt: RefreshTokenRecord = {
  jti: 'rt-001',
  clientId: 'c1',
  subject: 'u1',
  scope: 'read',
  expiresAt: 10000,
  family: 'fam-001',
  parentJti: null,
  revokedByReplayAt: null,
  revokedAt: null,
};

async function withStore(fn: (s: Store) => Promise<void>) {
  const s = new SqliteStore(':memory:');
  await s.init();
  await s.saveClient(client);
  try {
    await fn(s);
  } finally {
    await s.close();
  }
}

test('save and retrieve a non-expired access token', () =>
  withStore(async (s) => {
    await s.saveAccessToken(at);
    const got = await s.getAccessToken('at-001', 1000);
    assert.ok(got);
    assert.equal(got.jti, 'at-001');
    assert.equal(got.clientId, 'c1');
    assert.equal(got.scope, 'read');
  }));

test('expired access token is not returned', () =>
  withStore(async (s) => {
    await s.saveAccessToken(at);
    assert.equal(await s.getAccessToken('at-001', 2000), null);
  }));

test('unknown access token returns null', () =>
  withStore(async (s) => {
    assert.equal(await s.getAccessToken('nope', 1000), null);
  }));

test('revoke an access token', () =>
  withStore(async (s) => {
    await s.saveAccessToken(at);
    const ok = await s.revokeAccessToken('at-001', 1100);
    assert.equal(ok, true);
    assert.equal(await s.getAccessToken('at-001', 1000), null);
  }));

test('revoke unknown access token returns false', () =>
  withStore(async (s) => {
    assert.equal(await s.revokeAccessToken('nope', 1000), false);
  }));

test('save and retrieve a refresh token', () =>
  withStore(async (s) => {
    await s.saveRefreshToken(rt);
    const got = await s.consumeRefreshToken('rt-001', 1000);
    assert.ok(got);
    assert.equal(got?.jti, 'rt-001');
    assert.equal(got?.family, 'fam-001');
  }));

test('expired refresh token is not consumable', () =>
  withStore(async (s) => {
    await s.saveRefreshToken(rt);
    assert.equal(await s.consumeRefreshToken('rt-001', 10000), null);
  }));

test('refresh token can be consumed exactly once', () =>
  withStore(async (s) => {
    await s.saveRefreshToken(rt);
    assert.ok(await s.consumeRefreshToken('rt-001', 1000));
    assert.equal(await s.consumeRefreshToken('rt-001', 1000), null);
  }));

test('revoke a refresh token', () =>
  withStore(async (s) => {
    await s.saveRefreshToken(rt);
    const ok = await s.revokeRefreshToken('rt-001', 1100);
    assert.equal(ok, true);
    assert.equal(await s.consumeRefreshToken('rt-001', 1000), null);
  }));

test('revoke unknown refresh token returns false', () =>
  withStore(async (s) => {
    assert.equal(await s.revokeRefreshToken('nope', 1000), false);
  }));

test('revoke an entire token family', () =>
  withStore(async (s) => {
    await s.saveRefreshToken(rt);
    await s.saveRefreshToken({ ...rt, jti: 'rt-002', parentJti: 'rt-001' });
    const count = await s.revokeTokenFamily('fam-001', 5000);
    assert.equal(count, 2);
    assert.equal(await s.consumeRefreshToken('rt-001', 1000), null);
    assert.equal(await s.consumeRefreshToken('rt-002', 1000), null);
  }));

test('consuming a refresh token that has a consumed sibling in the same family revokes the family', () =>
  withStore(async (s) => {
    // Issue initial
    await s.saveRefreshToken(rt);
    // Rotate once: rt-001 consumed, rt-002 issued
    const first = await s.consumeRefreshToken('rt-001', 1000);
    assert.ok(first);
    await s.saveRefreshToken({ ...rt, jti: 'rt-002', parentJti: 'rt-001' });

    // Attacker replays rt-001 (already consumed)
    const replay = await s.consumeRefreshToken('rt-001', 1000);
    assert.equal(replay, null);

    // rt-002 should also be revoked (family killed)
    assert.equal(await s.consumeRefreshToken('rt-002', 1000), null);
  }));

test('data persists across process restart', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oauth2-token-store-'));
  const path = join(dir, 'db.sqlite');
  try {
    const a = new SqliteStore(path);
    await a.init();
    await a.saveClient(client);
    await a.saveAccessToken(at);
    await a.saveRefreshToken(rt);
    await a.revokeAccessToken('at-001', 1100);
    await a.consumeRefreshToken('rt-001', 1000);
    await a.close();

    const b = new SqliteStore(path);
    await b.init();
    assert.equal(await b.getAccessToken('at-001', 1000), null, 'revocation persists');
    assert.equal(await b.consumeRefreshToken('rt-001', 1000), null, 'consumption persists');
    await b.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});