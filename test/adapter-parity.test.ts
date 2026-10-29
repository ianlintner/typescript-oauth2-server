import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Store } from '../src/ports.js';
import { PostgresStore } from '../src/postgres-store.js';
import { MongoClient } from 'mongodb';
import { MongoStore } from '../src/mongo-store.js';
import { SqliteStore } from '../src/sqlite-store.js';

const sqliteDir = mkdtempSync(join(tmpdir(), 'adapter-parity-'));
process.on('exit', () => rmSync(sqliteDir, { recursive: true, force: true }));
const factories: Array<[string, () => Store]> = [['sqlite', () => new SqliteStore(join(sqliteDir, 'parity.db'))]];
if (process.env.TEST_POSTGRES_URL) factories.push(['postgres', () => new PostgresStore(process.env.TEST_POSTGRES_URL!, 'adapter_parity')]);
if (process.env.TEST_MONGO_URL) factories.push(['mongo', () => new MongoStore(process.env.TEST_MONGO_URL!, 'adapter_parity')]);

test('mongo: URI database paths isolate clients and tokens with database-scoped credentials', { skip: !process.env.TEST_MONGO_URL }, async () => {
  const base = new URL(process.env.TEST_MONGO_URL!);
  const prefix = `uri_${crypto.randomUUID().replaceAll('-', '')}`;
  const firstDb = `${prefix}_a`;
  const secondDb = `${prefix}_b`;
  const namespace = 'same_namespace';
  const clientId = `client-${prefix}`;
  const tokenId = `token-${prefix}`;
  const uri = (db: string, user?: string, password?: string) => {
    const url = new URL(base);
    url.pathname = `/${db}`;
    if (user && password) { url.username = user; url.password = password; url.searchParams.set('authSource', db); }
    return url.toString();
  };
  const admin = new MongoClient(base.toString());
  await admin.connect();
  const first = new MongoStore(uri(firstDb), namespace);
  const second = new MongoStore(uri(secondDb), namespace);
  const password = crypto.randomUUID();
  const user = `user_${prefix}`;
  try {
    await first.init(); await second.init();
    await first.saveClient({clientId, clientSecretHash:null, redirectUris:[], grantTypes:[], scopes:[], enabled:true});
    await first.saveRefreshToken({jti:tokenId, clientId, subject:'user', scope:'read', expiresAt:2000,
      family:tokenId, parentJti:null, revokedAt:null, revokedByReplayAt:null});
    assert.equal(await second.getClient(clientId), null);
    assert.equal(await second.getRefreshToken(tokenId, 1000), null);
    assert.equal(await admin.db(firstDb).collection('oauth2_documents').countDocuments({ namespace }), 3);
    assert.equal(await admin.db(secondDb).collection('oauth2_documents').countDocuments({ namespace, kind: 'client' }), 0);
    await admin.db(firstDb).command({ createUser: user, pwd: password, roles: [{ role: 'readWrite', db: firstDb }] });
    const scoped = new MongoStore(uri(firstDb, user, password), namespace);
    try {
      await scoped.init();
      assert.ok(await scoped.getClient(clientId));
      assert.ok(await scoped.getRefreshToken(tokenId, 1000));
      const deniedUrl = new URL(uri(secondDb, user, password));
      deniedUrl.searchParams.set('authSource', firstDb);
      const denied = new MongoClient(deniedUrl.toString());
      try {
        await denied.connect();
        await assert.rejects(denied.db(secondDb).collection('oauth2_documents').findOne({ namespace }), /not authorized/);
      } finally { await denied.close(); }
    } finally { await scoped.close(); }
  } finally {
    await first.close(); await second.close();
    await admin.db(firstDb).command({ dropDatabase: 1 });
    await admin.db(secondDb).command({ dropDatabase: 1 });
    await admin.close();
  }
});

test('mongo: explicit database cannot contradict URI path', () => {
  assert.throws(() => new MongoStore('mongodb://localhost/selected', 'oauth2', 'other'), /conflicts/);
});

for (const [name, make] of factories) {
  test(`${name}: PAR and device claims are single-use across restart and concurrent replicas`, async () => {
    const a = make(); await a.init();
    await a.healthcheck();
    const id = `restart-${crypto.randomUUID()}`;
    await a.savePar({ requestUriHash:id, clientId:id, params:{ scope:'read' }, expiresAt:2000, consumedAt:null });
    await a.saveDeviceCode({ deviceCodeHash:id, userCodeHash:id, clientId:id, scope:'read', expiresAt:2000,
      interval:5, lastPolledAt:null, status:'pending', subject:null });
    await a.close();
    const b = make(); const c = make(); await b.init(); await c.init();
    try {
      assert.equal(await b.resolveDeviceCode(id, 'approved', 'user', 1000), true);
      assert.equal(await c.resolveDeviceCode(id, 'denied', 'user', 1000), false);
      assert.equal((await Promise.all([b.consumePar(id, id, 1000), c.consumePar(id, id, 1000)])).filter(Boolean).length, 1);
      assert.equal((await Promise.all([b.consumeDeviceCode(id, 1000), c.consumeDeviceCode(id, 1000)])).filter(Boolean).length, 1);
      assert.equal(await c.consumePar(id, id, 1000), null);
    } finally { await b.close(); await c.close(); }
  });
  test(`${name}: transaction rollback, single-use and replay survive independent connections`, async () => {
    const a = make();
    const b = make();
    await a.init();
    await b.init();
    const id = `client-${crypto.randomUUID()}`;
    const code = `code-${id}`;
    const family = `family-${id}`;
    const proof = `proof-${id}`;
    try {
      await a.saveClient({clientId:id, clientSecretHash:null, redirectUris:[], grantTypes:[], scopes:[], enabled:true});
      await assert.rejects(a.transaction(async tx => {
        await tx.saveAuthorizationCode({codeHash: code, clientId:id, redirectUri:'https://example.test', subject:'user', scope:'read', codeChallenge:'challenge', expiresAt:2000, consumedAt:null, nonce:null, authTime:null});
        throw new Error('abort');
      }), /abort/);
      assert.equal(await b.consumeAuthorizationCode(code, 1000), null);
      await a.saveAuthorizationCode({codeHash: code, clientId:id, redirectUri:'https://example.test', subject:'user', scope:'read', codeChallenge:'challenge', expiresAt:2000, consumedAt:null, nonce:null, authTime:null});
      const claims = await Promise.all([a.consumeAuthorizationCode(code, 1000), b.consumeAuthorizationCode(code, 1000)]);
      assert.equal(claims.filter(Boolean).length, 1);
      await a.saveRefreshToken({jti:`rt-${id}`, clientId:id, subject:'user', scope:'read', expiresAt:2000, family, parentJti:null, revokedAt:null, revokedByReplayAt:null});
      assert.ok(await a.consumeRefreshToken(`rt-${id}`, 1000));
      await a.saveRefreshToken({jti:`child-${id}`, clientId:id, subject:'user', scope:'read', expiresAt:2000, family, parentJti:`rt-${id}`, revokedAt:null, revokedByReplayAt:null});
      assert.equal(await b.consumeRefreshToken(`rt-${id}`, 1001), null);
      assert.equal(await a.getRefreshToken(`child-${id}`, 1001), null);
      assert.deepEqual(await Promise.all([a.consumeDpopJti(proof, 2000, 1000), b.consumeDpopJti(proof, 2000, 1000)]).then(x => x.sort()), [false, true]);
      assert.equal(await b.consumeDpopJti(proof, 3000, 2000), true);
    } finally { await a.close(); await b.close(); }
  });
}
