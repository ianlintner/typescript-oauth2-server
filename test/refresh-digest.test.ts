import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import type { FastifyInstance } from 'fastify';
import { exportPKCS8, generateKeyPair } from 'jose';
import { hashClientSecret } from '../src/client-auth.js';
import { DocumentStore, TransactionDocuments, type Documents } from '../src/document-store.js';
import type { RefreshTokenRecord, Store } from '../src/ports.js';
import { runRefreshCutover } from '../src/refresh-cutover.js';
import { cryptoRandom } from '../src/runtime.js';
import { buildServer } from '../src/server.js';
import { createJoseSigner } from '../src/signer.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { REFRESH_ID_PREFIX, isDigestRefreshId, refreshTokenId } from '../src/token-digest.js';

// All data below is ephemeral and synthetic (temp SQLite file / in-memory fakes).
const CB = 'https://app.example/cb';
const VERIFIER = 'v'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const SECRET = 'synthetic-client-secret-value';
const NOW = 1_000_000;

async function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'rt-digest-'));
  const path = join(dir, 'db.sqlite');
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
  const store = new SqliteStore(path);
  await store.init();
  const base = { redirectUris: [CB], grantTypes: ['authorization_code', 'refresh_token'], scopes: ['read'], enabled: true };
  await store.saveClient({ ...base, clientId: 'conf', clientSecretHash: await hashClientSecret(SECRET) });
  const server = buildServer({
    store, signer, clock: { now: () => NOW }, random: cryptoRandom, issuer: 'http://localhost:8080',
    authenticate: async () => 'user-1', refreshTokenTtl: 86_400,
  });
  const raw = () => new DatabaseSync(path);
  const cleanup = async () => { await server.close(); await store.close(); rmSync(dir, { recursive: true, force: true }); };
  return { server, store, raw, cleanup };
}

function post(server: FastifyInstance, url: string, form: Record<string, string>) {
  return server.inject({
    method: 'POST', url, headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(form).toString(),
  });
}

async function issue(server: FastifyInstance): Promise<string> {
  const q = new URLSearchParams({
    response_type: 'code', client_id: 'conf', redirect_uri: CB, code_challenge: CHALLENGE,
    code_challenge_method: 'S256', state: 's', scope: 'read',
  });
  const authz = await server.inject({ method: 'GET', url: `/oauth/authorize?${q.toString()}` });
  const code = new URL(authz.headers.location as string).searchParams.get('code')!;
  const res = await post(server, '/oauth/token', {
    grant_type: 'authorization_code', code, redirect_uri: CB, client_id: 'conf', client_secret: SECRET, code_verifier: VERIFIER,
  });
  assert.equal(res.statusCode, 200);
  return res.json().refresh_token as string;
}

const refresh = (server: FastifyInstance, rt: string) =>
  post(server, '/oauth/token', { grant_type: 'refresh_token', refresh_token: rt, client_id: 'conf', client_secret: SECRET });

test('digest format is versioned, deterministic and not the raw value', () => {
  const id = refreshTokenId('abc');
  assert.ok(id.startsWith(REFRESH_ID_PREFIX) && isDigestRefreshId(id));
  assert.equal(id, refreshTokenId('abc'));
  assert.notEqual(id, refreshTokenId('abd'));
  assert.ok(!id.includes('abc'));
  assert.equal(isDigestRefreshId('abc'), false);
});

test('issued refresh value is never stored; id, family and parent are digests', async () => {
  const s = await setup();
  try {
    const rt1 = await issue(s.server);
    const rotated = await refresh(s.server, rt1);
    assert.equal(rotated.statusCode, 200);
    const rt2 = rotated.json().refresh_token as string;

    const db = s.raw();
    const rows = db.prepare('SELECT * FROM refresh_tokens ORDER BY expires_at, jti').all() as unknown as Array<Record<string, string | null>>;
    db.close();
    assert.equal(rows.length, 2);
    for (const r of rows) {
      assert.ok(isDigestRefreshId(r.jti!), 'jti is digest');
      assert.ok(isDigestRefreshId(r.family!), 'family is digest');
      assert.ok(r.parent_jti == null || isDigestRefreshId(r.parent_jti), 'parent is digest');
      for (const v of Object.values(r)) assert.ok(typeof v !== 'string' || (!v.includes(rt1) && !v.includes(rt2)), 'no raw value in any column');
    }
    const first = rows.find((r) => r.jti === refreshTokenId(rt1))!;
    const second = rows.find((r) => r.jti === refreshTokenId(rt2))!;
    assert.ok(first && second);
    assert.equal(first.parent_jti, null);
    assert.equal(first.family, first.jti);
    assert.equal(second.parent_jti, first.jti);
    assert.equal(second.family, first.family);
  } finally { await s.cleanup(); }
});

test('rotation, replay family revocation and revocation endpoint work on digests', async () => {
  const s = await setup();
  try {
    const rt1 = await issue(s.server);
    const rt2 = (await refresh(s.server, rt1)).json().refresh_token as string;
    // Replay of the consumed parent revokes the family, including the live child.
    assert.equal((await refresh(s.server, rt1)).statusCode, 400);
    assert.equal((await refresh(s.server, rt2)).statusCode, 400);

    const rt3 = await issue(s.server);
    const rev = await post(s.server, '/oauth/revoke', { token: rt3, token_type_hint: 'refresh_token', client_id: 'conf', client_secret: SECRET });
    assert.equal(rev.statusCode, 200);
    assert.equal((await refresh(s.server, rt3)).statusCode, 400);
    assert.equal(await s.store.getRefreshToken(refreshTokenId(rt3), NOW), null);
  } finally { await s.cleanup(); }
});

test('a stored digest identifier is not itself a usable refresh token', async () => {
  const s = await setup();
  try {
    const rt = await issue(s.server);
    assert.equal((await refresh(s.server, refreshTokenId(rt))).statusCode, 400);
    assert.equal((await refresh(s.server, rt)).statusCode, 200);
  } finally { await s.cleanup(); }
});

const legacy = (jti: string): RefreshTokenRecord => ({
  jti, clientId: 'conf', subject: 'user-1', scope: 'read', expiresAt: NOW + 1000, family: jti,
  parentJti: null, revokedAt: null, revokedByReplayAt: null,
});

test('old/new boundary: a legacy raw-identifier row is rejected, counted, and removed only by explicit apply', async () => {
  const s = await setup();
  try {
    const liveRt = await issue(s.server);
    const legacyValue = 'legacy-synthetic-raw-refresh-value-001';
    await s.store.saveRefreshToken(legacy(legacyValue)); // pre-cutover row keyed by the raw value

    // Not silently accepted: presenting the raw value hashes it and finds nothing.
    assert.equal((await refresh(s.server, legacyValue)).statusCode, 400);
    assert.equal(await s.store.countLegacyRefreshTokens(), 1);

    // Dry run changes nothing; start-up style re-init changes nothing.
    assert.deepEqual(await runRefreshCutover(s.store, { apply: false }), { format: 'rt1.sha256', legacyFound: 1, purged: 0, applied: false });
    await s.store.init();
    assert.equal(await s.store.countLegacyRefreshTokens(), 1);

    // Explicit apply removes only legacy rows; digest-format sessions survive.
    assert.deepEqual(await runRefreshCutover(s.store, { apply: true }), { format: 'rt1.sha256', legacyFound: 1, purged: 1, applied: true });
    assert.equal(await s.store.countLegacyRefreshTokens(), 0);
    assert.equal((await refresh(s.server, legacyValue)).statusCode, 400);
    assert.equal((await refresh(s.server, liveRt)).statusCode, 200);
    // Idempotent.
    assert.equal((await runRefreshCutover(s.store, { apply: true })).purged, 0);
  } finally { await s.cleanup(); }
});

// -- shared document-store path (PostgreSQL/MongoDB adapters), over an in-memory fake --

class MemoryDocuments implements Documents {
  readonly data = new Map<string, unknown>();
  async get<T>(kind: string, id: string) { return (this.data.get(`${kind}\0${id}`) as T | undefined) ?? null; }
  async insert<T>(kind: string, id: string, v: T) { if (this.data.has(`${kind}\0${id}`)) throw new Error('dup'); this.data.set(`${kind}\0${id}`, v); }
  async put<T>(kind: string, id: string, v: T) { this.data.set(`${kind}\0${id}`, v); }
  async remove(kind: string, id: string) { this.data.delete(`${kind}\0${id}`); }
  async list<T>(kind: string) { return [...this.data].filter(([k]) => k.startsWith(`${kind}\0`)).map(([, v]) => v as T); }
  async find<T>(kind: string, field: string, value: string) {
    return (await this.list<Record<string, unknown>>(kind)).filter((v) => v[field] === value) as T[];
  }
  async purge(kind: string, now: number) {
    let removed = 0;
    for (const [k, v] of [...this.data]) {
      if (k.startsWith(`${kind}\0`) && (v as { expiresAt?: number }).expiresAt !== undefined && (v as { expiresAt: number }).expiresAt <= now) { this.data.delete(k); removed++; }
    }
    return removed;
  }
  async countLive(kind: string, now: number, field?: string, value?: string) {
    return (await this.list<Record<string, unknown>>(kind))
      .filter((v) => typeof v.expiresAt === 'number' && v.expiresAt > now && (field === undefined || v[field] === value)).length;
  }
  async health() { /* ok */ }
}
class MemoryStore extends DocumentStore {
  readonly docs = new MemoryDocuments();
  protected run<T>(fn: (db: Documents) => Promise<T>) { return fn(this.docs); }
  transaction<T>(fn: (tx: Store) => Promise<T>) { return fn(new TransactionDocuments(this.docs)); }
  async init() { /* none */ }
  async close() { /* none */ }
}

test('document store: rotation lineage, replay, revoke and legacy purge on digest identifiers', async () => {
  const store = new MemoryStore();
  const a = refreshTokenId('doc-a');
  const b = refreshTokenId('doc-b');
  await store.saveRefreshToken({ ...legacy(a), family: a });
  assert.ok(await store.getRefreshToken(a, NOW));
  assert.ok(await store.consumeRefreshToken(a, NOW));
  await store.saveRefreshToken({ ...legacy(b), family: a, parentJti: a });
  // Replaying the consumed parent revokes the family.
  assert.equal(await store.consumeRefreshToken(a, NOW), null);
  assert.equal(await store.getRefreshToken(b, NOW), null);

  const c = refreshTokenId('doc-c');
  await store.saveRefreshToken(legacy(c));
  assert.equal(await store.revokeRefreshToken(c, NOW), true);
  assert.equal(await store.getRefreshToken(c, NOW), null);

  await store.saveRefreshToken(legacy('raw-legacy-doc-value'));
  assert.equal(await store.countLegacyRefreshTokens(), 1);
  assert.equal(await store.getRefreshToken(refreshTokenId('raw-legacy-doc-value'), NOW), null);
  assert.equal(await store.purgeLegacyRefreshTokens(), 1);
  assert.equal(await store.countLegacyRefreshTokens(), 0);
  assert.equal((await store.docs.list('refresh')).length, 3); // a, b, c remain
});

test('replay revocation landing between consume and replacement save leaves no usable token', async () => {
  const s = await setup();
  try {
    const rt1 = await issue(s.server);
    const base = s.store;
    let injected = false;
    let replayStatus = 0;
    // Deterministic interleaving: when the winning request saves its replacement, a replay of the
    // already-consumed parent (revoking the family) completes first.
    const racing = new Proxy(base, {
      get(target, prop) {
        if (prop === 'saveRefreshToken') {
          return async (t: RefreshTokenRecord) => {
            if (!injected && t.parentJti !== null) {
              injected = true;
              replayStatus = (await refresh(s.server, rt1)).statusCode;
            }
            return target.saveRefreshToken(t);
          };
        }
        const v = Reflect.get(target, prop, target) as unknown;
        return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    }) as Store;
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const signer = await createJoseSigner(await exportPKCS8(privateKey), 'k1');
    const racer = buildServer({
      store: racing, signer, clock: { now: () => NOW }, random: cryptoRandom, issuer: 'http://localhost:8080',
      authenticate: async () => 'user-1', refreshTokenTtl: 86_400,
    });
    try {
      const winner = await refresh(racer, rt1);
      assert.equal(replayStatus, 400, 'replay is rejected');
      assert.equal(winner.statusCode, 400, 'winner fails closed');
      assert.equal(winner.json().refresh_token, undefined);
      const db = s.raw();
      const live = db.prepare('SELECT COUNT(*) AS n FROM refresh_tokens WHERE revoked_at IS NULL AND revoked_by_replay_at IS NULL').get() as unknown as { n: number };
      db.close();
      assert.equal(live.n, 0, 'no usable refresh token remains in the family');
    } finally { await racer.close(); }
  } finally { await s.cleanup(); }
});
