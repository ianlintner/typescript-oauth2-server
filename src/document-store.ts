import type { AccessTokenRecord, AuthorizationCodeRecord, ClientRecord, DeviceCodeRecord, ParRecord, RefreshTokenRecord, Store, TrustedIssuerRecord, WindowCount } from './ports.js';
import { isDigestRefreshId } from './token-digest.js';

/** Database-specific primitives; callers hold a real backend transaction. */
export interface Documents {
  get<T>(kind: string, id: string): Promise<T | null>;
  insert<T>(kind: string, id: string, value: T): Promise<void>;
  put<T>(kind: string, id: string, value: T): Promise<void>;
  remove(kind: string, id: string): Promise<void>;
  list<T>(kind: string): Promise<T[]>;
  /** Documents of `kind` whose top-level `field` equals `value`; backends index the fields used here. */
  find<T>(kind: string, field: string, value: string): Promise<T[]>;
  /** Remove documents of `kind` whose numeric `expiresAt` is at or before `now`; returns the count. */
  purge(kind: string, now: number): Promise<number>;
  /** Count documents of `kind` whose `expiresAt` is after `now`, optionally with `field` equal to `value`. */
  countLive(kind: string, now: number, field?: string, value?: string): Promise<number>;
  health(): Promise<void>;
}

/** One contract for SQL and document backends. All read-modify-write paths execute in a database transaction. */
export abstract class DocumentStore implements Store {
  protected abstract run<T>(fn: (db: Documents) => Promise<T>): Promise<T>;
  abstract transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T>;
  abstract init(): Promise<void>;
  abstract close(): Promise<void>;
  healthcheck(): Promise<void> { return this.run(db => db.health()); }
  saveClient(c: ClientRecord): Promise<void> { return this.run(db => db.put('client', c.clientId, c)); }
  getClient(id: string): Promise<ClientRecord | null> { return this.run(db => db.get('client', id)); }
  deleteClient(id: string): Promise<boolean> { return this.run(async db => {
    if (!await db.get('client', id)) return false;
    for (const kind of ['code', 'access', 'refresh', 'device', 'par']) {
      const records = await db.find<Record<string, unknown>>(kind, 'clientId', id);
      for (const r of records) await db.remove(kind, String(r.codeHash ?? r.jti ?? r.deviceCodeHash ?? r.requestUriHash));
    }
    await db.remove('client', id);
    return true;
  }); }
  saveTrustedIssuer(t: TrustedIssuerRecord): Promise<void> { return this.run(db => db.put('trusted_issuer', t.issuer, t)); }
  getTrustedIssuer(issuer: string): Promise<TrustedIssuerRecord | null> { return this.run(db => db.get('trusted_issuer', issuer)); }
  listTrustedIssuers(): Promise<TrustedIssuerRecord[]> { return this.run(db => db.list('trusted_issuer')); }
  deleteTrustedIssuer(id: string): Promise<boolean> { return this.run(async db => {
    const matches = (await db.list<TrustedIssuerRecord>('trusted_issuer')).filter(t => t.id === id);
    for (const t of matches) await db.remove('trusted_issuer', t.issuer);
    return matches.length > 0;
  }); }
  saveDeviceCode(d: DeviceCodeRecord): Promise<void> { return this.run(async db => {
    if ((await db.find<DeviceCodeRecord>('device', 'userCodeHash', d.userCodeHash)).length > 0) throw new Error('duplicate user code');
    await db.insert('device', d.deviceCodeHash, d);
  }); }
  getDeviceCode(h: string): Promise<DeviceCodeRecord | null> { return this.run(db => db.get('device', h)); }
  recordDevicePoll(h: string, now: number, interval: number): Promise<void> { return this.run(async db => {
    const r = await db.get<DeviceCodeRecord>('device', h);
    if (r) await db.put('device', h, { ...r, lastPolledAt: now, interval });
  }); }
  resolveDeviceCode(user: string, status: 'approved' | 'denied', subject: string, now: number): Promise<boolean> { return this.run(async db => {
    const r = (await db.find<DeviceCodeRecord>('device', 'userCodeHash', user)).find(x => x.status === 'pending' && x.expiresAt > now);
    if (!r) return false;
    await db.put('device', r.deviceCodeHash, { ...r, status, subject });
    return true;
  }); }
  consumeDeviceCode(h: string, now: number): Promise<DeviceCodeRecord | null> { return this.run(async db => {
    const r = await db.get<DeviceCodeRecord>('device', h);
    if (!r || r.status !== 'approved' || r.expiresAt <= now) return null;
    await db.put('device', h, { ...r, status: 'consumed' });
    return r;
  }); }
  savePar(p: ParRecord): Promise<void> { return this.run(db => db.insert('par', p.requestUriHash, p)); }
  getPar(h: string, now: number): Promise<ParRecord | null> { return this.run(async db => {
    const r = await db.get<ParRecord>('par', h);
    return r && r.consumedAt === null && r.expiresAt > now ? r : null;
  }); }
  consumePar(h: string, client: string, now: number): Promise<ParRecord | null> { return this.run(async db => {
    const r = await db.get<ParRecord>('par', h);
    if (!r || r.clientId !== client || r.consumedAt !== null || r.expiresAt <= now) return null;
    const result = { ...r, consumedAt: now };
    await db.put('par', h, result);
    return result;
  }); }
  saveAuthorizationCode(c: AuthorizationCodeRecord): Promise<void> { return this.run(async db => {
    if (!await db.get('client', c.clientId)) throw new Error('unknown client');
    await db.insert('code', c.codeHash, c);
  }); }
  consumeAuthorizationCode(h: string, now: number): Promise<AuthorizationCodeRecord | null> { return this.run(async db => {
    const r = await db.get<AuthorizationCodeRecord>('code', h);
    if (!r || r.consumedAt !== null || r.expiresAt <= now) return null;
    const consumed = { ...r, consumedAt: now };
    await db.put('code', h, consumed);
    return consumed;
  }); }
  saveAccessToken(t: AccessTokenRecord): Promise<void> { return this.run(db => db.insert('access', t.jti, t)); }
  getAccessToken(id: string, now: number): Promise<AccessTokenRecord | null> { return this.run(async db => {
    const r = await db.get<AccessTokenRecord>('access', id);
    return r && r.revokedAt === null && r.expiresAt > now ? r : null;
  }); }
  revokeAccessToken(id: string, now: number): Promise<boolean> { return this.run(async db => {
    const r = await db.get<AccessTokenRecord>('access', id);
    if (!r) return false;
    await db.put('access', id, { ...r, revokedAt: now });
    return true;
  }); }
  saveRefreshToken(t: RefreshTokenRecord): Promise<void> { return this.run(db => db.insert('refresh', t.jti, { ...t, dpopJkt: t.dpopJkt ?? null, resource: t.resource ?? null, consumedAt: null })); }
  getRefreshToken(id: string, now: number): Promise<RefreshTokenRecord | null> { return this.run(async db => {
    const r = await db.get<RefreshTokenRecord>('refresh', id);
    return r && r.expiresAt > now && r.revokedAt === null && r.revokedByReplayAt === null ? r : null;
  }); }
  consumeRefreshToken(id: string, now: number): Promise<RefreshTokenRecord | null> { return this.run(async db => {
    const r = await db.get<RefreshTokenRecord & { consumedAt: number | null }>('refresh', id);
    if (!r || r.expiresAt <= now || r.revokedAt !== null || r.revokedByReplayAt !== null) return null;
    const family = await db.find<RefreshTokenRecord & { consumedAt: number | null }>('refresh', 'family', r.family);
    const revoke = async () => { for (const item of family) if (item.revokedAt === null && item.revokedByReplayAt === null) await db.put('refresh', item.jti, { ...item, revokedByReplayAt: now }); };
    if (r.consumedAt !== null) { await revoke(); return null; }
    await db.put('refresh', id, { ...r, consumedAt: now });
    return r;
  }); }
  revokeRefreshToken(id: string, now: number): Promise<boolean> { return this.run(async db => {
    const r = await db.get<RefreshTokenRecord>('refresh', id);
    if (!r) return false;
    await db.put('refresh', id, { ...r, revokedAt: now });
    return true;
  }); }
  revokeGrant(grant: string, now: number, clientId?: string): Promise<number> { return this.run(async db => {
    const filter = (r: { clientId: string }) => clientId === undefined || r.clientId === clientId;
    for (const a of await db.find<AccessTokenRecord>('access', 'grant', grant)) {
      if (a.revokedAt === null && filter(a)) await db.put('access', a.jti, { ...a, revokedAt: now });
    }
    let count = 0;
    for (const r of await db.find<RefreshTokenRecord>('refresh', 'family', grant)) {
      if (r.revokedAt === null && r.revokedByReplayAt === null && filter(r)) {
        await db.put('refresh', r.jti, { ...r, revokedAt: now }); count++;
      }
    }
    return count;
  }); }
  recordWindowHit(key: string, windowSeconds: number, now: number): Promise<WindowCount> { return this.run(async db => {
    const current = await db.get<{ count: number; expiresAt: number }>('window', key);
    const next = current && current.expiresAt > now
      ? { count: current.count + 1, expiresAt: current.expiresAt }
      : { count: 1, expiresAt: now + windowSeconds };
    await db.put('window', key, next);
    return { count: next.count, resetAt: next.expiresAt };
  }); }
  peekWindow(key: string, now: number): Promise<WindowCount | null> { return this.run(async db => {
    const current = await db.get<{ count: number; expiresAt: number }>('window', key);
    return current && current.expiresAt > now ? { count: current.count, resetAt: current.expiresAt } : null;
  }); }
  countLiveRecords(kind: 'par' | 'device', now: number, clientId?: string): Promise<number> {
    return this.run(db => clientId === undefined ? db.countLive(kind, now) : db.countLive(kind, now, 'clientId', clientId));
  }
  sweepExpired(now: number): Promise<number> { return this.run(async db => {
    let removed = 0;
    for (const kind of ['code', 'access', 'refresh', 'device', 'par', 'proof', 'window']) removed += await db.purge(kind, now);
    return removed;
  }); }
  countLegacyRefreshTokens(): Promise<number> { return this.run(async db =>
    (await db.list<RefreshTokenRecord>('refresh')).filter(r => !isDigestRefreshId(r.jti)).length); }
  purgeLegacyRefreshTokens(): Promise<number> { return this.run(async db => {
    const legacy = (await db.list<RefreshTokenRecord>('refresh')).filter(r => !isDigestRefreshId(r.jti));
    for (const r of legacy) await db.remove('refresh', r.jti);
    return legacy.length;
  }); }
  consumeDpopJti(key: string, expiresAt: number, now: number): Promise<boolean> { return this.run(async db => {
    const current = await db.get<{ expiresAt: number }>('proof', key);
    if (current && current.expiresAt > now) return false;
    await db.put('proof', key, { expiresAt });
    return true;
  }); }
}

/** Scoped handle cannot outlive its callback or start a nested transaction. */
export class TransactionDocuments extends DocumentStore {
  private active = true;
  constructor(private readonly db: Documents) { super(); }
  documents(): Documents {
    if (!this.active) throw new Error('transaction has ended');
    return this.db;
  }
  end(): void { this.active = false; }
  protected run<T>(fn: (db: Documents) => Promise<T>): Promise<T> {
    if (!this.active) return Promise.reject(new Error('transaction has ended'));
    return fn(this.db);
  }
  transaction<T>(): Promise<T> { return Promise.reject(new Error('nested transactions are not supported')); }
  init(): Promise<void> { return Promise.reject(new Error('not available inside a transaction')); }
  close(): Promise<void> { return Promise.reject(new Error('not available inside a transaction')); }
}
