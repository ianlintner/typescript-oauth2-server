import type { AccessTokenRecord, AuthorizationCodeRecord, ClientRecord, DeviceCodeRecord, ParRecord, RefreshTokenRecord, Store } from './ports.js';

/** Database-specific primitives; callers hold a real backend transaction. */
export interface Documents {
  get<T>(kind: string, id: string): Promise<T | null>;
  insert<T>(kind: string, id: string, value: T): Promise<void>;
  put<T>(kind: string, id: string, value: T): Promise<void>;
  remove(kind: string, id: string): Promise<void>;
  list<T>(kind: string): Promise<T[]>;
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
      const records = await db.list<Record<string, unknown>>(kind);
      for (const r of records) if (r.clientId === id) await db.remove(kind, String(r.codeHash ?? r.jti ?? r.deviceCodeHash ?? r.requestUriHash));
    }
    await db.remove('client', id);
    return true;
  }); }
  saveDeviceCode(d: DeviceCodeRecord): Promise<void> { return this.run(async db => {
    if ((await db.list<DeviceCodeRecord>('device')).some(x => x.userCodeHash === d.userCodeHash)) throw new Error('duplicate user code');
    await db.insert('device', d.deviceCodeHash, d);
  }); }
  getDeviceCode(h: string): Promise<DeviceCodeRecord | null> { return this.run(db => db.get('device', h)); }
  recordDevicePoll(h: string, now: number, interval: number): Promise<void> { return this.run(async db => {
    const r = await db.get<DeviceCodeRecord>('device', h);
    if (r) await db.put('device', h, { ...r, lastPolledAt: now, interval });
  }); }
  resolveDeviceCode(user: string, status: 'approved' | 'denied', subject: string, now: number): Promise<boolean> { return this.run(async db => {
    const r = (await db.list<DeviceCodeRecord>('device')).find(x => x.userCodeHash === user && x.status === 'pending' && x.expiresAt > now);
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
  saveRefreshToken(t: RefreshTokenRecord): Promise<void> { return this.run(db => db.insert('refresh', t.jti, { ...t, dpopJkt: t.dpopJkt ?? null, consumedAt: null })); }
  getRefreshToken(id: string, now: number): Promise<RefreshTokenRecord | null> { return this.run(async db => {
    const r = await db.get<RefreshTokenRecord>('refresh', id);
    return r && r.expiresAt > now && r.revokedAt === null && r.revokedByReplayAt === null ? r : null;
  }); }
  consumeRefreshToken(id: string, now: number): Promise<RefreshTokenRecord | null> { return this.run(async db => {
    const r = await db.get<RefreshTokenRecord & { consumedAt: number | null }>('refresh', id);
    if (!r || r.expiresAt <= now || r.revokedAt !== null || r.revokedByReplayAt !== null) return null;
    const family = (await db.list<RefreshTokenRecord & { consumedAt: number | null }>('refresh')).filter(x => x.family === r.family);
    const revoke = async () => { for (const item of family) if (item.revokedAt === null && item.revokedByReplayAt === null) await db.put('refresh', item.jti, { ...item, revokedByReplayAt: now }); };
    if (r.consumedAt !== null) { await revoke(); return null; }
    const sibling = family.some(x => x.jti !== id && x.jti !== r.parentJti && x.consumedAt !== null && x.revokedAt === null && x.revokedByReplayAt === null);
    await db.put('refresh', id, { ...r, consumedAt: now });
    if (sibling) await revoke();
    return r;
  }); }
  revokeRefreshToken(id: string, now: number): Promise<boolean> { return this.run(async db => {
    const r = await db.get<RefreshTokenRecord>('refresh', id);
    if (!r) return false;
    await db.put('refresh', id, { ...r, revokedAt: now });
    return true;
  }); }
  revokeTokenFamily(family: string, now: number): Promise<number> { return this.run(async db => {
    let count = 0;
    for (const r of await db.list<RefreshTokenRecord>('refresh')) if (r.family === family && r.revokedAt === null && r.revokedByReplayAt === null) {
      await db.put('refresh', r.jti, { ...r, revokedAt: now }); count++;
    }
    return count;
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
