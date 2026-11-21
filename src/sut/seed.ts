import { createPublicKey, type webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parse as parseYaml } from 'yaml';
import { hashClientSecret } from '../client-auth.js';
import type { ClientRecord, Jwks, Store } from '../ports.js';

/** Validated, normalized conformance seed (contract/sut-interface.md §2, schemas/seed.schema.json). */
export interface SeedClient {
  clientId: string;
  /** Plaintext only until applySeed hashes it; null for public clients. */
  clientSecret: string | null;
  /** private_key_jwt only: the client's public JWKS (RFC 7523 §2.2). */
  jwks?: Jwks | undefined;
  redirectUris: string[];
  grantTypes: string[];
  scopes: string[];
}
export interface SeedUser {
  username: string;
  password: string;
  autoApproveClients: string[];
  email?: string | undefined;
}
export interface SeedSigningKey {
  kid: string;
  alg: string;
}
export interface Seed {
  issuer: string;
  clients: SeedClient[];
  users: SeedUser[];
  signingKeys: SeedSigningKey[];
}

export class SeedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SeedError';
  }
}

const MAX_DOCUMENT_BYTES = 1024 * 1024;
const DEFAULT_SCOPES = ['openid', 'read'];
const DEFAULT_GRANT_TYPES = ['authorization_code'];
const GRANT_TYPES = new Set([
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'urn:ietf:params:oauth:grant-type:device_code',
  'urn:ietf:params:oauth:grant-type:jwt-bearer',
]);
const AUTH_METHODS = new Set(['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt']);
const ALG_RE = /^(RS|ES|PS|HS)[0-9]{3}$/;
/** The only signing algorithm this server can provision (see signer.ts). */
const PROVISIONABLE_ALG = 'ES256';

type Obj = Record<string, unknown>;

function fail(message: string): never {
  throw new SeedError(message);
}

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function obj(v: unknown, where: string): Obj {
  if (!isObj(v)) fail(`${where} must be an object`);
  return v;
}

function onlyKeys(o: Obj, allowed: readonly string[], where: string): void {
  for (const key of Object.keys(o)) {
    if (!allowed.includes(key)) fail(`${where}: unknown property ${JSON.stringify(key)}`);
  }
}

function str(o: Obj, key: string, where: string): string {
  const v = o[key];
  if (typeof v !== 'string' || v === '') fail(`${where}: ${key} must be a nonempty string`);
  return v;
}

function optStr(o: Obj, key: string, where: string): string | undefined {
  return o[key] === undefined ? undefined : str(o, key, where);
}

function strArray(o: Obj, key: string, where: string, opts: { min?: number } = {}): string[] {
  const v = o[key];
  if (!Array.isArray(v)) fail(`${where}: ${key} must be an array`);
  if (opts.min !== undefined && v.length < opts.min) fail(`${where}: ${key} must have at least ${opts.min} item(s)`);
  for (const item of v) if (typeof item !== 'string') fail(`${where}: ${key} entries must be strings`);
  return v as string[];
}

/**
 * A seed jwks entry is persisted as client metadata and later handed to the
 * verifier, so it must be a complete *public* verification key:
 *  - no private or symmetric material (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`),
 *  - a public asymmetric kty (never `oct`),
 *  - the public parameters the verifier needs (RFC 7518 §6.2 EC / §6.3 RSA).
 * Anything else would either leak a secret into storage or pass startup and then
 * silently fail every client assertion, so both cases fail here.
 */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;
const PUBLIC_JWK_MEMBERS = ['kty', 'kid', 'use', 'alg', 'key_ops', 'x5c', 'x5t', 'x5t#S256', 'x5u', 'crv', 'x', 'y', 'n', 'e'];
const EC_COORDINATE_BYTES: Record<string, number> = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };
const EC_CURVES = new Set(Object.keys(EC_COORDINATE_BYTES));
const MIN_RSA_MODULUS_BYTES = 256; // RFC 7518 §3.3: RSA keys of at least 2048 bits

function isBase64Url(v: unknown, minBytes = 1): boolean {
  if (typeof v !== 'string' || v === '' || !/^[A-Za-z0-9_-]+$/.test(v)) return false;
  const decoded = Buffer.from(v, 'base64url');
  return decoded.byteLength >= minBytes && decoded.toString('base64url').replace(/=+$/, '') === v.replace(/=+$/, '');
}

function checkVerificationKey(k: Obj, where: string): Obj {
  for (const member of PRIVATE_JWK_MEMBERS) {
    if (k[member] !== undefined) {
      fail(`${where}: must carry public key material only (${JSON.stringify(member)} is private or symmetric)`);
    }
  }
  for (const member of Object.keys(k)) {
    if (!PUBLIC_JWK_MEMBERS.includes(member)) fail(`${where}: unknown property ${JSON.stringify(member)}`);
  }
  const kty = k.kty;
  if (kty === 'oct') fail(`${where}: a symmetric key cannot be a client assertion verification key`);
  if (kty === 'EC') {
    if (typeof k.crv !== 'string' || !EC_CURVES.has(k.crv)) fail(`${where}: EC key needs crv P-256, P-384 or P-521`);
    // The reference accepts RS/ES/PS for assertions; these are the EC curves we can actually verify against.
    if (!isBase64Url(k.x, 1) || !isBase64Url(k.y, 1)) fail(`${where}: EC key needs base64url x and y`);
    // RFC 7518 §6.2.1.2/3: coordinates are the full curve field size, zero-padded.
    const size = EC_COORDINATE_BYTES[k.crv] as number;
    if (Buffer.from(k.x as string, 'base64url').byteLength !== size || Buffer.from(k.y as string, 'base64url').byteLength !== size) {
      fail(`${where}: EC ${k.crv} x and y must be ${size} bytes`);
    }
  } else if (kty === 'RSA') {
    if (!isBase64Url(k.n, MIN_RSA_MODULUS_BYTES)) fail(`${where}: RSA key needs n of at least 2048 bits`);
    if (!isBase64Url(k.e)) fail(`${where}: RSA key needs base64url e`);
    // Node's JWK import does not validate RSA parameters: reject a zero/even modulus or an unusable exponent here.
    const n = Buffer.from(k.n as string, 'base64url');
    const e = Buffer.from(k.e as string, 'base64url');
    if (n[0] === 0 || (n[n.length - 1]! & 1) === 0) fail(`${where}: RSA n must be an odd modulus with no leading zero bytes`);
    if (e.every((b) => b === 0) || (e[e.length - 1]! & 1) === 0 || (e.length === 1 && e[0] === 1)) fail(`${where}: RSA e must be an odd exponent of at least 3`);
  } else {
    fail(`${where}: unsupported kty ${JSON.stringify(kty)} (only EC and RSA are verification keys)`);
  }
  // A real import catches what the shape checks cannot (off-curve points, unusable RSA parameters):
  // such a key would pass startup and then silently fail every assertion.
  try {
    createPublicKey({ key: k as unknown as webcrypto.JsonWebKey, format: 'jwk' });
  } catch {
    fail(`${where}: not a valid public key (cannot be imported)`);
  }
  if (k.alg !== undefined && (typeof k.alg !== 'string' || !ALG_RE.test(k.alg))) fail(`${where}: alg is not a recognized JWS algorithm`);
  if (k.use !== undefined && k.use !== 'sig') fail(`${where}: use must be "sig"`);
  if (k.kid !== undefined && (typeof k.kid !== 'string' || k.kid === '')) fail(`${where}: kid must be a nonempty string`);
  return k;
}

function parseClient(raw: unknown, index: number): SeedClient {
  const at = `clients[${index}]`;
  const c = obj(raw, at);
  onlyKeys(c, ['client_id', 'name', 'client_secret', 'token_endpoint_auth_method', 'public', 'redirect_uris', 'scopes', 'grant_types', 'jwks'], at);
  const clientId = str(c, 'client_id', at);
  const where = `client ${JSON.stringify(clientId)}`;
  optStr(c, 'name', where);
  const secret = optStr(c, 'client_secret', where) ?? null;
  const method = optStr(c, 'token_endpoint_auth_method', where);
  if (method !== undefined && !AUTH_METHODS.has(method)) fail(`${where}: token_endpoint_auth_method ${JSON.stringify(method)} is not supported`);
  if (c.public !== undefined && typeof c.public !== 'boolean') fail(`${where}: public must be a boolean`);
  const isPublic = c.public === true;

  let jwks: Jwks | undefined;
  if (method === 'private_key_jwt') {
    if (isPublic) fail(`${where}: a public client cannot use private_key_jwt`);
    if (secret !== null) fail(`${where}: a private_key_jwt client must not carry a client_secret`);
    const raw = c.jwks;
    if (!isObj(raw) || !Array.isArray(raw.keys) || raw.keys.length === 0 || !raw.keys.every(isObj)) {
      fail(`${where}: private_key_jwt needs jwks with at least one key`);
    }
    jwks = { keys: raw.keys.map((key, i) => checkVerificationKey(obj(key, `${where}: jwks.keys[${i}]`), `${where}: jwks.keys[${i}]`)) };
  } else if (c.jwks !== undefined) {
    fail(`${where}: jwks is only valid with token_endpoint_auth_method private_key_jwt`);
  } else if (isPublic) {
    if (secret !== null) fail(`${where}: a public client must not carry a secret`);
    if (method !== undefined && method !== 'none') fail(`${where}: a public client must use method none`);
  } else {
    if (secret === null) fail(`${where}: a confidential client needs client_secret (or set public: true)`);
    if (method === 'none') fail(`${where}: method none is only valid for a public client`);
  }

  const redirectUris = strArray(c, 'redirect_uris', where, { min: 1 });
  for (const uri of redirectUris) {
    if (uri === '') fail(`${where}: redirect_uris entries must be nonempty`);
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      fail(`${where}: redirect_uri ${JSON.stringify(uri)} is not an absolute URI`);
    }
    if (parsed.hash !== '' || uri.includes('#')) fail(`${where}: redirect_uri ${JSON.stringify(uri)} must not contain a fragment`);
  }

  const scopes = c.scopes === undefined ? [...DEFAULT_SCOPES] : strArray(c, 'scopes', where);
  for (const scope of scopes) {
    if (scope === '' || /\s/.test(scope)) fail(`${where}: invalid scope ${JSON.stringify(scope)}`);
  }
  const grantTypes = c.grant_types === undefined ? [...DEFAULT_GRANT_TYPES] : strArray(c, 'grant_types', where);
  for (const grant of grantTypes) {
    if (!GRANT_TYPES.has(grant)) fail(`${where}: unsupported grant type ${JSON.stringify(grant)}`);
  }
  return { clientId, clientSecret: secret, redirectUris, grantTypes, scopes, ...(jwks ? { jwks } : {}) };
}

/** Parse and validate a YAML or JSON seed document. Any defect throws SeedError: no partial seed, no defaults for invalid input. */
export function parseSeed(text: string): Seed {
  if (Buffer.byteLength(text, 'utf8') > MAX_DOCUMENT_BYTES) fail('seed document is too large');
  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch (err) {
    fail(`seed document is not valid YAML/JSON: ${err instanceof Error ? err.message.split('\n')[0] : 'parse error'}`);
  }
  const root = obj(doc, 'seed document');
  onlyKeys(root, ['issuer', 'signingKeys', 'clients', 'users'], 'seed');

  const issuer = str(root, 'issuer', 'seed');
  if (!/^https?:\/\//.test(issuer)) fail('seed: issuer must be an http(s) URL');
  try {
    new URL(issuer);
  } catch {
    fail('seed: issuer must be a valid URL');
  }
  // RFC 8414/9207: the issuer is compared as a string; the SUT must not normalize it.
  if (issuer.endsWith('/')) fail("seed: issuer must not end with '/'");

  const rawClients = root.clients;
  if (!Array.isArray(rawClients) || rawClients.length === 0) fail('seed: clients must be a nonempty array');
  const clients = rawClients.map(parseClient);
  const clientIds = new Set<string>();
  for (const c of clients) {
    if (clientIds.has(c.clientId)) fail(`seed: duplicate client_id ${JSON.stringify(c.clientId)}`);
    clientIds.add(c.clientId);
  }

  const rawUsers = root.users;
  if (!Array.isArray(rawUsers) || rawUsers.length === 0) fail('seed: users must be a nonempty array');
  const usernames = new Set<string>();
  const users = rawUsers.map((raw, i): SeedUser => {
    const at = `users[${i}]`;
    const u = obj(raw, at);
    onlyKeys(u, ['username', 'password', 'email', 'scopes', 'auto_approve_clients'], at);
    const username = str(u, 'username', at);
    const where = `user ${JSON.stringify(username)}`;
    const password = str(u, 'password', where);
    const email = optStr(u, 'email', where);
    if (email !== undefined && email.length < 3) fail(`${where}: email must be at least 3 characters`);
    if (u.scopes !== undefined) strArray(u, 'scopes', where);
    const autoApproveClients = u.auto_approve_clients === undefined ? [] : strArray(u, 'auto_approve_clients', where);
    for (const id of autoApproveClients) {
      if (!clientIds.has(id)) fail(`${where}: auto_approve_clients names unknown client ${JSON.stringify(id)}`);
    }
    if (usernames.has(username)) fail(`seed: duplicate username ${JSON.stringify(username)}`);
    usernames.add(username);
    return { username, password, autoApproveClients, email };
  });

  const signingKeys: SeedSigningKey[] = [];
  if (root.signingKeys !== undefined) {
    if (!Array.isArray(root.signingKeys)) fail('seed: signingKeys must be an array');
    const kids = new Set<string>();
    root.signingKeys.forEach((raw, i) => {
      const at = `signingKeys[${i}]`;
      const k = obj(raw, at);
      onlyKeys(k, ['kid', 'alg', 'use'], at);
      const kid = str(k, 'kid', at);
      const alg = str(k, 'alg', at);
      if (!ALG_RE.test(alg)) fail(`${at}: alg ${JSON.stringify(alg)} is not a recognized JWS algorithm`);
      if (k.use !== undefined && k.use !== 'sig') fail(`${at}: use must be "sig"`);
      if (kids.has(kid)) fail(`seed: duplicate signing key kid ${JSON.stringify(kid)}`);
      kids.add(kid);
      signingKeys.push({ kid, alg });
    });
  }

  return { issuer, clients, users, signingKeys };
}

/** Read and validate a seed file. A missing, unreadable or invalid file throws SeedError. */
export async function loadSeed(path: string): Promise<Seed> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    throw new SeedError(`cannot read seed file ${JSON.stringify(path)}`);
  }
  return parseSeed(text);
}

/**
 * The seed must be satisfiable by this server as configured: the contract says a
 * SUT that cannot apply the seed completely must not become ready. This server
 * provisions one ES256 key (OAUTH2_SIGNING_KEY_PEM / _ID) and advertises one issuer.
 */
export function assertProvisionable(seed: Seed, config: { issuer: string; signingKeyId: string }): void {
  if (seed.issuer !== config.issuer) {
    fail(`seed issuer ${JSON.stringify(seed.issuer)} does not match OAUTH2_ISSUER ${JSON.stringify(config.issuer)}`);
  }
  for (const key of seed.signingKeys) {
    if (key.alg !== PROVISIONABLE_ALG) {
      fail(`seed signing key ${JSON.stringify(key.kid)}: alg ${key.alg} cannot be provisioned (only ${PROVISIONABLE_ALG} is supported)`);
    }
    if (key.kid !== config.signingKeyId) {
      fail(`seed signing key kid ${JSON.stringify(key.kid)} does not match OAUTH2_SIGNING_KEY_ID ${JSON.stringify(config.signingKeyId)}`);
    }
  }
}

/** Apply the seed atomically to a store. Existing clients are never overwritten: the store must be empty of them. */
export async function applySeed(seed: Seed, store: Store): Promise<void> {
  const records: ClientRecord[] = [];
  for (const c of seed.clients) {
    records.push({
      clientId: c.clientId,
      clientSecretHash: c.clientSecret === null ? null : await hashClientSecret(c.clientSecret),
      redirectUris: c.redirectUris,
      grantTypes: c.grantTypes,
      scopes: c.scopes,
      enabled: true,
      ...(c.jwks ? { tokenEndpointAuthMethod: 'private_key_jwt', jwks: c.jwks } : {}),
    });
  }
  await store.transaction(async (tx) => {
    for (const record of records) {
      if ((await tx.getClient(record.clientId)) !== null) {
        throw new SeedError(`cannot apply seed: client ${JSON.stringify(record.clientId)} already exists`);
      }
      await tx.saveClient(record);
    }
  });
}
