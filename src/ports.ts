export interface Clock {
  /** Current time in whole seconds since the Unix epoch. */
  now(): number;
}

export interface Random {
  /** URL-safe random string with at least `bytes` bytes of entropy. */
  token(bytes: number): string;
}

export interface Jwks {
  keys: Array<Record<string, unknown>>;
}

export interface Signer {
  sign(claims: Record<string, unknown>): Promise<string>;
  publicJwks(): Promise<Jwks>;
}

export interface ClientRecord {
  clientId: string;
  clientSecretHash: string | null;
  redirectUris: string[];
  grantTypes: string[];
  scopes: string[];
  enabled: boolean;
  /** Present only for clients created through RFC 7591 dynamic registration. */
  registration?: ClientRegistration | null | undefined;
}

/** RFC 7591/7592 state. The registration access token is stored only as a SHA-256 hash. */
export interface ClientRegistration {
  tokenHash: string;
  issuedAt: number;
  /** Echoed client metadata (client_name, token_endpoint_auth_method, ...). */
  metadata: Record<string, unknown>;
}

export type DeviceCodeStatus = 'pending' | 'approved' | 'denied' | 'consumed';

/** RFC 8628 device authorization. Codes are stored only as SHA-256 hashes. */
export interface DeviceCodeRecord {
  deviceCodeHash: string;
  userCodeHash: string;
  clientId: string;
  scope: string;
  expiresAt: number;
  /** Minimum seconds between polls; raised by 5 on each slow_down (RFC 8628 §3.5). */
  interval: number;
  lastPolledAt: number | null;
  status: DeviceCodeStatus;
  subject: string | null;
}

/** RFC 9126 pushed authorization request, bound to the pushing client. */
export interface ParRecord {
  requestUriHash: string;
  clientId: string;
  params: Record<string, string>;
  expiresAt: number;
  consumedAt: number | null;
}

export interface AuthorizationCodeRecord {
  codeHash: string;
  clientId: string;
  redirectUri: string;
  /** Authenticated resource owner the code was issued for. */
  subject: string;
  scope: string;
  codeChallenge: string;
  expiresAt: number;
  consumedAt: number | null;
  /** OIDC nonce, set from the authorize request. */
  nonce: string | null;
  /** Epoch seconds the end-user authenticated, recorded when max_age was requested (OIDC auth_time). */
  authTime: number | null;
}

export interface AccessTokenRecord {
  jti: string;
  clientId: string;
  subject: string;
  scope: string;
  expiresAt: number;
  revokedAt: number | null;
  /** JWT token hash for lookup. Null for opaque tokens. */
  tokenHash: string | null;
}

export interface RefreshTokenRecord {
  jti: string;
  clientId: string;
  subject: string;
  scope: string;
  expiresAt: number;
  family: string;
  /** Previous refresh-token jti this token replaced, or null for initial issuance. */
  parentJti: string | null;
  /** Set when a rotated-but-unused refresh is found reused (replay attack). */
  revokedByReplayAt: number | null;
  /** Simple revocation (not replay). */
  revokedAt: number | null;
}

export interface Store {
  init(): Promise<void>;
  close(): Promise<void>;
  healthcheck(): Promise<void>;

  saveClient(client: ClientRecord): Promise<void>;
  getClient(clientId: string): Promise<ClientRecord | null>;
  /** Delete a client and everything issued to it. Returns false if unknown. */
  deleteClient(clientId: string): Promise<boolean>;

  saveDeviceCode(record: DeviceCodeRecord): Promise<void>;
  getDeviceCode(deviceCodeHash: string): Promise<DeviceCodeRecord | null>;
  /** Record a poll attempt and the (possibly increased) interval. */
  recordDevicePoll(deviceCodeHash: string, now: number, interval: number): Promise<void>;
  /** Atomically decide a pending, unexpired code. False if unknown, expired or already decided. */
  resolveDeviceCode(userCodeHash: string, status: 'approved' | 'denied', subject: string, now: number): Promise<boolean>;
  /** Atomically consume an approved, unexpired code (one-time). */
  consumeDeviceCode(deviceCodeHash: string, now: number): Promise<DeviceCodeRecord | null>;

  savePar(record: ParRecord): Promise<void>;
  /** Read a pushed request without consuming. Null if unknown or expired. */
  getPar(requestUriHash: string, now: number): Promise<ParRecord | null>;
  /** Atomically consume an unexpired pushed request bound to `clientId` (one-time). */
  consumePar(requestUriHash: string, clientId: string, now: number): Promise<ParRecord | null>;

  saveAuthorizationCode(code: AuthorizationCodeRecord): Promise<void>;
  /**
   * Atomically mark an unexpired, unconsumed code as consumed and return it.
   * Returns null if unknown, expired or already consumed (replay).
   */
  consumeAuthorizationCode(codeHash: string, now: number): Promise<AuthorizationCodeRecord | null>;

  /** Save a newly issued access token. */
  saveAccessToken(token: AccessTokenRecord): Promise<void>;
  /** Look up a non-revoked, non-expired access token by jti. */
  getAccessToken(jti: string, now: number): Promise<AccessTokenRecord | null>;
  /** Mark an access token revoked (no-op for unknown). */
  revokeAccessToken(jti: string, now: number): Promise<boolean>;

  /** Save a newly issued refresh token. */
  saveRefreshToken(token: RefreshTokenRecord): Promise<void>;
  /**
   * Look up a refresh token by jti (without consuming). Returns null if
   * unknown, expired, revoked, or revoked by replay.
   */
  getRefreshToken(jti: string, now: number): Promise<RefreshTokenRecord | null>;
  /**
   * Atomically consume and rotate a refresh token: mark the presented token
   * consumed, check for replay (already-consumed within the same family),
   * and return the consumed record. Returns null if unknown or expired.
   */
  consumeRefreshToken(jti: string, now: number): Promise<RefreshTokenRecord | null>;
  /** Mark a refresh token revoked (no-op for unknown). */
  revokeRefreshToken(jti: string, now: number): Promise<boolean>;
  /**
   * Revoke the entire family (all tokens in the same family that are not
   * already revoked). Call on replay detection.
   */
  revokeTokenFamily(family: string, now: number): Promise<number>;

  /** Run `fn` atomically; commits on resolve, rolls back and rethrows on reject. Not reentrant. */
  transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T>;
}
