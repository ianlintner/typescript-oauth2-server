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
