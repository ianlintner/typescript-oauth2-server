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
  scope: string;
  codeChallenge: string;
  expiresAt: number;
  consumedAt: number | null;
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

  /** Run `fn` atomically; commits on resolve, rolls back and rethrows on reject. Not reentrant. */
  transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T>;
}
