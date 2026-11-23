export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'invalid_target'
  | 'invalid_dpop_proof'
  | 'use_dpop_nonce'
  | 'access_denied'
  | 'server_error'
  | 'temporarily_unavailable'
  | 'invalid_client_metadata'
  | 'invalid_redirect_uri'
  | 'authorization_pending'
  | 'slow_down'
  | 'expired_token'
  | 'invalid_request_uri'
  | 'invalid_authorization_details'
  | 'unsupported_response_type';

const STATUS: Record<OAuthErrorCode, number> = {
  invalid_request: 400,
  invalid_client: 401,
  invalid_grant: 400,
  unauthorized_client: 400,
  unsupported_grant_type: 400,
  invalid_scope: 400,
  invalid_target: 400,
  invalid_dpop_proof: 400,
  use_dpop_nonce: 400,
  access_denied: 403,
  server_error: 500,
  temporarily_unavailable: 503,
  invalid_client_metadata: 400,
  invalid_redirect_uri: 400,
  authorization_pending: 400,
  slow_down: 400,
  expired_token: 400,
  invalid_request_uri: 400,
  invalid_authorization_details: 400,
  unsupported_response_type: 400,
};

export class OAuthError extends Error {
  readonly code: OAuthErrorCode;
  readonly description: string | undefined;
  /** Seconds until a throttled caller may retry; when set the response is 429 with Retry-After. */
  readonly retryAfter: number | undefined;
  /** Fresh server nonce to return in a `DPoP-Nonce` header (RFC 9449 §8). */
  readonly dpopNonce: string | undefined;

  constructor(code: OAuthErrorCode, description?: string, extra?: { retryAfter?: number; dpopNonce?: string }) {
    super(description ?? code);
    this.name = 'OAuthError';
    this.code = code;
    this.description = description;
    this.retryAfter = extra?.retryAfter;
    this.dpopNonce = extra?.dpopNonce;
  }
}

export interface ErrorResponse {
  status: number;
  headers: Record<string, string>;
  body: { error: OAuthErrorCode; error_description?: string };
}

/** Single mapping from errors to RFC 6749 §5.2 status, headers and JSON. */
export function errorResponse(err: unknown): ErrorResponse {
  const headers: Record<string, string> = { 'cache-control': 'no-store', pragma: 'no-cache' };
  if (!(err instanceof OAuthError)) {
    return { status: 500, headers, body: { error: 'server_error' } };
  }
  if (err.code === 'invalid_client') {
    headers['www-authenticate'] = 'Basic realm="oauth2", charset="UTF-8"';
  }
  if (err.dpopNonce !== undefined) headers['dpop-nonce'] = err.dpopNonce;
  const body: ErrorResponse['body'] = { error: err.code };
  // Server-side failure details are never exposed to clients.
  if (err.description !== undefined && err.code !== 'server_error') {
    body.error_description = err.description;
  }
  if (err.retryAfter !== undefined) {
    headers['retry-after'] = String(Math.ceil(err.retryAfter));
    return { status: 429, headers, body };
  }
  return { status: STATUS[err.code], headers, body };
}
