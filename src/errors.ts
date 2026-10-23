export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'invalid_dpop_proof'
  | 'access_denied'
  | 'server_error'
  | 'temporarily_unavailable'
  | 'invalid_client_metadata'
  | 'invalid_redirect_uri'
  | 'authorization_pending'
  | 'slow_down'
  | 'expired_token'
  | 'invalid_request_uri'
  | 'unsupported_response_type';

const STATUS: Record<OAuthErrorCode, number> = {
  invalid_request: 400,
  invalid_client: 401,
  invalid_grant: 400,
  unauthorized_client: 400,
  unsupported_grant_type: 400,
  invalid_scope: 400,
  invalid_dpop_proof: 400,
  access_denied: 403,
  server_error: 500,
  temporarily_unavailable: 503,
  invalid_client_metadata: 400,
  invalid_redirect_uri: 400,
  authorization_pending: 400,
  slow_down: 400,
  expired_token: 400,
  invalid_request_uri: 400,
  unsupported_response_type: 400,
};

export class OAuthError extends Error {
  readonly code: OAuthErrorCode;
  readonly description: string | undefined;

  constructor(code: OAuthErrorCode, description?: string) {
    super(description ?? code);
    this.name = 'OAuthError';
    this.code = code;
    this.description = description;
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
  const body: ErrorResponse['body'] = { error: err.code };
  // Server-side failure details are never exposed to clients.
  if (err.description !== undefined && err.code !== 'server_error') {
    body.error_description = err.description;
  }
  return { status: STATUS[err.code], headers, body };
}
