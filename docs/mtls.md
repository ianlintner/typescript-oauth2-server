# RFC 8705 mTLS client authentication and certificate-bound tokens

Supports `tls_client_auth`, `self_signed_tls_client_auth`, `cnf.x5t#S256` binding, and discovery
`tls_client_certificate_bound_access_tokens`. **Disabled by default.**

## Design

The server speaks plain HTTP, so a **trusted TLS terminator** (nginx, Envoy, ALB, ...) performs the
mutual-TLS handshake and forwards the client certificate:

| Env | Meaning |
|---|---|
| `OAUTH2_MTLS_PROXY_SECRET` | Enables mTLS. >= 32 chars, non-placeholder. The proxy must send it as `X-Mtls-Proxy-Secret`. |
| `OAUTH2_MTLS_CERT_HEADER` | Header carrying the cert (default `x-client-cert`; URL-encoded PEM, e.g. nginx `$ssl_client_escaped_cert`, or base64 DER). |
| `OAUTH2_MTLS_CA_PEM` | Optional trust anchor: `tls_client_auth` certs must additionally be directly issued by this CA (single level). |

**Fail closed.** The cert header is honoured only when the shared-secret header matches (constant time).
A direct hit, a mismatched proxy header value, a missing, duplicated or garbled cert, an expired cert, or mTLS left unconfigured all
mean "no certificate": mTLS clients get an opaque `invalid_client`, bound-token clients get no token,
and bound tokens are rejected at userinfo. The proxy must strip any client-supplied copies of both
headers and must only forward the app over a private link.

**Client registration** (`ClientRecord`, set via the store; dynamic registration is not extended yet):
- `tokenEndpointAuthMethod: 'tls_client_auth'` plus `mtls: { subjectDn }` **or** `{ sanDns }` (exactly one).
- `tokenEndpointAuthMethod: 'self_signed_tls_client_auth'` plus `jwks` with an `x5c` entry equal to the cert.
- Any secret-authenticated client may set `mtls: { boundTokens: true }` to require and bind to a cert.

mTLS-authenticated clients always get tokens carrying `cnf: { "x5t#S256": <b64url sha256(DER)> }`
(combined with `jkt` if DPoP is also used). Introspection reports `cnf`; `/oauth/userinfo` requires the
bound certificate. Refresh tokens are not separately cert-bound: refreshing re-authenticates the client
(and re-binds to the presented cert).

## Alternatives considered

- **Direct Node TLS** (`https.createServer` with `requestCert`): strongest, but changes the listener
  (TLS key/trust-store config, Fastify https wiring) and loses the plain-HTTP deployment model.
  The `presentedCertificate` seam makes it addable later.
- **Trusting a header without a secret**: rejected; any reachable client could forge identity.
- **App-side full chain validation**: left to the proxy; only an optional single-CA check is done here.

Not implemented: `mtls_endpoint_aliases`, RFC 7591 registration of the mTLS methods, store-level
cert-thumbprint binding of refresh tokens.
