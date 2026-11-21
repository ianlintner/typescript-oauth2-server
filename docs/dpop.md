# DPoP (RFC 9449) — v0.5 slice 1

Scope of this slice: proof validation at the token endpoint and the UserInfo resource, `cnf.jkt` binding, storage-backed `jti` replay protection, discovery and introspection metadata. RFC 8705 mTLS and RFC 9700 rate limiting are separate follow-up slices; `sender-constrained` is therefore **not** yet claimed in `conformance.yaml`. Slice 2 (server nonces) is documented below.

## Behaviour

- A `DPoP` header on `/oauth/token` (all grants) is validated and the issued access token carries `cnf: {jkt}` with `token_type: DPoP`. No header keeps issuing plain Bearer tokens. A present-but-invalid proof is rejected with `400 invalid_dpop_proof`; for `authorization_code` the proof is checked before the code is consumed.
- Proof checks: `typ=dpop+jwt`, `alg=ES256` only (no symmetric/`none`), public EC P-256 `jwk` in the header (any private parameter rejected), signature verifies under that `jwk`, `jti` present, `htm` equals the method, `htu` equals the issuer-derived endpoint URL (query/fragment ignored; never built from `Host`), `iat` within `[now-300s, now+60s]`, and for resources `ath` = base64url SHA-256 of the access token. A single `DPoP` header is required.
- Replay: `jti` (scoped by key thumbprint) is recorded through `Store.consumeDpopJti` (`dpop_proofs` table, primary key = atomic insert). Because the decision is the database's, replay is rejected across processes sharing the database and across restarts; entries expire with the acceptance window. The `jti` is only consumed after all other checks pass.
- Refresh tokens issued against a proof are bound to its key (`refresh_tokens.dpop_jkt`); refreshing needs a proof from the same key, and a mismatch is rejected before the token is consumed.
- `/oauth/userinfo`: a bound token requires the `DPoP` authorization scheme and a proof whose key thumbprint equals `cnf.jkt`; Bearer use of a bound token, or the DPoP scheme on an unbound token, is `401 invalid_token`.
- Introspection reports `token_type: DPoP` and `cnf` for bound tokens; discovery advertises `dpop_signing_alg_values_supported`.

## Server-provided nonces (RFC 9449 §8/§9) — v0.5 slice 2

Opt-in: `OAUTH2_DPOP_NONCE=required` (default `off`, slice-1 behaviour unchanged). Library users pass `dpopNonce: { key, required }` to `buildServer`.

- **Format (stateless HMAC).** `nonce = <windowStart>.<base64url HMAC-SHA256(key, "dpop-nonce:v1:" + windowStart)>`, where `windowStart` is the current time floored to a 60 s rotation window and `key` is derived from `OAUTH2_SESSION_SECRET` (`HMAC(secret, "dpop-nonce-key:v1")`, domain-separated). Nothing is stored: every process sharing the secret issues and accepts the same nonces, so it works across processes and restarts with no Store/port change.
- **Validation.** Must match the exact shape, `windowStart` aligned to the window and not in the future, HMAC equal (constant-time), and `now < windowStart + 60 s + 60 s grace`. So a nonce lives 60-120 s and the previous window stays valid for 60 s after rotation, letting in-flight requests finish. Forged, tampered, other-deployment, malformed, future and stale nonces all fail.
- **Flow.** In required mode a proof with a missing or invalid `nonce` claim gets `400 use_dpop_nonce` with a fresh `DPoP-Nonce` header at `/oauth/token`, and `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` plus `DPoP-Nonce` at `/oauth/userinfo`. Successful DPoP responses also carry the current `DPoP-Nonce` (§8.2). Non-DPoP requests are unaffected.
- **Ordering.** The nonce is checked after the signature/claims and before the `jti` is consumed, so a `use_dpop_nonce` rejection does not burn the proof's `jti`; a malformed proof gets `invalid_dpop_proof` and no nonce. In non-required library mode a *presented* nonce is still validated.
- **Replay** remains the job of the `jti` store; a nonce proves recency against this server, not single use.

### Design alternatives considered

- *Stored nonces* (random value per issue, looked up in `Store`): exact single-use/revocation semantics, but needs a new Store method plus a table/document in all of SQLite, Postgres and Mongo, and a write per challenge, for little benefit since `jti` already prevents replay. Rejected as the larger, non-fail-closed-by-default surface.
- *Single process-local secret*: simpler but breaks multi-process and restarts; rejected by the project's "no process-local security state" rule.
- Key rotation: nonces are bound to `OAUTH2_SESSION_SECRET`; rotating it invalidates outstanding nonces, which clients recover from via the `use_dpop_nonce` retry.

## Not in this slice

DPoP on the device grant and PAR (`dpop_jkt`) paths (a proof sent there is ignored and a Bearer token is issued), client-registered `dpop_bound_access_tokens` / required-DPoP policy, non-ES256 algorithms, RFC 8705, RFC 9700 rate limiting and CSRF/redirect items.
