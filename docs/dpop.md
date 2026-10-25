# DPoP (RFC 9449) — v0.5 slice 1

Scope of this slice: proof validation at the token endpoint and the UserInfo resource, `cnf.jkt` binding, storage-backed `jti` replay protection, discovery and introspection metadata. Server-provided nonces (RFC 9449 §8/§9), RFC 8705 mTLS and RFC 9700 rate limiting are separate follow-up slices; `sender-constrained` is therefore **not** yet claimed in `conformance.yaml`.

## Behaviour

- A `DPoP` header on `/oauth/token` (all grants) is validated and the issued access token carries `cnf: {jkt}` with `token_type: DPoP`. No header keeps issuing plain Bearer tokens. A present-but-invalid proof is rejected with `400 invalid_dpop_proof`; for `authorization_code` the proof is checked before the code is consumed.
- Proof checks: `typ=dpop+jwt`, `alg=ES256` only (no symmetric/`none`), public EC P-256 `jwk` in the header (any private parameter rejected), signature verifies under that `jwk`, `jti` present, `htm` equals the method, `htu` equals the issuer-derived endpoint URL (query/fragment ignored; never built from `Host`), `iat` within `[now-300s, now+60s]`, and for resources `ath` = base64url SHA-256 of the access token. A single `DPoP` header is required.
- Replay: `jti` (scoped by key thumbprint) is recorded through `Store.consumeDpopJti` (`dpop_proofs` table, primary key = atomic insert). Because the decision is the database's, replay is rejected across processes sharing the database and across restarts; entries expire with the acceptance window. The `jti` is only consumed after all other checks pass.
- Refresh tokens issued against a proof are bound to its key (`refresh_tokens.dpop_jkt`); refreshing needs a proof from the same key, and a mismatch is rejected before the token is consumed.
- `/oauth/userinfo`: a bound token requires the `DPoP` authorization scheme and a proof whose key thumbprint equals `cnf.jkt`; Bearer use of a bound token, or the DPoP scheme on an unbound token, is `401 invalid_token`.
- Introspection reports `token_type: DPoP` and `cnf` for bound tokens; discovery advertises `dpop_signing_alg_values_supported`.

## Not in this slice

DPoP on the device grant and PAR (`dpop_jkt`) paths (a proof sent there is ignored and a Bearer token is issued), server nonces and `use_dpop_nonce`, client-registered `dpop_bound_access_tokens` / required-DPoP policy, non-ES256 algorithms, RFC 8705, RFC 9700 rate limiting and CSRF/redirect items.
