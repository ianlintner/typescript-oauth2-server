# TypeScript OAuth2 server — architecture proposal

Status: proposed, not implemented. Reference: `ianlintner/rust-oauth2-server` on `main`. The Rust server is the behavioral reference, not proof that every advertised extension is conformant. Verify each item against the current Rust tests, route behavior and RFC text before marking it supported.

## Goal and boundaries

Build a TypeScript/Node.js authorization server that implements the same protocol behavior and security invariants as the Rust server in staged, testable slices. Keep endpoint names and wire behavior compatible where intentional; record explicit deviations and deferred features in a conformance matrix. Do not copy Rust internal concurrency or infrastructure machinery literally. No release or claim of spec compliance until a published fixture/test matrix passes for the implemented slice.

Out of initial scope: UI parity, Kubernetes, Kafka/RabbitMQ, MongoDB, distributed tracing backend, social-login providers, the Rust Phase 7 agent/A2A extensions, dynamic registration, DPoP and mTLS. These are candidates for later parity waves, not permanently excluded; architecture must leave explicit extension points without implementing them prematurely.

## Proposed stack (for architecture approval)

- Node.js LTS + strict TypeScript, ESM, `pnpm` lockfile. Fastify for HTTP route boundaries and request/response validation; no hidden OAuth behavior from a framework plugin.
- `jose` for JWS/JWK/JWT and `@noble`/Node crypto only where a standard library primitive is appropriate; never implement signature or KDF algorithms ourselves. `zod` or JSON Schema for typed boundary validation, with duplicate form/query parameters checked *before* coercion.
- Domain/application layer independent of Fastify and SQL: typed commands for authorization, token issuance, introspection, revocation, clients, users, sessions and key sets. Inject clock, randomness, signer/verifier and storage ports for deterministic tests. Use discriminated OAuth error types mapped once to RFC status, headers and JSON.
- SQLite adapter first for tests/local operation, PostgreSQL adapter after the storage contract is executable. Explicit transactions and unique constraints for one-time authorization-code consumption, refresh-token rotation/replay family revocation and DPoP/nonce stores in later waves. Avoid process-local state for security decisions in production mode.
- Config validation at startup; fail closed for missing signing/session secrets, invalid issuer or insecure production redirect/cookie settings. Persist/manage signing keys rather than rotating on every restart. Secrets stay out of logs, responses and repository.

## Port map and stages

1. **Architecture and contracts:** extract current Rust routes, storage traits and tests (`crates/oauth2-{core,ports,actix,server,storage-*}`, `tests/compliance_*`, `tests/rfc9700_*`, `tests/security_http.rs`) into a versioned endpoint/conformance matrix. Decide runtime/framework, key persistence, transaction and tenancy boundaries. Owner reviews this proposal before implementation.
2. **Runnable skeleton and contract harness:** health endpoint, typed config/errors, CI (typecheck, lint, tests, dependency audit), deterministic clock/random fixtures, HTTP integration harness. A fixture must be runnable against Rust and TS with normalization only for nondeterministic token/key fields; failure must identify method, path, status, header or claim mismatch.
3. **Core authorization code + PKCE:** client registration fixture, exact redirect URI, S256 PKCE, state/issuer response, one-time code redemption, confidential/public client authentication, no implicit/ROPC. Tests map RFC 6749/7636/9207 and RFC 9700 security cases (duplicates, wrong redirect, replay, wrong verifier, missing/weak client auth).
4. **Token lifecycle and OIDC baseline:** client credentials, JWT/JWKS and key IDs, refresh rotation/family replay, revocation/introspection, OIDC discovery/ID token/nonce/UserInfo. Tests map RFC 6750, 7009, 7662, 8414, 9068 and OIDC Core, with explicit cross-process persistence checks.
5. **Storage parity and advanced waves:** PostgreSQL contract parity; then device grant, PAR, dynamic registration, DPoP, mTLS, social providers, and agent/A2A features in separate scoped milestones. Each wave is accepted only with negative security cases and protocol fixtures, not endpoint stubs.

## Conformance matrix format

Each scenario should record: RFC clause, Rust test/route reference, request fixture, expected status/headers/body semantics, storage side effect, TS test, and status (`planned`, `passing`, `deferred`, `deviation`). Start with `tests/compliance_rfc6749.rs`, `compliance_rfc7636.rs`, `rfc9700_code_replay.rs`, `security_http.rs`; extend by RFC wave. Avoid snapshotting opaque secrets; use decoded claims and invariant assertions. Run a common black-box suite against isolated Rust and TS instances without shared databases.

## Architecture decisions for owner

1. Confirm Fastify + Node LTS + strict TS and whether the public package/server should be monorepo or one package initially (recommend one package with internal modules).
2. Confirm SQLite first and PostgreSQL second; defer MongoDB until core parity. Define deployment key storage/persistence model before JWT implementation.
3. Confirm the first milestone is authorization-code + S256 PKCE plus a reusable cross-language conformance harness; keep OIDC and advanced extensions as later, explicitly nonconformant until tested.
4. Confirm compatibility target: match Rust's wire routes by default, but permit documented corrections where Rust behavior diverges from an RFC. Never silently copy an unsafe deviation.

## Exit criteria for the first implementation wave

`pnpm install --frozen-lockfile`, typecheck, lint and tests pass; a local Fastify process boots with validated config; the cross-language harness runs a representative positive and negative authorization-code/PKCE set against both servers; code-replay and redirect/PKCE failure paths use atomic persistence; no secrets in fixtures or logs. Record what is *not* yet implemented in README, without claiming full server parity.
