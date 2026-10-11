# TypeScript OAuth2 Server

A TypeScript port of the [Rust OAuth2 server](https://github.com/ianlintner/rust-oauth2-server), developed against shared protocol and conformance expectations.

This repository is in early implementation. It is **not** an operational or spec-compliant authorization server yet. The architecture proposal has been accepted, but the conformance matrix and protocol behavior remain staged work.

The Rust implementation is the behavioral reference; differences and intentionally deferred features will be recorded explicitly as the port is built.

The conformance matrix in `src/conformance/matrix.ts` lists every route-method registered by the Rust reference (94 entries; commit and route table pinned in `src/conformance/rust-routes.ts`), each with a status, milestone and Rust references. It is a route inventory, not evidence of protocol parity: every entry is `planned`, `deferred` or `deviation` until a fixture exercises a real TypeScript endpoint. Rust test files listed per route only mention the path. Admin, eventing, Swagger and static mounts are recorded as deferred/unscheduled.

The harness checks each server against `fixture.expect` (status, declared response headers, and declared top-level claims), then compares those selected contract fields between servers. It does **not** compare entire normalized response bodies during fixture execution: incidental headers and undeclared claims are ignored. Header names are case insensitive. Only named token and timestamp fields with valid primitive types are normalized. Client-controlled state/nonce, OAuth errors, malformed token/time values, and all other strings remain exact. Redirects are not followed automatically, and interpolated paths cannot leave either configured server origin.

Fixtures can supply an ordered `setup` array. Each step has `request`, `expect`, and optional `bind`, mapping variable names to top-level string claims from its raw JSON response, for example `"bind": { "code": "code" }`. Subsequent request paths, query values, form values, and header values can reference `{{code}}`. Bindings are isolated per server and per run; all setup contracts must pass before dependent steps execute. Missing bindings or malformed fixtures fail explicitly. This minimal mechanism does not yet capture redirect query parameters or manage login sessions/cookies.

The four live PKCE, redirect, and code-replay fixtures are deferred until real authorization/client setup exists. The CLI reports them as DEFERRED and does not dispatch their requests. Replay harness tests use deterministic mocks to obtain a code, exchange it successfully, replay that same code, and check revocation of the prior token through introspection. These tests validate the harness only. Fixture/matrix statuses stay planned or deferred (with the existing documented Rust stub deviation); a matching run does not promote a status or establish protocol conformance.

## Server skeleton and authorization-code/PKCE slice

`src/main.ts` boots a Fastify shell serving `GET /health` (503 when storage is unreachable). `src/oauth.ts` adds `GET /oauth/authorize` and `POST /oauth/token` for the authorization-code grant only: S256 PKCE (required), exact redirect URI match, `state` and `iss` on redirect responses, duplicate-parameter rejection, atomic one-time code redemption, and confidential (scrypt-hashed secret, Basic or form) plus public client authentication. No implicit or password grant, refresh, introspection, revocation, JWKS or OIDC endpoint exists. Resource-owner login/consent is out of scope: `authenticate` is an injected hook and the authorize endpoint fails closed with `access_denied` without it, so this is not a deployable authorization server.

Behavior is verified by in-process tests (`test/oauth-flow.test.ts`, `test/client-auth.test.ts`). The cross-language fixtures above remain deferred because the harness cannot yet bind a code from a redirect `Location`; matrix statuses are unchanged.

- `src/config.ts`: environment validation that fails closed. `OAUTH2_ENV`, `OAUTH2_ISSUER`, `OAUTH2_SESSION_SECRET` (32+ chars), `OAUTH2_SIGNING_KEY_PEM` (PKCS#8 ES256) and `OAUTH2_SIGNING_KEY_ID` are required. Production additionally requires an https issuer, a persistent `OAUTH2_DATABASE_PATH`, and a non-placeholder secret. Error messages never echo secret values.
- `src/errors.ts`: typed OAuth errors mapped once to RFC 6749 status, headers and JSON; server errors are opaque.
- `src/ports.ts`: clock, random, signer and store interfaces. `src/sqlite-store.ts` is the SQLite adapter (`node:sqlite`) with serialized transactions and atomic one-time authorization-code consumption; `src/signer.ts` is the `jose` ES256 signer.

Run with `pnpm start` after exporting the variables above. Signing keys are supplied by the operator and are not generated or rotated by the server.
