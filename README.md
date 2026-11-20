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

- `src/config.ts`: environment validation that fails closed. `OAUTH2_ENV`, `OAUTH2_ISSUER`, `OAUTH2_SESSION_SECRET` (32+ chars), `OAUTH2_SIGNING_KEY_PEM` (PKCS#8 ES256) and `OAUTH2_SIGNING_KEY_ID` are required. Production additionally requires an https issuer, a persistent `OAUTH2_DATABASE_PATH`, and a non-placeholder secret. Error messages never echo secret values. `OAUTH2_ADMIN_TOKEN` is optional; when unset the `/admin/trusted-issuers` routes are not registered. When set, in every environment it must be at least 32 characters and must not look like a placeholder or well-known value (for example one starting with `admin`, `token`, `test` or `dev`). It is a single shared secret protecting trusted-issuer registration. Outside production, setting it with a non-loopback `OAUTH2_HOST` is refused unless `OAUTH2_ALLOW_ADMIN_ON_NON_LOOPBACK=1` (only behind a trusted proxy).
- `src/errors.ts`: typed OAuth errors mapped once to RFC 6749 status, headers and JSON; server errors are opaque.
- `src/ports.ts`: clock, random, signer and store interfaces. `src/sqlite-store.ts` is the SQLite adapter (`node:sqlite`) with serialized transactions and atomic one-time authorization-code consumption; `src/signer.ts` is the `jose` ES256 signer.

Run with `pnpm start` after exporting the variables above. Signing keys are supplied by the operator and are not generated or rotated by the server.

### Dynamic client registration policy

Embedders that pass `dynamicRegistration: true` to `buildServer` can also pass a `registrationPolicy`. Every value a registrant supplies must appear on the matching allow-list, otherwise `POST` and `PUT /connect/register` return `invalid_client_metadata` or `invalid_redirect_uri`:

- `allowedGrantTypes` (default `authorization_code`, `refresh_token`). `client_credentials`, the device grant and `urn:ietf:params:oauth:grant-type:jwt-bearer` are opt-in.
- `allowedScopes` (default `openid`, `profile`, `email`).
- `allowedRedirectSchemes` (default `https`). Plain `http` is accepted only for `127.0.0.1` and `[::1]`; custom app schemes are opt-in; credentials in the URI are always refused.
- `initialAccessToken`: when set, `POST /connect/register` requires it as a Bearer token. Reading, updating and deleting a client continue to use that client's registration access token.

Embedders that enabled registration without a policy now get these defaults; list any previously accepted grant types, scopes or schemes explicitly to keep them.

## Token exchange (RFC 8693)

`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` is advertised in discovery and available to confidential clients registered with that grant type.

- **Subject/actor tokens.** `subject_token_type` and `actor_token_type` may be `urn:ietf:params:oauth:token-type:access_token` or `...:jwt`. Only access tokens this server issued are accepted, and each must still be on record, unrevoked and unexpired. Refresh tokens, ID tokens, SAML and foreign-issuer tokens are `invalid_request`. A subject bound to a DPoP key (`cnf.jkt`) can only be exchanged with a matching proof at the endpoint.
- **Result.** The issued token belongs to the exchanging client, keeps the subject's `sub`, and is narrowed in scope (requested ⊆ subject ⊆ client registration), audience (`resource`/`audience` must be within the subject token's audience; an audience-unrestricted subject accepts no target, since no resource registry exists in this port: `invalid_target`) and lifetime (never beyond the subject's `exp`). `issued_token_type` echoes `requested_token_type` (default access_token). `authorization_details` is not supported.
- **Delegation.** An `actor_token` (which must have been issued to the exchanging client) is recorded as the `act` claim (`{sub, iss, sub_profile}`, nested over any existing chain) only when the subject token's `may_act` names that actor, or the subject's client lists the exchanging client in its `allowedActors` registration. Without an actor, exchanging a token issued to another client requires that client's `allowedActors`. Chain depth is limited by `OAUTH2_MAX_DELEGATION_DEPTH` (default 4, range 1-32).
- **Errors.** Invalid or policy-unacceptable subject/actor tokens, depth overruns and missing parameters are `invalid_request` (RFC 8693 §2.2.2); scope overruns are `invalid_scope`; unfulfillable targets are `invalid_target`.
- **`allowedActors`** is operator-provisioned (conformance seed key `allowed_actors`, or the store directly); dynamic registration never sets it.

## Remote key retrieval

Trusted-issuer `jwks_uri` documents are fetched only from public addresses. A literal non-public address is rejected at registration, and every hostname is resolved at fetch time and refused if any resolved address is loopback, private, link-local, carrier-grade NAT, multicast, reserved or unspecified. Forced refreshes (used when a key rotates) are limited to one per URI every 10 seconds; within that window the cached document is used. Tests that serve keys from a local listener use the `setJwksNetGuard` test seam (`src/jwks.ts`); it is not configurable from the environment.
