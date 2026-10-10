# TypeScript OAuth2 Server

A TypeScript port of the [Rust OAuth2 server](https://github.com/ianlintner/rust-oauth2-server), developed against shared protocol and conformance expectations.

This repository is in early implementation. It is **not** an operational or spec-compliant authorization server yet. The architecture proposal has been accepted, but the conformance matrix and protocol behavior remain staged work.

The Rust implementation is the behavioral reference; differences and intentionally deferred features will be recorded explicitly as the port is built.

The conformance matrix in `src/conformance/matrix.ts` lists every route-method registered by the Rust reference (94 entries; commit and route table pinned in `src/conformance/rust-routes.ts`), each with a status, milestone and Rust references. It is a route inventory, not evidence of protocol parity: every entry is `planned`, `deferred` or `deviation` until a fixture exercises a real TypeScript endpoint. Rust test files listed per route only mention the path. Admin, eventing, Swagger and static mounts are recorded as deferred/unscheduled.

The harness checks each server against `fixture.expect` (status, declared response headers, and declared top-level claims), then compares those selected contract fields between servers. It does **not** compare entire normalized response bodies during fixture execution: incidental headers and undeclared claims are ignored. Header names are case insensitive. Only named token and timestamp fields with valid primitive types are normalized. Client-controlled state/nonce, OAuth errors, malformed token/time values, and all other strings remain exact. Redirects are not followed automatically, and interpolated paths cannot leave either configured server origin.

Fixtures can supply an ordered `setup` array. Each step has `request`, `expect`, and optional `bind`, mapping variable names to top-level string claims from its raw JSON response, for example `"bind": { "code": "code" }`. Subsequent request paths, query values, form values, and header values can reference `{{code}}`. Bindings are isolated per server and per run; all setup contracts must pass before dependent steps execute. Missing bindings or malformed fixtures fail explicitly. This minimal mechanism does not yet capture redirect query parameters or manage login sessions/cookies.

The four live PKCE, redirect, and code-replay fixtures are deferred until real authorization/client setup exists. The CLI reports them as DEFERRED and does not dispatch their requests. Replay harness tests use deterministic mocks to obtain a code, exchange it successfully, replay that same code, and check revocation of the prior token through introspection. These tests validate the harness only. Fixture/matrix statuses stay planned or deferred (with the existing documented Rust stub deviation); a matching run does not promote a status or establish protocol conformance.
