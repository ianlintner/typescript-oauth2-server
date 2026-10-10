// Conformance matrix inventory.
//
// This is an intentionally partial seed of routes and protocol scenarios,
// not a full Rust route inventory or a completed Stage 1 deliverable.
// References below identify the intended Rust comparison points; this seed
// has not been checked against a current Rust checkout. See README.md for
// omitted route families and the work needed before claiming full coverage.
//
// The TypeScript server does not implement any endpoints yet, so every entry
// is `planned` (port pending), `deferred` (out of scope per the architecture
// proposal), or `deviation` (Rust advertises a stub that must not be copied
// silently). `passing` will appear only once a fixture exercises a real
// endpoint against the TypeScript instance and the fixture runner reports a
// match.

import type { ConformanceEntry } from './status.js';

export const MATRIX: readonly ConformanceEntry[] = [
  // ── OAuth2 core (RFC 6749) ────────────────────────────────────────────
  {
    id: 'rfc6749.authorization-endpoint',
    rfc: 'RFC 6749 §4.1',
    method: 'GET',
    path: '/oauth/authorize',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::oauth::authorize)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'rfc6749.token-endpoint',
    rfc: 'RFC 6749 §4.1.3',
    method: 'POST',
    path: '/oauth/token',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::oauth::token)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'rfc6749.pushed-authorization-request',
    rfc: 'RFC 9126 (PAR)',
    method: 'POST',
    path: '/oauth/par',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::oauth::par)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'rfc6749.authorization-code-replay',
    rfc: 'RFC 9700 §4.5 (code replay)',
    method: 'POST',
    path: '/oauth/token',
    rustReference: 'tests/rfc9700_code_replay.rs',
    tsReference: null,
    status: 'deferred',
    note: 'Live obtain/exchange/replay/introspection setup is not available; mock harness tests are not protocol coverage.',
  },
  // ── Token lifecycle (RFC 7009 / 7662) ────────────────────────────────
  {
    id: 'rfc7662.introspection',
    rfc: 'RFC 7662 §2',
    method: 'POST',
    path: '/oauth/introspect',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::token::introspect)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'rfc7009.revocation',
    rfc: 'RFC 7009 §2',
    method: 'POST',
    path: '/oauth/revoke',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::token::revoke)',
    tsReference: null,
    status: 'planned',
  },
  // ── OIDC (UserInfo, discovery, session) ──────────────────────────────
  {
    id: 'oidc.userinfo',
    rfc: 'OpenID Connect Core §5.3',
    method: 'GET',
    path: '/oauth/userinfo',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::wellknown::userinfo)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'oidc.discovery',
    rfc: 'OpenID Discovery §4 (well-known)',
    method: 'GET',
    path: '/.well-known/openid-configuration',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::wellknown::openid_configuration)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'rfc8414.as-metadata',
    rfc: 'RFC 8414 §3',
    method: 'GET',
    path: '/.well-known/oauth-authorization-server',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::wellknown::openid_configuration)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'rfc7517.jwks',
    rfc: 'RFC 7517 §5 (JWKS)',
    method: 'GET',
    path: '/.well-known/jwks.json',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::wellknown::jwks)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'oidc.check-session',
    rfc: 'OIDC Session Management 1.0 §5',
    method: 'GET',
    path: '/oauth/check_session',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::session::check_session_iframe)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'oidc.end-session',
    rfc: 'OIDC RP-Initiated Logout §2',
    method: 'GET',
    path: '/oauth/logout',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::oidc_logout::logout)',
    tsReference: null,
    status: 'planned',
  },
  // ── Device authorization grant (RFC 8628) ────────────────────────────
  {
    id: 'rfc8628.device-authorization',
    rfc: 'RFC 8628 §3.1',
    method: 'POST',
    path: '/oauth/device_authorization',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::device::device_authorization)',
    tsReference: null,
    status: 'planned',
  },
  // ── Protected resource metadata (RFC 9728) ───────────────────────────
  {
    id: 'rfc9728.protected-resource-metadata',
    rfc: 'RFC 9728 §3',
    method: 'GET',
    path: '/.well-known/oauth-protected-resource',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::wellknown::protected_resource_metadata)',
    tsReference: null,
    status: 'deferred',
    note: 'Agent/A2A OAuth extension; out of initial scope per architecture proposal.',
  },
  {
    id: 'rfc9728.per-resource-metadata',
    rfc: 'RFC 9728 §3',
    method: 'GET',
    path: '/.well-known/oauth-protected-resource/:id',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::wellknown::protected_resource_metadata_for_resource)',
    tsReference: null,
    status: 'deferred',
    note: 'Agent/A2A OAuth extension; out of initial scope per architecture proposal.',
  },
  // ── Transaction authorization challenge (draft-rosomakho) ───────────
  {
    id: 'draft-txn-challenge',
    rfc: 'draft-rosomakho-oauth-txn-challenge-00',
    method: 'POST',
    path: '/oauth/transaction_authorization',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::transaction_authorization)',
    tsReference: null,
    status: 'deferred',
    note: 'Agent/A2A transaction authorization; out of initial scope.',
  },
  // ── Dynamic client registration (RFC 7591/7592) ─────────────────────
  {
    id: 'rfc7591.dynamic-registration',
    rfc: 'RFC 7591 §3',
    method: 'POST',
    path: '/connect/register',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::client::dynamic_register)',
    tsReference: null,
    status: 'deferred',
    note: 'Dynamic registration out of initial scope per architecture proposal.',
  },
  // ── Social login (OIDC Connect via external providers) ───────────────
  {
    id: 'social.google-login',
    rfc: 'OIDC Core (external IdP)',
    method: 'GET',
    path: '/auth/login/google',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_social_login::handlers::auth::google_login)',
    tsReference: null,
    status: 'deferred',
    note: 'Social-login provider out of initial scope.',
  },
  {
    id: 'social.okta-login',
    rfc: 'OIDC Core (external IdP)',
    method: 'GET',
    path: '/auth/login/okta',
    rustReference: 'crates/oauth2-server/src/lib.rs (inline 503 stub)',
    tsReference: null,
    status: 'deviation',
    note: 'Rust returns a hardcoded 503 "not yet implemented" stub; must not be copied — defer the provider instead.',
  },
  // ── Operational endpoints ────────────────────────────────────────────
  {
    id: 'ops.health',
    rfc: 'n/a (operational)',
    method: 'GET',
    path: '/health',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::admin::health)',
    tsReference: null,
    status: 'planned',
  },
  {
    id: 'ops.ready',
    rfc: 'n/a (operational)',
    method: 'GET',
    path: '/ready',
    rustReference: 'crates/oauth2-server/src/lib.rs (oauth2_actix::handlers::admin::readiness)',
    tsReference: null,
    status: 'planned',
  },
];
