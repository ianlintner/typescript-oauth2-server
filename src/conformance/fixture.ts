// Extension of the bootstrap Scenario into a full conformance fixture.
//
// The bootstrap `Scenario` (src/fixtures.ts) validates a minimal request +
// expected status. A conformance fixture adds the fields the architecture
// proposal §Stage 2 requires the harness to compare: response headers and
// response claims, plus a `setup` hook for stateful flows (e.g. obtain a
// token, then call an authenticated endpoint).

import type { ConformanceStatus } from './status.js';

export interface FixtureRequest {
  method: 'GET' | 'POST';
  path: string;
  /** Optional query parameters, appended to `path`. */
  query?: Record<string, string>;
  /** Optional form body (application/x-www-form-urlencoded). */
  body?: Record<string, string>;
  /** Optional request headers. */
  headers?: Record<string, string>;
}

export interface FixtureExpectation {
  /** Expected HTTP status code. */
  status: number;
  /** Header names to compare (values normalized for nondeterminism). */
  headers?: Record<string, string>;
  /**
   * Claim checks compared (after nondeterministic-field normalization) between
   * the two server responses.
   */
  claims?: Record<string, unknown>;
}

export interface Fixture {
  /** Stable identifier, shared with the conformance matrix entry. */
  id: string;
  /** Reference clause, e.g. `RFC 6749 §4.1`. */
  rfc: string;
  /** Conformance status this fixture is currently tracking. */
  status: ConformanceStatus;
  /** The request to issue against both servers. */
  request: FixtureRequest;
  /** The expected response contract. */
  expect: FixtureExpectation;
}

export function parseFixture(input: unknown): Fixture {
  if (typeof input !== 'object' || input === null) {
    throw new TypeError('fixture must be an object');
  }
  const value = input as Record<string, unknown>;
  if (typeof value.id !== 'string' || value.id.trim() === '') {
    throw new TypeError('fixture id must be nonempty');
  }
  if (typeof value.rfc !== 'string' || value.rfc.trim() === '') {
    throw new TypeError('RFC reference must be nonempty');
  }
  const status = value.status;
  if (status !== 'planned' && status !== 'passing' && status !== 'deferred' && status !== 'deviation') {
    throw new TypeError('fixture status must be a valid conformance status');
  }
  const request = value.request as Record<string, unknown> | undefined;
  if (typeof request !== 'object' || request === null || Array.isArray(request)) {
    throw new TypeError('request must be an object');
  }
  if (request.method !== 'GET' && request.method !== 'POST') {
    throw new TypeError('request method must be GET or POST');
  }
  if (typeof request.path !== 'string' || !request.path.startsWith('/')) {
    throw new TypeError('request path must start with /');
  }
  const expect = value.expect as Record<string, unknown> | undefined;
  if (typeof expect !== 'object' || expect === null || Array.isArray(expect)) {
    throw new TypeError('expectation must be an object');
  }
  if (!Number.isInteger(expect.status) || (expect.status as number) < 100 || (expect.status as number) > 599) {
    throw new TypeError('expected status must be an HTTP status code');
  }
  return {
    id: value.id as string,
    rfc: value.rfc as string,
    status: status as Fixture['status'],
    request: {
      method: request.method as FixtureRequest['method'],
      path: request.path as string,
      ...(request.query !== undefined ? { query: request.query as Record<string, string> } : {}),
      ...(request.body !== undefined ? { body: request.body as Record<string, string> } : {}),
      ...(request.headers !== undefined ? { headers: request.headers as Record<string, string> } : {}),
    },
    expect: {
      status: expect.status as number,
      ...(expect.headers !== undefined ? { headers: expect.headers as Record<string, string> } : {}),
      ...(expect.claims !== undefined ? { claims: expect.claims as Record<string, unknown> } : {}),
    },
  };
}
