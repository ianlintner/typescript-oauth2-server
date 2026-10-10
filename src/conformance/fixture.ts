import type { ConformanceStatus } from './status.js';

export interface FixtureRequest {
  method: 'GET' | 'POST';
  path: string;
  query?: Record<string, string>;
  /** Form body (application/x-www-form-urlencoded). */
  body?: Record<string, string>;
  headers?: Record<string, string>;
}

export interface FixtureExpectation {
  status: number;
  /** Only these response headers are checked; names are case insensitive. */
  headers?: Record<string, string>;
  /** Declared top-level claims must be present and match normalized values. */
  claims?: Record<string, unknown>;
}

export interface FixtureStep {
  request: FixtureRequest;
  expect: FixtureExpectation;
  /** Bind variable names to top-level string claims in the raw response. */
  bind?: Record<string, string>;
}

export interface Fixture {
  id: string;
  rfc: string;
  status: ConformanceStatus;
  note?: string;
  /** Ordered steps executed separately for each server before the final request. */
  setup?: FixtureStep[];
  request: FixtureRequest;
  expect: FixtureExpectation;
}

function record(input: unknown, label: string): Record<string, unknown> {
  if (typeof input !== 'object' || input === null ||
      (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return input as Record<string, unknown>;
}

function strings(input: unknown, label: string): Record<string, string> {
  const value = record(input, label);
  if (Object.values(value).some(entry => typeof entry !== 'string')) {
    throw new TypeError(`${label} must be a string-valued record`);
  }
  return value as Record<string, string>;
}

function parseRequest(input: unknown, label: string): FixtureRequest {
  const request = record(input, label);
  if (request.method !== 'GET' && request.method !== 'POST') {
    throw new TypeError(`${label} method must be GET or POST`);
  }
  if (typeof request.path !== 'string' || !request.path.startsWith('/') || request.path.startsWith('//') || request.path.includes('\\')) {
    throw new TypeError(`${label} path must start with / and be local to the server`);
  }
  return {
    method: request.method,
    path: request.path,
    ...(request.query !== undefined ? { query: strings(request.query, `${label}.query`) } : {}),
    ...(request.body !== undefined ? { body: strings(request.body, `${label}.body`) } : {}),
    ...(request.headers !== undefined ? { headers: strings(request.headers, `${label}.headers`) } : {}),
  };
}

function parseExpectation(input: unknown, label: string): FixtureExpectation {
  const expect = record(input, label);
  if (!Number.isInteger(expect.status) || (expect.status as number) < 100 || (expect.status as number) > 599) {
    throw new TypeError(`${label}: expected status must be an HTTP status code`);
  }
  return {
    status: expect.status as number,
    ...(expect.headers !== undefined ? { headers: strings(expect.headers, `${label}.headers`) } : {}),
    ...(expect.claims !== undefined ? { claims: record(expect.claims, `${label}.claims`) } : {}),
  };
}

export function parseFixture(input: unknown): Fixture {
  const value = record(input, 'fixture');
  if (typeof value.id !== 'string' || value.id.trim() === '') throw new TypeError('fixture id must be nonempty');
  if (typeof value.rfc !== 'string' || value.rfc.trim() === '') throw new TypeError('RFC reference must be nonempty');
  const status = value.status;
  if (status !== 'planned' && status !== 'passing' && status !== 'deferred' && status !== 'deviation') {
    throw new TypeError('fixture status must be a valid conformance status');
  }
  if (value.note !== undefined && (typeof value.note !== 'string' || value.note.trim() === '')) {
    throw new TypeError('fixture note must be nonempty');
  }
  let setup: FixtureStep[] | undefined;
  if (value.setup !== undefined) {
    if (!Array.isArray(value.setup)) throw new TypeError('setup must be an array');
    setup = value.setup.map((input, index) => {
      const label = `setup[${index}]`;
      const step = record(input, label);
      const bind = step.bind === undefined ? undefined : strings(step.bind, `${label}.bind`);
      if (bind && Object.entries(bind).some(([name, claim]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || claim === '')) {
        throw new TypeError(`${label}.bind requires variable names and nonempty claim names`);
      }
      return {
        request: parseRequest(step.request, `${label}.request`),
        expect: parseExpectation(step.expect, `${label}.expect`),
        ...(bind ? { bind } : {}),
      };
    });
  }
  return {
    id: value.id, rfc: value.rfc, status,
    ...(value.note !== undefined ? { note: value.note as string } : {}),
    ...(setup !== undefined ? { setup } : {}),
    request: parseRequest(value.request, 'request'),
    expect: parseExpectation(value.expect, 'expect'),
  };
}
