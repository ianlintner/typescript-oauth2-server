import { normalizePayload } from './normalize.js';
import type { FixtureExpectation, FixtureRequest, FixtureStep } from './fixture.js';

export interface ResponseSnapshot {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface Diff {
  field: string;
  rust: unknown;
  ts: unknown;
  expected?: unknown;
}

export interface ComparisonResult {
  fixtureId: string;
  match: boolean;
  diffs: Diff[];
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((entry, i) => deepEqual(entry, b[i]));
  }
  if (a !== null && b !== null && typeof a === 'object' && typeof b === 'object') {
    const ak = Object.keys(a), bk = Object.keys(b);
    return ak.length === bk.length && ak.every(k => Object.hasOwn(b, k) && deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
  }
  return false;
}

function claims(body: unknown): Record<string, unknown> {
  return body !== null && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : {};
}

function headers(input: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(input).map(([key, value]) => [key.toLowerCase(), value]));
}

/** Compare normalized bodies and selected headers, then enforce both contracts. */
export function compareResponses(input: {
  fixtureId: string;
  rust: ResponseSnapshot;
  ts: ResponseSnapshot;
  expect?: FixtureExpectation;
}): ComparisonResult {
  const { fixtureId, rust, ts, expect } = input;
  const diffs: Diff[] = [];
  if (rust.status !== ts.status) diffs.push({ field: 'status', rust: rust.status, ts: ts.status });
  const rb = normalizePayload(rust.body), tb = normalizePayload(ts.body);
  const rc = claims(rb), tc = claims(tb);
  // A fixture contract selects the claims that matter. The low-level comparator
  // retains full-body differential behavior when no contract is supplied.
  if (!expect) {
    if (rb !== null && tb !== null && typeof rb === 'object' && typeof tb === 'object' && !Array.isArray(rb) && !Array.isArray(tb)) {
      for (const key of [...new Set([...Object.keys(rc), ...Object.keys(tc)])].sort()) {
        if (!deepEqual(rc[key], tc[key]) || Object.hasOwn(rc, key) !== Object.hasOwn(tc, key)) {
          diffs.push({ field: `claim[${key}]`, rust: rc[key], ts: tc[key] });
        }
      }
    } else if (!deepEqual(rb, tb)) {
      diffs.push({ field: 'body', rust: rb, ts: tb });
    }
  }
  const rh = headers(rust.headers), th = headers(ts.headers);
  // Low-level comparisons without a contract retain explicit snapshot headers.
  // Fixture execution always supplies a contract, so incidental headers are ignored.
  const selected = expect ? Object.keys(headers(expect.headers ?? {})) : [...new Set([...Object.keys(rh), ...Object.keys(th)])];
  for (const key of selected.sort()) {
    if (rh[key] !== th[key]) diffs.push({ field: `header[${key}]`, rust: rh[key], ts: th[key] });
  }
  if (expect) {
    if (rust.status !== expect.status || ts.status !== expect.status) {
      diffs.push({ field: 'expect.status', rust: rust.status, ts: ts.status, expected: expect.status });
    }
    for (const [key, value] of Object.entries(headers(expect.headers ?? {})).sort()) {
      if (rh[key] !== value || th[key] !== value) diffs.push({ field: `expect.header[${key}]`, rust: rh[key], ts: th[key], expected: value });
    }
    for (const [key, value] of Object.entries(claims(normalizePayload(expect.claims ?? {}))).sort(([a], [b]) => a.localeCompare(b))) {
      if (!Object.hasOwn(rc, key) || !Object.hasOwn(tc, key) || !deepEqual(rc[key], value) || !deepEqual(tc[key], value)) {
        diffs.push({ field: `expect.claim[${key}]`, rust: rc[key], ts: tc[key], expected: value });
      }
    }
  }
  return { fixtureId, match: diffs.length === 0, diffs };
}

const LOCATION_QUERY_PREFIX = 'location.query.';

/**
 * Resolve a bind source against a raw response: either a top-level string body
 * claim, or `location.query.<name>` read from the redirect `Location` header.
 * Returns undefined unless exactly one string value exists (a repeated or
 * missing redirect parameter is never silently bound).
 */
export function bindSource(snapshot: ResponseSnapshot, source: string): string | undefined {
  if (source.startsWith(LOCATION_QUERY_PREFIX)) {
    const name = source.slice(LOCATION_QUERY_PREFIX.length);
    const location = headers(snapshot.headers).location;
    if (name === '' || location === undefined) return undefined;
    let url: URL;
    try { url = new URL(location, 'http://redirect.invalid'); } catch { return undefined; }
    const values = url.searchParams.getAll(name);
    return values.length === 1 && values[0] !== '' ? values[0] : undefined;
  }
  const body = claims(snapshot.body);
  const value = body[source];
  return Object.hasOwn(body, source) && typeof value === 'string' ? value : undefined;
}

/** Bind raw string claims independently per server. Never bind normalized tokens. */
export async function runFixture(input: FixtureRequest & {
  fixtureId: string;
  expect: FixtureExpectation;
  setup?: FixtureStep[] | undefined;
  rustBaseUrl: string;
  tsBaseUrl: string;
  fetchImpl?: typeof fetch;
}): Promise<ComparisonResult> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const variables = [new Map<string, string>(), new Map<string, string>()];
  const bases = [input.rustBaseUrl, input.tsBaseUrl];
  const dispatch = async (base: string, vars: Map<string, string>, request: FixtureRequest): Promise<ResponseSnapshot> => {
    const resolve = (value: string): string => value.replace(/\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}/g, (_match, name: string) => {
      const bound = vars.get(name);
      if (bound === undefined) throw new Error(`unbound variable ${name} for ${base}`);
      return bound;
    });
    const resolveRecord = (record: Record<string, string>): Record<string, string> => Object.fromEntries(Object.entries(record).map(([key, value]) => [key, resolve(value)]));
    const root = new URL(base);
    const url = new URL(resolve(request.path), root);
    if (url.origin !== root.origin) {
      throw new Error(`fixture request escaped configured server origin ${root.origin}`);
    }
    for (const [key, value] of Object.entries(resolveRecord(request.query ?? {}))) url.searchParams.set(key, value);
    const init: RequestInit = { method: request.method, redirect: 'manual', headers: resolveRecord(request.headers ?? {}) };
    if (request.body !== undefined) {
      const requestHeaders = new Headers(init.headers);
      requestHeaders.set('content-type', 'application/x-www-form-urlencoded');
      init.headers = requestHeaders;
      init.body = new URLSearchParams(resolveRecord(request.body)).toString();
    }
    const response = await fetchImpl(url.toString(), init);
    const text = await response.text();
    let body: unknown = {};
    if (text !== '') {
      try { body = JSON.parse(text); } catch { body = text; }
    }
    return { status: response.status, headers: Object.fromEntries(response.headers), body };
  };
  const steps: FixtureStep[] = [...(input.setup ?? []), { request: input, expect: input.expect }];
  for (const [index, step] of steps.entries()) {
    const snapshots = await Promise.all(bases.map((base, i) => dispatch(base, variables[i]!, step.request)));
    const result = compareResponses({ fixtureId: input.fixtureId, rust: snapshots[0]!, ts: snapshots[1]!, expect: step.expect });
    if (!result.match) {
      if (index < steps.length - 1) result.diffs = result.diffs.map(diff => ({ ...diff, field: `setup[${index}].${diff.field}` }));
      return result;
    }
    for (const [name, claim] of Object.entries(step.bind ?? {})) {
      for (const [i, snapshot] of snapshots.entries()) {
        const value = bindSource(snapshot, claim);
        if (value === undefined) throw new Error(`setup[${index}] binding ${name}: ${claim} must be a string claim or single location.query value for ${bases[i]}`);
        variables[i]!.set(name, value);
      }
    }
  }
  return { fixtureId: input.fixtureId, match: true, diffs: [] };
}
