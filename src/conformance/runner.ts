// Executable black-box conformance runner.
//
// Replays a fixture against an isolated Rust instance and an isolated
// TypeScript instance, then compares the response contract (status, selected
// headers, claims) after normalizing nondeterministic token/time fields. A
// mismatch reports exactly which field diverged so the author knows what to
// fix — no opaque snapshot equality.

import { normalizePayload } from './normalize.js';

/** A minimal, normalized snapshot of one server's response to a fixture. */
export interface ResponseSnapshot {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

/** A single field divergence between the Rust and TypeScript responses. */
export interface Diff {
  field: string;
  rust: unknown;
  ts: unknown;
}

export interface ComparisonResult {
  fixtureId: string;
  match: boolean;
  diffs: Diff[];
}

/**
 * Compare two already-normalized response snapshots.
 *
 * Returns `match: true` and an empty `diffs` when the method/path/status and
 * every compared header and claim agree. Nondeterministic fields are
 * normalized (see normalize.ts) before this function is called.
 *
 * `diffs` is emitted in a deterministic order: status first, then claims
 * (shallow, sorted by key), then headers (sorted by lowercased name). This
 * ordering is load-bearing for the runner test suite.
 */
export function compareResponses(input: {
  fixtureId: string;
  rust: ResponseSnapshot;
  ts: ResponseSnapshot;
}): ComparisonResult {
  const { fixtureId, rust, ts } = input;
  const diffs: Diff[] = [];

  if (rust.status !== ts.status) {
    diffs.push({ field: 'status', rust: rust.status, ts: ts.status });
  }

  // Claims: shallow compare with a stable sort so results are deterministic.
  const rustBody = (rust.body ?? {}) as Record<string, unknown>;
  const tsBody = (ts.body ?? {}) as Record<string, unknown>;
  const claimKeys = Array.from(new Set([...Object.keys(rustBody), ...Object.keys(tsBody)])).sort();
  for (const key of claimKeys) {
    const rv = rustBody[key];
    const tv = tsBody[key];
    const rvNorm = normalizePayload(rv);
    const tvNorm = normalizePayload(tv);
    if (!deepEqual(rvNorm, tvNorm)) {
      diffs.push({ field: `claim[${key}]`, rust: rv, ts: tv });
    }
  }

  // Headers: compare a stable, sorted view.
  const headerKeys = Array.from(
    new Set([...Object.keys(rust.headers), ...Object.keys(ts.headers)]),
  ).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  for (const key of headerKeys) {
    const rv = rust.headers[key];
    const tv = ts.headers[key];
    if (rv !== tv) {
      diffs.push({ field: `header[${key}]`, rust: rv, ts: tv });
    }
  }

  return { fixtureId, match: diffs.length === 0, diffs };
}

/** Structural equality that treats numeric 1 and string '1' as distinct. */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((entry, i) => deepEqual(entry, b[i]));
  }
  if (a !== null && b !== null && typeof a === 'object' && typeof b === 'object') {
    const ak = Object.keys(a as Record<string, unknown>);
    const bk = Object.keys(b as Record<string, unknown>);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
  }
  return false;
}

/**
 * Replay a fixture against two live base URLs and return the comparison.
 *
 * `fetch` is injected so tests can substitute a deterministic fake without
 * spinning up servers; production passes the global `fetch`. Normalization is
 * applied to the parsed JSON body (when the response has one) before
 * comparison; headers are compared as lowercased names under the hood in
 * `compareResponses`.
 */
export async function runFixture(input: {
  fixtureId: string;
  method: 'GET' | 'POST';
  path: string;
  query?: Record<string, string>;
  body?: Record<string, string>;
  headers?: Record<string, string>;
  rustBaseUrl: string;
  tsBaseUrl: string;
  fetchImpl?: typeof fetch;
}): Promise<ComparisonResult> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const urlFor = (base: string): string => {
    const url = new URL(input.path, base);
    if (input.query) {
      for (const [key, value] of Object.entries(input.query)) {
        url.searchParams.set(key, value);
      }
    }
    return url.toString();
  };

  const dispatch = async (base: string): Promise<ResponseSnapshot> => {
    const init: RequestInit = { method: input.method };
    if (input.headers !== undefined) {
      init.headers = input.headers;
    }
    if (input.body !== undefined) {
      init.headers = {
        ...(input.headers ?? {}),
        'content-type': 'application/x-www-form-urlencoded',
      };
      init.body = new URLSearchParams(input.body).toString();
    }
    const response = await fetchImpl(urlFor(base), init);
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    const text = await response.text();
    let body: unknown = {};
    if (text !== '') {
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
    }
    return { status: response.status, headers, body: normalizePayload(body) };
  };

  const [rust, ts] = await Promise.all([
    dispatch(input.rustBaseUrl),
    dispatch(input.tsBaseUrl),
  ]);

  return compareResponses({ fixtureId: input.fixtureId, rust, ts });
}
