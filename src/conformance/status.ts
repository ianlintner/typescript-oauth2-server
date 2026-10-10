// Conformance status vocabulary for the cross-language port.
//
// A `planned` entry is a route/test the Rust reference already implements or
// covers but the TypeScript server has not ported yet. `passing` means a
// fixture in this repo exercises the behavior against the TypeScript server
// and it currently passes. `deferred` is an out-of-scope feature the
// architecture proposal explicitly postponed (DPoP, mTLS, dynamic
// registration, social login, agent/A2A extensions). `deviation` records a
// place where the TypeScript implementation intentionally diverges from the
// Rust wire behavior with a documented reason.

export type ConformanceStatus = 'planned' | 'passing' | 'deferred' | 'deviation';

export const CONFORMANCE_STATUSES: readonly ConformanceStatus[] = [
  'planned',
  'passing',
  'deferred',
  'deviation',
] as const;

/** The supported HTTP methods for a conformance fixture. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

export interface ConformanceEntry {
  /** Stable identifier, e.g. `rfc6749.authorization-code`. */
  id: string;
  /** Reference clause, e.g. `RFC 6749 §4.1`. */
  rfc: string;
  /** HTTP method of the route under test. */
  method: HttpMethod;
  /** Request path relative to the server base URL. */
  path: string;
  /** Rust implementation reference: source file + route. */
  rustReference: string;
  /** TS implementation reference, or null when not yet implemented. */
  tsReference: string | null;
  /** Conformance status for this entry. */
  status: ConformanceStatus;
  /**
   * A single sentence documenting a deviation, or the reason an entry is
   * deferred. Required when status is `deviation`; optional otherwise.
   */
  note?: string;
}

export function parseConformanceStatus(input: unknown): ConformanceStatus {
  if (typeof input === 'string' && (CONFORMANCE_STATUSES as readonly string[]).includes(input)) {
    return input as ConformanceStatus;
  }
  throw new TypeError(`unknown conformance status: ${String(input)}`);
}
