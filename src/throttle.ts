import { createHash } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { OAuthError } from './errors.js';
import type { Clock, Store } from './ports.js';

/** Fixed-window bounds. Counters live in the store, so they hold across processes sharing it. */
export interface ThrottleConfig {
  /** Window length for every counter below, in seconds. */
  windowSeconds: number;
  /** Failed client authentications allowed per client id per window. */
  maxFailuresPerClient: number;
  /** Failed client authentications allowed per source address per window. */
  maxFailuresPerSource: number;
  /** Device-authorization / pushed-request creations allowed per source address per window. */
  maxCreationsPerSource: number;
  /** Unexpired device codes (or pushed requests) allowed per client. */
  maxLiveRecordsPerClient: number;
  /** Unexpired device codes (or pushed requests) allowed overall. */
  maxLiveRecords: number;
}

export const DEFAULT_THROTTLE: ThrottleConfig = {
  windowSeconds: 60,
  maxFailuresPerClient: 20,
  maxFailuresPerSource: 10,
  maxCreationsPerSource: 30,
  maxLiveRecordsPerClient: 1_000,
  maxLiveRecords: 10_000,
};

export interface ThrottleDeps {
  store: Store;
  clock: Clock;
  throttle?: Partial<ThrottleConfig> | false | undefined;
}

/** Effective limits, or null when throttling is disabled (`throttle: false`). */
export function resolveThrottle(deps: ThrottleDeps): ThrottleConfig | null {
  return deps.throttle === false ? null : { ...DEFAULT_THROTTLE, ...deps.throttle };
}

const digest = (value: string): string => createHash('sha256').update(value).digest('base64url');
export const failureKey = {
  client: (clientId: string): string => `authfail:client:${digest(clientId)}`,
  // req.ip is the socket address unless the embedder configured trustProxy; forwarding headers are never read here.
  source: (req: FastifyRequest): string => `authfail:source:${req.ip}`,
};
export const creationKey = (kind: 'par' | 'device', req: FastifyRequest): string => `create:${kind}:${req.ip}`;

export function tooManyRequests(resetAt: number, now: number): OAuthError {
  return new OAuthError('temporarily_unavailable', 'too many requests', Math.max(1, resetAt - now));
}
