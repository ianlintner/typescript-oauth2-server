import { randomBytes } from 'node:crypto';
import type { Clock, Random } from './ports.js';

export const systemClock: Clock = { now: () => Math.floor(Date.now() / 1000) };

export const cryptoRandom: Random = {
  token(bytes: number): string {
    if (!Number.isInteger(bytes) || bytes < 16) throw new RangeError('token needs at least 16 bytes');
    return randomBytes(bytes).toString('base64url');
  },
};
