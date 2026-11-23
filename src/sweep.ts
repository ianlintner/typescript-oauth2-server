import type { Clock, Store } from './ports.js';

export const DEFAULT_SWEEP_INTERVAL_SECONDS = 300;

export interface Sweeper {
  /** Stop scheduling and wait for a sweep that is already running. */
  stop(): Promise<void>;
}

/**
 * Remove expired records now and then every `intervalSeconds`. Sweeps are idempotent and safe to run
 * from several processes at once; a failed sweep is reported and retried on the next tick. The timer
 * never keeps the process alive. An interval of 0 disables scheduling.
 */
export function startSweeper(
  store: Store, clock: Clock, intervalSeconds: number, onError: (err: unknown) => void = () => undefined,
): Sweeper {
  let running: Promise<void> = Promise.resolve();
  let stopped = false;
  const tick = (): void => {
    if (stopped) return;
    running = running.then(() => store.sweepExpired(clock.now()).then(() => undefined, onError));
  };
  if (intervalSeconds <= 0) return { stop: async () => undefined };
  tick();
  const timer = setInterval(tick, intervalSeconds * 1000);
  timer.unref();
  return {
    stop: async () => {
      stopped = true;
      clearInterval(timer);
      await running;
    },
  };
}
