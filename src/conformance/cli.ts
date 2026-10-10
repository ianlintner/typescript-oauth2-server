// Conformance harness CLI.
//
// Replays every seeded fixture against an isolated Rust base URL and an
// isolated TypeScript base URL, compares the normalized response contract, and
// prints a per-fixture PASS/DIFF report. Exit code 0 only when every fixture
// matches.
//
// Usage:
//   node src/conformance/cli.ts --rust http://127.0.0.1:8080 --ts http://127.0.0.1:3000
//
// The CLI deliberately refuses to run until both base URLs are provided; the
// harness is cross-language by design and has nothing to compare against a
// single server.

import { loadFixtures } from './loader.js';
import { runFixture } from './runner.js';

interface Options {
  rust: string;
  ts: string;
}

function parseArgs(argv: string[]): Options {
  const opts: Partial<Options> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--rust' || arg === '--ts') {
      const value = argv[i + 1];
      if (value === undefined) {
        throw new Error(`missing value for ${arg}`);
      }
      if (arg === '--rust') opts.rust = value;
      if (arg === '--ts') opts.ts = value;
      i += 1;
    }
  }
  if (opts.rust === undefined || opts.ts === undefined) {
    throw new Error('usage: cli.ts --rust <url> --ts <url>');
  }
  return { rust: opts.rust, ts: opts.ts };
}

async function main(argv: string[]): Promise<number> {
  const { rust, ts } = parseArgs(argv);
  const fixtures = await loadFixtures();

  let failures = 0;
  for (const fixture of fixtures) {
    const result = await runFixture({
      fixtureId: fixture.id,
      method: fixture.request.method,
      path: fixture.request.path,
      ...(fixture.request.query !== undefined ? { query: fixture.request.query } : {}),
      ...(fixture.request.body !== undefined ? { body: fixture.request.body } : {}),
      ...(fixture.request.headers !== undefined ? { headers: fixture.request.headers } : {}),
      rustBaseUrl: rust,
      tsBaseUrl: ts,
    });

    if (result.match) {
      console.log(`PASS ${fixture.id}`);
    } else {
      failures += 1;
      console.log(`DIFF ${fixture.id}`);
      for (const diff of result.diffs) {
        console.log(`  ${diff.field}: rust=${safeJson(diff.rust)} ts=${safeJson(diff.ts)}`);
      }
    }
  }

  if (fixtures.length === 0) {
    console.log('no fixtures loaded');
    return 1;
  }
  if (failures > 0) {
    console.log(`${failures} of ${fixtures.length} fixtures diverged`);
    return 1;
  }
  console.log(`all ${fixtures.length} fixtures matched`);
  return 0;
}

function safeJson(value: unknown): string {
  if (value === undefined) return '<undefined>';
  try {
    return JSON.stringify(value, (_key, entry: unknown) => {
      // Deep-equal-safe stringification for values that may contain cycles or
      // non-serializable entries from a live response.
      if (typeof entry === 'bigint') return entry.toString();
      return entry as string;
    });
  } catch {
    return String(value);
  }
}

process.exitCode = 0;
void (async () => {
  try {
    process.exitCode = await main(process.argv.slice(2));
  } catch (error) {
    console.error(String(error instanceof Error ? error.message : error));
    process.exitCode = 1;
  }
})();

// Re-export for tests.
export { safeJson };
