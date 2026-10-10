// Fixture discovery: load and validate the seeded JSON fixture files.
//
// The `fixtures/` tree holds one JSON file per scenario. Loading parses each
// through `parseFixture` so a malformed fixture fails fast at load time rather
// than producing an opaque runtime mismatch mid-run.

import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseFixture, type Fixture } from './fixture.js';

const FIXTURES_ROOT = fileURLToPath(
  new URL('../../fixtures', import.meta.url),
);

/**
 * Load every fixture under `fixtures/**`.
 *
 * Each JSON file must parse through {@link parseFixture}; a malformed file
 * throws with the file path in the message.
 */
export async function loadFixtures(root: string = FIXTURES_ROOT): Promise<Fixture[]> {
  const results: Fixture[] = [];
  const entries = await readdir(root, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...(await loadFixtures(full)));
    } else if (entry.name.endsWith('.json')) {
      const raw = await readFile(full, 'utf8');
      const fixture = parseFixture(JSON.parse(raw));
      results.push(fixture);
    }
  }
  return results;
}
