import assert from 'node:assert/strict';
import test from 'node:test';
import { MATRIX } from '../src/conformance/matrix.js';
import { parseConformanceStatus } from '../src/conformance/status.js';

test('every matrix entry has a valid conformance status', () => {
  for (const entry of MATRIX) {
    assert.doesNotThrow(() => parseConformanceStatus(entry.status), entry.id);
  }
});

test('matrix entry identifiers are unique', () => {
  const ids = MATRIX.map((entry) => entry.id);
  assert.equal(new Set(ids).size, ids.length, 'matrix ids must be unique');
});

test('every deviation entry carries a documented note', () => {
  for (const entry of MATRIX) {
    if (entry.status === 'deviation') {
      assert.ok(entry.note, `${entry.id} is a deviation but has no note`);
    }
  }
});

test('every entry names a Rust reference', () => {
  for (const entry of MATRIX) {
    assert.ok(entry.rustReference.trim().length > 0, `${entry.id} missing rustReference`);
  }
});

test('no entry is yet marked passing, because the TS server has no endpoints', () => {
  const passing = MATRIX.filter((entry) => entry.status === 'passing');
  assert.equal(passing.length, 0, 'nothing may be passing until a TS endpoint is exercised');
});

test('matrix scope is explicitly an intentionally partial seed', async () => {
  const { readFile } = await import('node:fs/promises');
  for (const file of ['src/conformance/matrix.ts', 'README.md']) {
    assert.match(await readFile(file, 'utf8'), /intentionally partial seed/);
  }
});
