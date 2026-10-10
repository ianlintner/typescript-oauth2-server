import assert from 'node:assert/strict';
import test from 'node:test';
import { MATRIX } from '../src/conformance/matrix.js';
import { RUST_ROUTES, RUST_TEST_FILES } from '../src/conformance/rust-routes.js';
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

test('matrix covers every route-method in the pinned Rust route table', () => {
  const snapshot = new Map(RUST_ROUTES.map((r) => [`${r.method} ${r.path}`, r]));
  for (const entry of MATRIX) {
    const key = `${entry.method} ${entry.path}`;
    const rust = snapshot.get(key);
    if (!rust) assert.fail(`${key} is in the matrix but not the pinned Rust route table`);
    const expectedRef = `crates/oauth2-server/src/lib.rs:${rust.line} (${rust.handler})`;
    assert.equal(entry.rustReference, expectedRef, `${entry.id} rustReference mismatch vs snapshot`);
  }
  const covered = new Set(MATRIX.map((e) => `${e.method} ${e.path}`));
  const missing = RUST_ROUTES.filter((r) => !covered.has(`${r.method} ${r.path}`));
  assert.deepEqual(missing.map((r) => `${r.method} ${r.path}`), [], 'Rust routes absent from the conformance matrix');
});

test('every rustTests reference exists among the pinned Rust test files', () => {
  const files = new Set(RUST_TEST_FILES);
  for (const entry of MATRIX) {
    for (const t of entry.rustTests) {
      assert.ok(files.has(t), `${entry.id} references unknown Rust test ${t}`);
    }
  }
});

test('matrix scope is a full route inventory, not a partial seed', async () => {
  const { readFile } = await import('node:fs/promises');
  for (const file of ['src/conformance/matrix.ts', 'README.md']) {
    assert.doesNotMatch(await readFile(file, 'utf8'), /intentionally partial seed/);
  }
});

test('no route-method key appears twice in the matrix or the pinned Rust route table', () => {
  const dupes = (keys: string[]) => keys.filter((k, i) => keys.indexOf(k) !== i);
  assert.deepEqual(dupes(MATRIX.map((e) => `${e.method} ${e.path}`)), [], 'duplicate matrix route-method keys');
  assert.deepEqual(dupes(RUST_ROUTES.map((r) => `${r.method} ${r.path}`)), [], 'duplicate Rust snapshot keys');
});
