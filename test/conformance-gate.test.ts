import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const SHA = 'a'.repeat(40);

function gate(manifest: string, report: object) {
  const dir = mkdtempSync(join(tmpdir(), 'gate-'));
  writeFileSync(join(dir, 'm.yaml'), manifest);
  writeFileSync(join(dir, 'r.json'), JSON.stringify(report));
  return spawnSync(process.execPath, ['scripts/check-conformance-report.mjs', join(dir, 'm.yaml'), join(dir, 'r.json')], {
    encoding: 'utf8',
  });
}

const manifest = (extra: string) => `implementation: impl
contract: ${SHA}
profiles: [core, token-lifecycle]
deviations:
${extra}`;

const passing = (profile: string) => ({
  contract: SHA, implementation: 'impl', profile,
  results: [{ id: `${profile}.ok`, status: 'stable', outcome: 'pass', requirements: ['RFC-OK'] }],
});

const coreDeviation = `  - requirement: RFC6749-1-core-only
    reason: a core-only gap that token-lifecycle cannot exercise
    profile: core`;

test('a deviation scoped to another profile is not stale in this profile report', () => {
  const r = gate(manifest(coreDeviation), passing('token-lifecycle'));
  assert.equal(r.status, 0, r.stderr);
});

test('a profile-scoped deviation that no longer fails in its own profile is stale', () => {
  const r = gate(manifest(coreDeviation), passing('core'));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /RFC6749-1-core-only no longer fails/);
});

test('a profile-scoped deviation does not excuse a failure in another profile', () => {
  const report = passing('token-lifecycle');
  report.results.push({ id: 'tl.bad', status: 'stable', outcome: 'fail', requirements: ['RFC6749-1-core-only'] });
  const r = gate(manifest(coreDeviation), report);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /tl\.bad/);
});

test('an unscoped deviation keeps applying to every profile', () => {
  const unscoped = `  - requirement: RFC6749-1-any
    reason: an unscoped deviation applies to all profiles`;
  const r = gate(manifest(unscoped), passing('core'));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /RFC6749-1-any no longer fails/);
});
