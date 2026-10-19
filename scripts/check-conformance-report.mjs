// Gate a shared-conformance-runner report against the deviations declared in
// `conformance.yaml`. TypeScript port of
// python-oauth2-server/scripts/check_conformance_report.py, with one extension:
// the manifest `contract` may be a pinned 40-hex commit SHA (pre-release) or a
// MAJOR.MINOR.PATCH version, both of which the runner records verbatim in the
// report's `contract` field.
//
// Usage: node scripts/check-conformance-report.mjs <conformance.yaml> <report.json>
//
// The runner's verdict is all-or-nothing (one failing stable scenario => `fail`).
// This server has known protocol gaps that predate its conformance mode, so the
// manifest declares each as a `deviation` (requirement + reason) and this gate
// enforces:
//   * the report is for this implementation, contract and a claimed profile;
//   * every failing scenario is covered by a declared deviation (an undeclared
//     failure is a regression and fails the gate);
//   * every declared deviation still fails (a deviation that now passes, or names
//     a requirement no scenario exercises, is stale and must be removed — the
//     ratchet only tightens);
//   * at least one stable scenario passed (an empty run is not evidence).
// `deferred` scenarios (draft / reference-deviation) never count as failures.
//
// Exit codes: 0 passed, 1 failed, 2 usage or unreadable input.
import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

const SEMVER = /^\d+\.\d+\.\d+$/;
const COMMIT = /^[0-9a-f]{40}$/;
const REQUIREMENT_ID = /^[A-Z][A-Z0-9]*(?:[0-9])?-[A-Za-z0-9._-]+$/;

class GateError extends Error {}

function isObj(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function validateManifest(manifest) {
  if (!isObj(manifest)) throw new GateError('manifest must be a mapping');
  for (const key of ['implementation', 'contract', 'profiles']) {
    if (!(key in manifest)) throw new GateError(`manifest is missing required key '${key}'`);
  }
  const contract = manifest.contract;
  if (typeof contract !== 'string' || (!SEMVER.test(contract) && !COMMIT.test(contract))) {
    throw new GateError('manifest contract must be a MAJOR.MINOR.PATCH version or a full 40-hex commit SHA');
  }
  const profiles = manifest.profiles;
  if (!Array.isArray(profiles) || profiles.length === 0 || !profiles.every((p) => typeof p === 'string' && p !== '')) {
    throw new GateError('manifest profiles must be a non-empty list of profile ids');
  }
  for (const deviation of manifest.deviations ?? []) {
    if (!isObj(deviation)) throw new GateError('each deviation must be a mapping');
    const requirement = deviation.requirement;
    if (typeof requirement !== 'string' || !REQUIREMENT_ID.test(requirement)) {
      throw new GateError(`deviation requirement ${JSON.stringify(requirement)} is not a requirement id`);
    }
    const reason = deviation.reason;
    if (typeof reason !== 'string' || reason.length < 10) {
      throw new GateError(`deviation ${requirement}: reason must be at least 10 characters`);
    }
    if (deviation.profile !== undefined && !profiles.includes(deviation.profile)) {
      throw new GateError(`deviation ${requirement}: profile ${JSON.stringify(deviation.profile)} is not a claimed profile`);
    }
  }
}

function evaluate(manifest, report) {
  const problems = [];
  if (report.contract !== manifest.contract) {
    problems.push(`report contract ${JSON.stringify(report.contract)} != pinned ${JSON.stringify(manifest.contract)}`);
  }
  if (report.implementation !== manifest.implementation) {
    problems.push(`report implementation ${JSON.stringify(report.implementation)} != manifest ${JSON.stringify(manifest.implementation)}`);
  }
  if (!(manifest.profiles ?? []).includes(report.profile)) {
    problems.push(`report profile ${JSON.stringify(report.profile)} is not a claimed profile`);
  }

  const results = report.results ?? [];
  // A deviation may be scoped to one profile (`profile: core`); it then only
  // excuses failures, and is only ratcheted, in that profile's report. An
  // unscoped deviation applies to every profile.
  const applicable = (manifest.deviations ?? []).filter((d) => d.profile === undefined || d.profile === report.profile);
  const declared = new Set(applicable.map((d) => d.requirement));
  const failingRequirements = new Set();

  for (const result of results) {
    const requirements = new Set(result.requirements ?? []);
    if (result.outcome === 'fail') {
      for (const r of requirements) failingRequirements.add(r);
      if (![...requirements].some((r) => declared.has(r))) {
        problems.push(
          `scenario ${JSON.stringify(result.id)} failed and its requirements ` +
            `${JSON.stringify([...requirements].sort())} are not declared as deviations`,
        );
      }
    }
  }

  for (const requirement of [...declared].sort()) {
    if (!failingRequirements.has(requirement)) {
      problems.push(
        `deviation ${requirement} no longer fails (or no scenario exercises it): remove it from conformance.yaml`,
      );
    }
  }

  if (!results.some((r) => r.outcome === 'pass' && r.status === 'stable')) {
    problems.push('no passing stable scenario: an empty run is not evidence');
  }

  return problems;
}

function main(argv) {
  if (argv.length !== 2) {
    process.stderr.write(
      'usage: node scripts/check-conformance-report.mjs <conformance.yaml> <report.json>\n',
    );
    return 2;
  }
  let manifest;
  let report;
  try {
    manifest = parseYaml(readFileSync(argv[0], 'utf8'));
    report = JSON.parse(readFileSync(argv[1], 'utf8'));
    validateManifest(manifest);
    if (!isObj(report)) throw new GateError('report must be a JSON object');
  } catch (err) {
    process.stderr.write(
      `check_conformance_report: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return 2;
  }

  const problems = evaluate(manifest, report);
  const results = report.results ?? [];
  const counts = {};
  for (const outcome of ['pass', 'fail', 'deferred']) {
    counts[outcome] = results.filter((r) => r.outcome === outcome).length;
  }
  const deviations = manifest.deviations ?? [];
  process.stdout.write(
    `conformance: ${counts.pass} passed, ${counts.fail} failed (${deviations.length} declared deviations), ${counts.deferred} deferred\n`,
  );
  for (const problem of problems) {
    process.stderr.write(`conformance gate: ${problem}\n`);
  }
  return problems.length === 0 ? 0 : 1;
}

process.exit(main(process.argv.slice(2)));
