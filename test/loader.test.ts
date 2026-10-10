import assert from 'node:assert/strict';
import test from 'node:test';
import { loadFixtures } from '../src/conformance/loader.js';

test('loads every seeded fixture and validates each one', async () => {
  const fixtures = await loadFixtures();
  assert.ok(fixtures.length >= 5, `expected >=5 seed fixtures, got ${fixtures.length}`);
  const ids = fixtures.map((fixture) => fixture.id).sort();
  // There must be no duplicate fixture identifiers.
  assert.equal(new Set(ids).size, ids.length, 'fixture ids must be unique');
  // Every loaded fixture is fully typed (parseFixture already validated), but
  // assert the intended statuses are all still `planned` until a TS endpoint
  // exists to exercise them for real.
  for (const fixture of fixtures) {
    assert.equal(fixture.status, 'planned', `${fixture.id} must start as planned`);
  }
});

test('includes the RFC 7636 PKCE seed fixtures', async () => {
  const fixtures = await loadFixtures();
  const ids = new Set(fixtures.map((fixture) => fixture.id));
  assert.ok(ids.has('rfc7636.pkce.missing-challenge'));
  assert.ok(ids.has('rfc7636.pkce.wrong-verifier'));
});

test('includes the RFC 9700 code-replay seed fixture', async () => {
  const fixtures = await loadFixtures();
  const ids = new Set(fixtures.map((fixture) => fixture.id));
  assert.ok(ids.has('rfc9700.code-replay'));
});
