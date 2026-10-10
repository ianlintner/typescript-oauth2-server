import assert from 'node:assert/strict';
import test from 'node:test';
import {
  compareResponses,
  type ComparisonResult,
  type ResponseSnapshot,
} from '../src/conformance/runner.js';

function snapshot(overrides: Partial<ResponseSnapshot> = {}): ResponseSnapshot {
  return {
    status: 200,
    headers: {},
    body: {},
    ...overrides,
  };
}

test('reports a match when status, headers and claims agree', () => {
  const result: ComparisonResult = compareResponses({
    fixtureId: 'rfc6749.token-endpoint',
    rust: snapshot({ status: 200, body: { token_type: 'Bearer' } }),
    ts: snapshot({ status: 200, body: { token_type: 'Bearer' } }),
  });
  assert.equal(result.match, true);
  assert.deepEqual(result.diffs, []);
});

test('detects a status mismatch and names the field', () => {
  const result = compareResponses({
    fixtureId: 'rfc6749.bad-status',
    rust: snapshot({ status: 400 }),
    ts: snapshot({ status: 201 }),
  });
  assert.equal(result.match, false);
  assert.deepEqual(result.diffs, [{ field: 'status', rust: 400, ts: 201 }]);
});

test('detects a header mismatch', () => {
  const result = compareResponses({
    fixtureId: 'rfc6749.header-mismatch',
    rust: snapshot({ headers: { 'content-type': 'application/json' } }),
    ts: snapshot({ headers: { 'content-type': 'text/html' } }),
  });
  assert.equal(result.match, false);
  assert.deepEqual(result.diffs, [
    {
      field: 'header[content-type]',
      rust: 'application/json',
      ts: 'text/html',
    },
  ]);
});

test('detects a claim mismatch', () => {
  const result = compareResponses({
    fixtureId: 'rfc6749.claim-mismatch',
    rust: snapshot({ body: { token_type: 'Bearer' } }),
    ts: snapshot({ body: { token_type: 'bearer' } }),
  });
  assert.equal(result.match, false);
  assert.deepEqual(result.diffs, [
    { field: 'claim[token_type]', rust: 'Bearer', ts: 'bearer' },
  ]);
});

test('normalizes a nondeterministic access_token before comparison', () => {
  const result = compareResponses({
    fixtureId: 'rfc6749.token-nondeterminism',
    rust: snapshot({ body: { token_type: 'Bearer', access_token: 'rust-token-A' } }),
    ts: snapshot({ body: { token_type: 'Bearer', access_token: 'ts-token-B' } }),
  });
  assert.equal(result.match, true, `expected match, got diffs ${JSON.stringify(result.diffs)}`);
});

test('reports every mismatch deterministically in field order', () => {
  const result = compareResponses({
    fixtureId: 'rfc6749.multiple-diffs',
    rust: snapshot({ status: 200, headers: { 'cache-control': 'no-store' }, body: { a: 1 } }),
    ts: snapshot({ status: 200, headers: { 'cache-control': 'no-cache' }, body: { a: 2 } }),
  });
  assert.equal(result.match, false);
  assert.deepEqual(result.diffs, [
    { field: 'claim[a]', rust: 1, ts: 2 },
    { field: 'header[cache-control]', rust: 'no-store', ts: 'no-cache' },
  ]);
});

for (const key of ['state', 'nonce']) {
  test(`detects a client-controlled ${key} mismatch`, () => {
    assert.equal(compareResponses({
      fixtureId: key,
      rust: snapshot({ body: { [key]: 'client-value-123456' } }),
      ts: snapshot({ body: { [key]: 'changed-value-123456' } }),
    }).match, false);
  });
}
