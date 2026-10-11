import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OAuthError, errorResponse } from '../src/errors.js';

test('invalid_client maps to 401 with WWW-Authenticate and no-store headers', () => {
  const res = errorResponse(new OAuthError('invalid_client', 'bad creds'));
  assert.equal(res.status, 401);
  assert.deepEqual(res.body, { error: 'invalid_client', error_description: 'bad creds' });
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.headers['pragma'], 'no-cache');
  assert.match(res.headers['www-authenticate'] ?? '', /^Basic /);
});

test('invalid_request maps to 400 without WWW-Authenticate', () => {
  const res = errorResponse(new OAuthError('invalid_request', 'dup param'));
  assert.equal(res.status, 400);
  assert.equal(res.headers['www-authenticate'], undefined);
});

test('server_error maps to 500 and never leaks the description', () => {
  const res = errorResponse(new OAuthError('server_error', 'db password=hunter2'));
  assert.equal(res.status, 500);
  assert.equal(res.body.error, 'server_error');
  assert.equal(JSON.stringify(res.body).includes('hunter2'), false);
});

test('non-OAuth errors become opaque server_error', () => {
  const res = errorResponse(new Error('secret internals'));
  assert.equal(res.status, 500);
  assert.deepEqual(res.body, { error: 'server_error' });
});

test('description omitted when absent', () => {
  assert.deepEqual(errorResponse(new OAuthError('invalid_grant')).body, { error: 'invalid_grant' });
});
