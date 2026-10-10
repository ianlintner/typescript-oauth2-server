import assert from 'node:assert/strict';
import test from 'node:test';
import { parseScenario } from '../src/fixtures.js';

test('accepts a minimal RFC scenario for an HTTP request and expected status', () => {
  const scenario = parseScenario({
    id: 'rfc6749.authorization-code',
    rfc: 'RFC 6749 §4.1',
    request: { method: 'GET', path: '/oauth/authorize' },
    expect: { status: 302 },
  });

  assert.equal(scenario.id, 'rfc6749.authorization-code');
  assert.equal(scenario.request.path, '/oauth/authorize');
  assert.equal(scenario.expect.status, 302);
});

test('rejects an unsupported HTTP method before dispatch', () => {
  assert.throws(() => parseScenario({
    id: 'rfc6749.bad-method',
    rfc: 'RFC 6749 §4.1',
    request: { method: 'DELETE', path: '/oauth/authorize' },
    expect: { status: 405 },
  }), /request method/);
});

test('rejects an out-of-range expected HTTP status', () => {
  assert.throws(() => parseScenario({
    id: 'rfc6749.bad-status',
    rfc: 'RFC 6749 §4.1',
    request: { method: 'POST', path: '/oauth/token' },
    expect: { status: 700 },
  }), /expected status/);
});

test('rejects a relative request path', () => {
  assert.throws(() => parseScenario({
    id: 'rfc6749.bad-path',
    rfc: 'RFC 6749 §4.1',
    request: { method: 'GET', path: 'oauth/authorize' },
    expect: { status: 400 },
  }), /request path/);
});

test('rejects a scenario without a nonempty RFC reference', () => {
  assert.throws(() => parseScenario({
    id: 'authorization-code',
    rfc: '',
    request: { method: 'GET', path: '/oauth/authorize' },
    expect: { status: 302 },
  }), /RFC reference/);
});

test('rejects a scenario without an identifier', () => {
  assert.throws(() => parseScenario({
    id: '',
    rfc: 'RFC 6749 §4.1',
    request: { method: 'GET', path: '/oauth/authorize' },
    expect: { status: 302 },
  }), /scenario id/);
});

test('rejects a missing request object', () => {
  assert.throws(() => parseScenario({
    id: 'rfc6749.no-request',
    rfc: 'RFC 6749 §4.1',
    expect: { status: 302 },
  }), /request must be an object/);
});

test('rejects a missing expectation object', () => {
  assert.throws(() => parseScenario({
    id: 'rfc6749.no-expectation',
    rfc: 'RFC 6749 §4.1',
    request: { method: 'GET', path: '/oauth/authorize' },
  }), /expectation must be an object/);
});
