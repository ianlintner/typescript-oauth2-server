import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ConfigError, loadConfig } from '../src/config.js';

const SECRET = 'x'.repeat(32);
const KEY = '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----';
const dev = {
  OAUTH2_ENV: 'development',
  OAUTH2_ISSUER: 'http://localhost:8080',
  OAUTH2_SESSION_SECRET: SECRET,
  OAUTH2_SIGNING_KEY_PEM: KEY,
  OAUTH2_SIGNING_KEY_ID: 'k1',
};
const prod = {
  ...dev,
  OAUTH2_ENV: 'production',
  OAUTH2_ISSUER: 'https://auth.example.com',
  OAUTH2_DATABASE_PATH: '/var/lib/oauth2/db.sqlite',
};

function rejects(env: Record<string, string | undefined>, pattern: RegExp) {
  assert.throws(() => loadConfig(env), (e) => e instanceof ConfigError && pattern.test(e.message));
}

test('valid development config loads with defaults', () => {
  const c = loadConfig(dev);
  assert.equal(c.env, 'development');
  assert.equal(c.issuer, 'http://localhost:8080');
  assert.equal(c.host, '127.0.0.1');
  assert.equal(c.port, 8080);
  assert.equal(c.databasePath, ':memory:');
  assert.equal(c.signingKeyId, 'k1');
});

test('valid production config loads', () => {
  const c = loadConfig(prod);
  assert.equal(c.env, 'production');
  assert.equal(c.issuer, 'https://auth.example.com');
});

test('missing issuer fails closed', () => {
  rejects({ ...dev, OAUTH2_ISSUER: undefined }, /OAUTH2_ISSUER/);
  rejects({ ...dev, OAUTH2_ISSUER: '  ' }, /OAUTH2_ISSUER/);
});

test('missing signing key or key id fails closed', () => {
  rejects({ ...dev, OAUTH2_SIGNING_KEY_PEM: undefined }, /OAUTH2_SIGNING_KEY_PEM/);
  rejects({ ...dev, OAUTH2_SIGNING_KEY_ID: undefined }, /OAUTH2_SIGNING_KEY_ID/);
});

test('missing or short session secret fails closed', () => {
  rejects({ ...dev, OAUTH2_SESSION_SECRET: undefined }, /OAUTH2_SESSION_SECRET/);
  rejects({ ...dev, OAUTH2_SESSION_SECRET: 'short' }, /OAUTH2_SESSION_SECRET/);
});

test('unknown or missing environment fails closed (no implicit development)', () => {
  rejects({ ...dev, OAUTH2_ENV: undefined }, /OAUTH2_ENV/);
  rejects({ ...dev, OAUTH2_ENV: 'prod' }, /OAUTH2_ENV/);
});

test('issuer must be an absolute URL without query, fragment or credentials', () => {
  for (const bad of ['not a url', 'ftp://x.example', 'https://a.example/?q=1', 'https://a.example/#f', 'https://u:p@a.example']) {
    rejects({ ...dev, OAUTH2_ISSUER: bad }, /OAUTH2_ISSUER/);
  }
});

test('production rejects http issuer, in-memory database and placeholder secrets', () => {
  rejects({ ...prod, OAUTH2_ISSUER: 'http://auth.example.com' }, /https/);
  rejects({ ...prod, OAUTH2_ISSUER: 'http://localhost:8080' }, /https/);
  rejects({ ...prod, OAUTH2_DATABASE_PATH: undefined }, /OAUTH2_DATABASE_PATH/);
  rejects({ ...prod, OAUTH2_DATABASE_PATH: ':memory:' }, /OAUTH2_DATABASE_PATH/);
  rejects({ ...prod, OAUTH2_SESSION_SECRET: 'change-me'.padEnd(40, '!') }, /OAUTH2_SESSION_SECRET/);
});

test('development allows http only for loopback issuers', () => {
  rejects({ ...dev, OAUTH2_ISSUER: 'http://auth.example.com' }, /https|loopback/);
  assert.equal(loadConfig({ ...dev, OAUTH2_ISSUER: 'http://127.0.0.1:9000' }).issuer, 'http://127.0.0.1:9000');
});

test('invalid port fails closed', () => {
  rejects({ ...dev, OAUTH2_PORT: '0' }, /OAUTH2_PORT/);
  rejects({ ...dev, OAUTH2_PORT: '70000' }, /OAUTH2_PORT/);
  rejects({ ...dev, OAUTH2_PORT: '80abc' }, /OAUTH2_PORT/);
});

test('config errors never echo secret values', () => {
  try {
    loadConfig({ ...dev, OAUTH2_SESSION_SECRET: 'tooshort-secret-value' });
    assert.fail('expected throw');
  } catch (e) {
    assert.equal(String((e as Error).message).includes('tooshort-secret-value'), false);
  }
});
