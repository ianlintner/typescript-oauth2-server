import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ConfigError, loadConfig } from '../src/config.js';
import { assertSafeForConformance, conformanceModeFromEnv } from '../src/sut/mode.js';

const base = {
  OAUTH2_ENV: 'test',
  OAUTH2_ISSUER: 'http://localhost:8080',
  OAUTH2_SESSION_SECRET: 'x'.repeat(32),
  OAUTH2_SIGNING_KEY_PEM: 'pem',
  OAUTH2_SIGNING_KEY_ID: 'k1',
};

function refused(env: Record<string, string | undefined>, pattern: RegExp) {
  assert.throws(
    () => assertSafeForConformance(env, loadConfig(env)),
    (e) => e instanceof ConfigError && pattern.test(e.message),
  );
}

test('conformance mode is off by default and for explicit 0 or empty', () => {
  assert.deepEqual(conformanceModeFromEnv({}), { enabled: false });
  assert.deepEqual(conformanceModeFromEnv({ OAUTH2_CONFORMANCE_MODE: '0' }), { enabled: false });
  assert.deepEqual(conformanceModeFromEnv({ OAUTH2_CONFORMANCE_MODE: '' }), { enabled: false });
});

test('a seed path without the mode switch is ignored, never enabling anything', () => {
  assert.deepEqual(conformanceModeFromEnv({ OAUTH2_CONFORMANCE_SEED: '/tmp/seed.yaml' }), { enabled: false });
});

test('mode 1 requires a seed path and returns it', () => {
  assert.throws(() => conformanceModeFromEnv({ OAUTH2_CONFORMANCE_MODE: '1' }), /OAUTH2_CONFORMANCE_SEED/);
  assert.throws(
    () => conformanceModeFromEnv({ OAUTH2_CONFORMANCE_MODE: '1', OAUTH2_CONFORMANCE_SEED: '  ' }),
    /OAUTH2_CONFORMANCE_SEED/,
  );
  assert.deepEqual(conformanceModeFromEnv({ OAUTH2_CONFORMANCE_MODE: '1', OAUTH2_CONFORMANCE_SEED: '/s.yaml' }), {
    enabled: true,
    seedPath: '/s.yaml',
  });
});

test('ambiguous mode values fail closed instead of being treated as off', () => {
  for (const v of ['yes', 'on', 'TRUE', '2', 'enabled']) {
    assert.throws(() => conformanceModeFromEnv({ OAUTH2_CONFORMANCE_MODE: v }), /OAUTH2_CONFORMANCE_MODE/);
  }
});

test('guard accepts test/development on in-memory storage and loopback binding', () => {
  for (const mode of ['test', 'development']) {
    const env = { ...base, OAUTH2_ENV: mode };
    assert.doesNotThrow(() => assertSafeForConformance(env, loadConfig(env)));
  }
  const explicit = { ...base, OAUTH2_DATABASE_PATH: ':memory:', OAUTH2_HOST: '::1' };
  assert.doesNotThrow(() => assertSafeForConformance(explicit, loadConfig(explicit)));
});

test('guard refuses a production profile', () => {
  const env = {
    ...base,
    OAUTH2_ENV: 'production',
    OAUTH2_ISSUER: 'https://auth.example.com',
    OAUTH2_DATABASE_PATH: '/var/lib/oauth2/db.sqlite',
  };
  refused(env, /production/);
});

test('guard refuses any other profile variable naming a non-test environment', () => {
  for (const name of ['APP_ENV', 'ENVIRONMENT', 'NODE_ENV', 'OAUTH2_ENVIRONMENT', 'OAUTH2_PROFILE']) {
    for (const value of ['production', 'prod', 'staging', 'typo-env']) {
      refused({ ...base, [name]: value }, new RegExp(name));
    }
    assert.doesNotThrow(() => {
      const env = { ...base, [name]: 'CI' };
      assertSafeForConformance(env, loadConfig(env));
    });
  }
});

test('guard refuses persistent database paths', () => {
  refused({ ...base, OAUTH2_DATABASE_PATH: '/var/lib/oauth2/db.sqlite' }, /in-memory/);
  refused({ ...base, OAUTH2_DATABASE_PATH: 'file::memory:?cache=shared' }, /in-memory/);
});

test('guard refuses non-loopback binding', () => {
  for (const host of ['0.0.0.0', '::', '192.168.1.10', 'example.com']) {
    refused({ ...base, OAUTH2_HOST: host }, /loopback/);
  }
});
