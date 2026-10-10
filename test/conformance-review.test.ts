import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { parseFixture } from '../src/conformance/fixture.js';
import { runFixture, compareResponses } from '../src/conformance/runner.js';
import { loadFixtures } from '../src/conformance/loader.js';

const base = { id: 'test', rfc: 'test', status: 'planned', request: { method: 'GET', path: '/test' }, expect: { status: 200 } };
const urls = { rustBaseUrl: 'http://rust.test', tsBaseUrl: 'http://ts.test' };
const request = { fixtureId: 'test', method: 'GET' as const, path: '/test', ...urls };

for (const [field, value] of [['query', 1], ['body', { a: 1 }], ['headers', []], ['query', null], ['headers', new Date()]]) {
  test(`rejects malformed request ${field}: ${JSON.stringify(value)}`, () => {
    assert.throws(() => parseFixture({ ...base, request: { ...base.request, [field as string]: value } }), new RegExp(`request.${field}`));
  });
}
test('rejects a backslash network-path that can leave both configured origins', () => {
  assert.throws(() => parseFixture({ ...base,
    request: { method: 'GET', path: '/\\\\other.test/probe' },
  }), /request path/);
});

test('rejects an interpolated path that escapes the configured server origin', async () => {
  const fixture = parseFixture({ ...base,
    setup: [{ request: { method: 'GET', path: '/setup' }, expect: { status: 200 }, bind: { target: 'target' } }],
    request: { method: 'GET', path: '/{{target}}' },
  });
  const seen: string[] = [];
  const fetchImpl: typeof fetch = async input => {
    seen.push(String(input));
    return Response.json({ target: '\\other.test/probe' });
  };
  await assert.rejects(runFixture({ fixtureId: fixture.id, ...fixture.request,
    expect: fixture.expect, setup: fixture.setup, ...urls, fetchImpl }), /origin/);
  assert.equal(seen.length, 2, 'only setup requests should reach their configured server');
});

for (const [field, value] of [['headers', []], ['headers', { a: 1 }], ['claims', []], ['claims', 1]]) {
  test(`rejects malformed expectation ${field}: ${JSON.stringify(value)}`, () => {
    assert.throws(() => parseFixture({ ...base, expect: { status: 200, [field as string]: value } }), new RegExp(`expect.${field}`));
  });
}

test('identical wrong status, headers or claims cannot PASS', async () => {
  for (const expect of [{ status: 201 }, { status: 200, headers: { 'X-Contract': 'yes' } }, { status: 200, claims: { error: 'invalid_client' } }]) {
    const result = await runFixture({ ...request, expect, fetchImpl: async () => Response.json({ error: 'invalid_grant' }) });
    assert.equal(result.match, false, JSON.stringify(expect));
    assert.ok(result.diffs.some(diff => diff.field.includes('expect')));
  }
});

test('only declared headers count and their names are case insensitive', async () => {
  const result = await runFixture({ ...request, expect: { status: 200, headers: { 'X-Contract': 'yes' }, claims: { ok: true } },
    fetchImpl: async url => Response.json({ ok: true }, { headers: { 'x-contract': 'yes', date: String(url), server: String(url) } }) });
  assert.equal(result.match, true);
});

test('ignores undeclared response claims when validating a fixture', async () => {
  const result = await runFixture({ ...request, expect: { status: 200, claims: { ok: true } },
    fetchImpl: async url => Response.json({ ok: true, incidental: String(url) }) });
  assert.equal(result.match, true);
});

test('rejects malformed token and timestamp claims despite normalization', async () => {
  const result = await runFixture({ ...request, expect: { status: 200, claims: { access_token: 'expected-token', exp: 123 } },
    fetchImpl: async () => Response.json({ access_token: null, exp: 'not-a-numeric-date' }) });
  assert.equal(result.match, false);
  assert.ok(result.diffs.some(diff => diff.field === 'expect.claim[access_token]'));
  assert.ok(result.diffs.some(diff => diff.field === 'expect.claim[exp]'));
});

test('rejects a literal normalization marker as an invalid timestamp', async () => {
  const oneMalformed = await runFixture({ ...request, expect: { status: 200, claims: { exp: 123 } },
    fetchImpl: async url => Response.json({ exp: String(url).includes('rust.test') ? 123 : '<normalized>' }) });
  assert.equal(oneMalformed.match, false);
  const bothMalformed = await runFixture({ ...request, expect: { status: 200, claims: { exp: 123 } },
    fetchImpl: async () => Response.json({ exp: '<normalized>' }) });
  assert.equal(bothMalformed.match, false);
});

test('OAuth errors remain distinct during comparison', () => {
  assert.equal(compareResponses({ fixtureId: 'errors', rust: { status: 400, headers: {}, body: { error: 'invalid_grant' } }, ts: { status: 400, headers: {}, body: { error: 'invalid_client' } } }).match, false);
});

for (const raw of ['{broken', JSON.stringify({ ...base, request: { method: 'GET', path: '/test', query: 1 } })]) {
  test(`loader attaches full path and original cause: ${raw.slice(0, 15)}`, async () => {
    const dir = await mkdtemp(path.resolve('.fixture-test-'));
    const file = path.join(dir, 'bad.json');
    try {
      await writeFile(file, raw);
      await assert.rejects(loadFixtures(dir), (error: Error) => error.message.includes(file) && error.cause instanceof Error);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
}

test('seed stateful cases are explicitly deferred without fake codes', async () => {
  const fixtures = await loadFixtures();
  for (const fixture of fixtures.filter(f => !f.id.endsWith('reject-invalid-client'))) {
    assert.equal(fixture.status, 'deferred');
    assert.ok(fixture.note);
    assert.doesNotMatch(JSON.stringify(fixture), /valid-code|already-consumed-code/);
  }
});

test('per-server setup obtains, exchanges, replays code and checks prior token revocation', async () => {
  const fixture = parseFixture({ ...base,
    setup: [
      { request: { method: 'GET', path: '/authorize' }, expect: { status: 200 }, bind: { code: 'code' } },
      { request: { method: 'POST', path: '/token', body: { code: '{{code}}' } }, expect: { status: 200, claims: { token_type: 'Bearer' } }, bind: { token: 'access_token' } },
      { request: { method: 'POST', path: '/token', body: { code: '{{code}}' } }, expect: { status: 400, claims: { error: 'invalid_grant' } } },
    ], request: { method: 'POST', path: '/introspect', body: { token: '{{token}}' }, headers: { authorization: 'Bearer {{token}}' }, query: { code: '{{code}}' } },
    expect: { status: 200, claims: { active: false } },
  });
  const calls = new Map<string, number>();
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const index = calls.get(url.host) ?? 0;
    calls.set(url.host, index + 1);
    const code = `${url.host}-code`, token = `${url.host}-token`;
    if (index === 0) { assert.equal(url.pathname, '/authorize'); return Response.json({ code }); }
    if (index === 1 || index === 2) {
      assert.equal(new URLSearchParams(String(init?.body)).get('code'), code);
      return index === 1 ? Response.json({ access_token: token, token_type: 'Bearer' }) : Response.json({ error: 'invalid_grant' }, { status: 400 });
    }
    assert.equal(url.pathname, '/introspect');
    assert.equal(new URLSearchParams(String(init?.body)).get('token'), token);
    assert.equal(new Headers(init?.headers).get('authorization'), `Bearer ${token}`);
    assert.equal(url.searchParams.get('code'), code);
    return Response.json({ active: false });
  };
  const result = await runFixture({ fixtureId: fixture.id, ...fixture.request, expect: fixture.expect, setup: fixture.setup, ...urls, fetchImpl });
  assert.equal(result.match, true);
  assert.deepEqual([...calls.values()], [4, 4]);
});

test('stateful replay mock detects missing cascade revocation', async () => {
  const fixture = parseFixture({ ...base,
    setup: [
      { request: { method: 'GET', path: '/authorize' }, expect: { status: 200 }, bind: { code: 'code' } },
      { request: { method: 'POST', path: '/token', body: { code: '{{code}}' } }, expect: { status: 200 }, bind: { token: 'access_token' } },
      { request: { method: 'POST', path: '/token', body: { code: '{{code}}' } }, expect: { status: 400, claims: { error: 'invalid_grant' } } },
    ], request: { method: 'POST', path: '/introspect', body: { token: '{{token}}' } },
    expect: { status: 200, claims: { active: false } },
  });
  const makeMock = (revokeOnReplay: boolean): typeof fetch => {
    const stores = new Map<string, { code: string; used: boolean; active: boolean }>();
    return async (input, init) => {
      const url = new URL(String(input));
      let store = stores.get(url.host);
      if (url.pathname === '/authorize') {
        store = { code: `${url.host}-code`, used: false, active: false };
        stores.set(url.host, store);
        return Response.json({ code: store.code });
      }
      assert.ok(store, 'authorization must precede token or introspection');
      const body = new URLSearchParams(String(init?.body));
      if (url.pathname === '/token') {
        assert.equal(body.get('code'), store.code);
        if (!store.used) {
          store.used = true;
          store.active = true;
          return Response.json({ access_token: `${url.host}-token` });
        }
        if (revokeOnReplay) store.active = false;
        return Response.json({ error: 'invalid_grant' }, { status: 400 });
      }
      assert.equal(url.pathname, '/introspect');
      assert.equal(body.get('token'), `${url.host}-token`);
      return Response.json({ active: store.active });
    };
  };
  const input = { fixtureId: fixture.id, ...fixture.request, expect: fixture.expect, setup: fixture.setup, ...urls };
  assert.equal((await runFixture({ ...input, fetchImpl: makeMock(true) })).match, true);
  const unrevoked = await runFixture({ ...input, fetchImpl: makeMock(false) });
  assert.equal(unrevoked.match, false);
  assert.ok(unrevoked.diffs.some(diff => diff.field === 'expect.claim[active]'));
});

test('setup contract failures stop dependent requests', async () => {
  let calls = 0;
  const result = await runFixture({ ...request, expect: { status: 200 }, setup: [{ request: { method: 'GET', path: '/setup' }, expect: { status: 201 } }], fetchImpl: async () => { calls++; return Response.json({}); } });
  assert.equal(result.match, false);
  assert.equal(calls, 2);
});

test('unbound request values and missing captured claims fail clearly', async () => {
  await assert.rejects(runFixture({ ...request, expect: { status: 200 }, body: { code: '{{missing}}' }, fetchImpl: async () => { throw new Error('must not dispatch'); } }), /unbound.*missing/);
  await assert.rejects(runFixture({ ...request, expect: { status: 200 }, setup: [{ request: { method: 'GET', path: '/setup' }, expect: { status: 200 }, bind: { code: 'code' } }], fetchImpl: async () => Response.json({}) }), /binding.*code/);
});

for (const setup of [{}, [null], [{ request: { ...base.request, headers: [] }, expect: base.expect }], [{ request: base.request, expect: base.expect, bind: { code: 1 } }]]) {
  test(`validates setup shape ${JSON.stringify(setup)}`, () => {
    assert.throws(() => parseFixture({ ...base, setup }), /setup/);
  });
}
