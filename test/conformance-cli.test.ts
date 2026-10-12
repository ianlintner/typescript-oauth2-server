import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const fixture = {
  id: 'cli-self-test', rfc: 'self-test', status: 'planned',
  request: { method: 'GET', path: '/probe' },
  expect: { status: 200, headers: { 'x-contract': 'yes' }, claims: { ok: true } },
};

async function responder(status: number, body: object, contract = 'yes'): Promise<{ server: Server; url: string; requests: string[] }> {
  const requests: string[] = [];
  const server = createServer((request, response) => {
    requests.push(`${request.method} ${request.url}`);
    response.writeHead(status, { 'content-type': 'application/json', 'x-contract': contract });
    response.end(JSON.stringify(body));
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
  } catch (error) {
    server.close();
    throw error;
  }
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  return { server, url: `http://127.0.0.1:${address.port}`, requests };
}

async function runCli(status: number, body: object, contract = 'yes', deferred = false) {
  const root = await mkdtemp(path.join(tmpdir(), 'oauth-cli-self-test-'));
  let rust: Awaited<ReturnType<typeof responder>> | undefined;
  let ts: Awaited<ReturnType<typeof responder>> | undefined;
  try {
    await writeFile(path.join(root, 'scenario.json'), JSON.stringify({ ...fixture, status: deferred ? 'deferred' : 'planned' }));
    rust = await responder(status, body, contract);
    ts = await responder(status, body, contract);
    let exitCode = 0;
    let stdout = '';
    try {
      ({ stdout } = await exec('pnpm', ['conformance', '--rust', rust.url, '--ts', ts.url, '--fixtures', root], {
        cwd: process.cwd(), timeout: 15000,
      }));
    } catch (error) {
      const failure = error as Error & { code?: number; stdout?: string; stderr?: string };
      assert.equal(typeof failure.code, 'number', failure.stderr ?? failure.message);
      exitCode = failure.code!;
      stdout = failure.stdout ?? '';
    }
    return { exitCode, stdout, requests: [rust.requests, ts.requests] };
  } finally {
    if (rust) {
      const server = rust.server;
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
    if (ts) {
      const server = ts.server;
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
    await rm(root, { recursive: true, force: true });
  }
}

test('CLI executes an isolated matching fixture and exits successfully', async () => {
  const result = await runCli(200, { ok: true });
  assert.equal(result.exitCode, 0, result.stdout);
  assert.match(result.stdout, /PASS cli-self-test/);
  assert.deepEqual(result.requests, [['GET /probe'], ['GET /probe']]);
});

test('CLI rejects identical wrong status with DIFF', async () => {
  const result = await runCli(201, { ok: true });
  assert.notEqual(result.exitCode, 0);
  assert.match(result.stdout, /DIFF cli-self-test/);
  assert.match(result.stdout, /expect\.status/);
});

test('CLI rejects identical wrong claim with DIFF', async () => {
  const result = await runCli(200, { ok: false });
  assert.notEqual(result.exitCode, 0);
  assert.match(result.stdout, /DIFF cli-self-test/);
  assert.match(result.stdout, /expect\.claim\[ok\]/);
});

test('CLI enforces selected headers even when both servers agree', async () => {
  const result = await runCli(200, { ok: true }, 'no');
  assert.notEqual(result.exitCode, 0);
  assert.match(result.stdout, /DIFF cli-self-test/);
  assert.match(result.stdout, /expect\.header\[x-contract\]/);
});

test('CLI cannot claim success when every fixture is deferred', async () => {
  const result = await runCli(200, { ok: true }, 'yes', true);
  assert.notEqual(result.exitCode, 0);
  assert.match(result.stdout, /DEFERRED cli-self-test/);
  assert.match(result.stdout, /no executable fixtures/);
  assert.deepEqual(result.requests, [[], []]);
});

test('CLI runs the shipped stateful fixtures against two live conformance responders', async () => {
  const { startConformanceServer } = await import('../src/conformance/serve.js');
  const a = await startConformanceServer();
  const b = await startConformanceServer();
  try {
    let stdout = '';
    let exitCode = 0;
    try {
      ({ stdout } = await exec('pnpm', ['conformance', '--rust', a.address, '--ts', b.address], { cwd: process.cwd(), timeout: 60000 }));
    } catch (error) {
      const failure = error as Error & { code?: number; stdout?: string };
      exitCode = failure.code ?? -1;
      stdout = failure.stdout ?? '';
    }
    assert.equal(exitCode, 0, stdout);
    for (const id of ['rfc9700.code-replay', 'rfc7636.pkce.wrong-verifier', 'rfc7636.pkce.missing-challenge',
      'rfc6749.authorization-code.reject-wrong-redirect-uri', 'rfc6749.authorization.reject-duplicate-parameter',
      'rfc6749.client-auth.reject-wrong-secret']) {
      assert.match(stdout, new RegExp(`PASS ${id.replaceAll('.', '\\.')}`), stdout);
    }
  } finally {
    await a.close();
    await b.close();
  }
});
