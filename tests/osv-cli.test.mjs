// JavaScript, tests/osv-cli.test.mjs, Node.js 20+, OSV CLI opt-in integration tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { main } from '../src/cli/main.mjs';

function json_response(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

test('audit command refuses network lookup unless --osv is explicit', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-osv-cli-opt-in-'));
  let calls = 0;
  try {
    await assert.rejects(
      main(['audit', directory], { fetch_impl: async () => { calls += 1; throw new Error('network must remain off'); } }),
      /pass --osv to query OSV\.dev.*No network request was made/,
    );
    assert.equal(calls, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('audit command scans lockfile versions, calls OSV only with opt-in, and writes JSON report', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-osv-cli-run-'));
  const output = path.join(tmpdir(), 'orix-osv-audit-' + process.pid + '-' + Date.now() + '.json');
  const calls = [];
  try {
    await writeFile(path.join(directory, 'package-lock.json'), JSON.stringify({
      name: 'fixture-project',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'fixture-project',
          version: '1.0.0',
          dependencies: { alpha: '^1.0.0' },
        },
        'node_modules/alpha': { version: '1.2.0' },
      },
    }));

    const fetch_impl = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith('/querybatch')) {
        const body = JSON.parse(init.body);
        assert.deepEqual(body.queries, [{
          package: { ecosystem: 'npm', name: 'alpha' },
          version: '1.2.0',
        }]);
        return json_response({ results: [{ vulns: [{ id: 'OSV-CLI-1', modified: '2025-01-01T00:00:00Z' }] }] });
      }
      assert.equal(String(url), 'https://api.osv.dev/v1/vulns/OSV-CLI-1');
      return json_response({
        id: 'OSV-CLI-1',
        summary: 'CLI fixture advisory',
        modified: '2025-01-01T00:00:00Z',
        references: [{ type: 'WEB', url: 'https://example.test/OSV-CLI-1' }],
      });
    };

    await main([
      'audit', directory, '--osv', '--json', '--out', output,
      '--max-packages', '50', '--max-advisories', '20',
    ], { fetch_impl });

    const report = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(report.schema_version, 'orix.vulnerability-audit.v1');
    assert.equal(report.summary.status, 'complete');
    assert.equal(report.summary.queried_packages, 1);
    assert.equal(report.summary.vulnerabilities, 1);
    assert.equal(report.vulnerabilities[0].id, 'OSV-CLI-1');
    assert.equal(calls.length, 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
    await rm(output, { force: true });
  }
});

test('audit command rejects unsupported output formats before contacting OSV', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-osv-cli-format-'));
  let calls = 0;
  try {
    await assert.rejects(
      main(['audit', directory, '--osv', '--format', 'sarif'], {
        fetch_impl: async () => { calls += 1; throw new Error('unexpected request'); },
      }),
      /audit output supports JSON or Markdown only/,
    );
    assert.equal(calls, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
