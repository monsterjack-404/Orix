// JavaScript, tests/osv.test.mjs, Node.js 20+, OSV protocol and result-contract tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  audit_project_dependencies,
  render_vulnerability_audit_markdown,
  OSV_QUERY_BATCH_SIZE,
} from '../src/vulnerability/osv.mjs';

function project(resolved_dependencies) {
  return {
    schema_version: 'orix.project.v1',
    resolved_dependencies,
  };
}

function dep(name, version, ecosystem = 'npm', lockfile_path = 'package-lock.json', dependency_type = 'direct') {
  return { name, version, ecosystem, lockfile_path, dependency_type };
}

function json_response(value, init = {}) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json', ...init.headers },
    ...init,
  });
}

function advisory(id, extra = {}) {
  return {
    id,
    summary: 'A test advisory summary',
    published: '2025-01-01T00:00:00Z',
    modified: '2025-01-02T00:00:00Z',
    aliases: ['CVE-2025-12345'],
    severity: [{ type: 'CVSS_V3', score: '7.5' }],
    references: [{ type: 'WEB', url: 'https://example.test/advisory/' + id }],
    ...extra,
  };
}

test('OSV audit sends only exact package identifiers and maps advisory matches to lockfile records', async () => {
  const calls = [];
  const fetch_impl = async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith('/querybatch')) {
      const body = JSON.parse(init.body);
      assert.deepEqual(body.queries, [
        { package: { ecosystem: 'npm', name: 'alpha' }, version: '1.2.0' },
        { package: { ecosystem: 'npm', name: 'beta' }, version: '3.4.0' },
      ]);
      return json_response({
        results: [
          { vulns: [{ id: 'OSV-ALPHA-1', modified: '2025-01-02T00:00:00Z' }] },
          {},
        ],
      });
    }
    assert.equal(String(url), 'https://api.osv.dev/v1/vulns/OSV-ALPHA-1');
    return json_response(advisory('OSV-ALPHA-1'));
  };

  const report = await audit_project_dependencies(project([
    dep('alpha', '1.2.0'),
    dep('alpha', '1.2.0', 'npm', 'nested/package-lock.json', 'transitive'),
    dep('beta', '3.4.0'),
    dep('unresolved', '*'),
    dep('mystery', '1.0.0', 'unknown'),
  ]), { fetch_impl });

  assert.equal(report.schema_version, 'orix.vulnerability-audit.v1');
  assert.equal(report.summary.status, 'partial', 'unsupported package identities must make coverage partial');
  assert.equal(report.summary.resolved_packages, 2);
  assert.equal(report.summary.queried_packages, 2);
  assert.equal(report.summary.matched_packages, 1);
  assert.equal(report.summary.vulnerabilities, 1);
  assert.equal(report.summary.unsupported_packages, 2);
  assert.equal(report.packages[0].status, 'matched');
  assert.deepEqual(report.packages[0].vulnerability_ids, ['OSV-ALPHA-1']);
  assert.equal(report.packages[0].locations.length, 2, 'duplicate package coordinates preserve lockfile locations');
  assert.equal(report.packages[1].status, 'no-match');
  assert.equal(report.vulnerabilities[0].matched_packages[0].version, '1.2.0');
  assert.equal(report.vulnerabilities[0].aliases[0], 'CVE-2025-12345');
  assert.equal(report.source.source_files_uploaded, false);
  assert.equal(report.source.package_identifiers_sent, 2);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(item => item.url.startsWith('https://api.osv.dev/')));
  assert.ok(!calls.some(item => String(item.init?.body ?? '').includes('package-lock.json')));
  assert.match(render_vulnerability_audit_markdown(report), /OSV-ALPHA-1/);
  assert.match(render_vulnerability_audit_markdown(report), /unsupported/i);
});

test('OSV pagination continues only package queries that include a next_page_token', async () => {
  const bodies = [];
  const fetch_impl = async (url, init) => {
    if (String(url).endsWith('/querybatch')) {
      const body = JSON.parse(init.body);
      bodies.push(body);
      if (bodies.length === 1) {
        assert.equal(body.queries.length, 2);
        return json_response({
          results: [
            { vulns: [{ id: 'OSV-PAGE-1' }], next_page_token: 'token-for-alpha' },
            { vulns: [] },
          ],
        });
      }
      assert.equal(body.queries.length, 1);
      assert.equal(body.queries[0].package.name, 'alpha');
      assert.equal(body.queries[0].page_token, 'token-for-alpha');
      return json_response({ results: [{ vulns: [{ id: 'OSV-PAGE-2' }] }] });
    }
    const id = String(url).split('/').at(-1);
    return json_response(advisory(id));
  };
  const report = await audit_project_dependencies(project([
    dep('alpha', '1.0.0'),
    dep('beta', '2.0.0'),
  ]), { fetch_impl });
  assert.equal(bodies.length, 2);
  assert.deepEqual(report.packages[0].vulnerability_ids, ['OSV-PAGE-1', 'OSV-PAGE-2']);
  assert.deepEqual(report.packages[1].vulnerability_ids, []);
  assert.equal(report.summary.complete, true);
});

test('OSV withdrawn advisories are separated and removed from active package matches', async () => {
  const fetch_impl = async url => {
    if (String(url).endsWith('/querybatch')) {
      return json_response({ results: [{ vulns: [{ id: 'OSV-WITHDRAWN' }] }] });
    }
    return json_response(advisory('OSV-WITHDRAWN', { withdrawn: '2025-04-01T00:00:00Z' }));
  };
  const report = await audit_project_dependencies(project([dep('alpha', '1.0.0')]), { fetch_impl });
  assert.equal(report.summary.vulnerabilities, 0);
  assert.equal(report.summary.withdrawn_advisories, 1);
  assert.equal(report.packages[0].status, 'no-match');
  assert.deepEqual(report.packages[0].vulnerability_ids, []);
  assert.equal(report.withdrawn_advisories[0].withdrawn, true);
});

test('OSV query failures produce partial coverage instead of a clean result', async () => {
  const report = await audit_project_dependencies(project([dep('alpha', '1.0.0')]), {
    fetch_impl: async () => { throw new Error('offline'); },
  });
  assert.equal(report.summary.status, 'partial');
  assert.equal(report.summary.complete, false);
  assert.equal(report.summary.query_failures, 1);
  assert.equal(report.packages[0].status, 'query-error');
  assert.ok(report.warnings.some(item => item.code === 'ORIX_OSV_QUERY_FAILED'));
});

test('OSV rejects malformed batch result shapes without inventing no-match status', async () => {
  const report = await audit_project_dependencies(project([dep('alpha', '1.0.0')]), {
    fetch_impl: async () => json_response({ results: [{ vulns: 'not-an-array' }] }),
  });
  assert.equal(report.summary.status, 'partial');
  assert.equal(report.packages[0].status, 'query-error');
  assert.ok(report.warnings.some(item => item.code === 'ORIX_OSV_PACKAGE_RESPONSE_INVALID'));
});

test('OSV reports pagination limits and keeps incomplete status explicit', async () => {
  const report = await audit_project_dependencies(project([dep('alpha', '1.0.0')]), {
    max_pages: 1,
    fetch_impl: async (url, init) => {
      if (String(url).endsWith('/querybatch')) {
        return json_response({ results: [{ vulns: [{ id: 'OSV-PAGED' }], next_page_token: 'next-page' }] });
      }
      return json_response(advisory('OSV-PAGED'));
    },
  });
  assert.equal(report.summary.complete, false);
  assert.equal(report.summary.status, 'partial');
  assert.ok(report.warnings.some(item => item.code === 'ORIX_OSV_PAGINATION_LIMIT'));
});

test('OSV handles empty and unsupported-only dependency inventories without querying', async () => {
  let calls = 0;
  const fetch_impl = async () => { calls += 1; throw new Error('should not be called'); };
  const empty = await audit_project_dependencies(project([]), { fetch_impl });
  assert.equal(empty.summary.status, 'empty');
  assert.equal(empty.summary.complete, true);
  const unsupported = await audit_project_dependencies(project([dep('local-lib', '1.0.0', 'custom')]), { fetch_impl });
  assert.equal(unsupported.summary.status, 'partial');
  assert.equal(unsupported.summary.unsupported_packages, 1);
  assert.equal(calls, 0);
});

test('OSV validates input, limits and oversized server responses', async () => {
  await assert.rejects(audit_project_dependencies({}), /orix.project.v1/);
  await assert.rejects(audit_project_dependencies(project([]), { max_packages: 0 }), /max_packages/);
  await assert.rejects(audit_project_dependencies(project([]), { timeout_ms: 100 }), /timeout_ms/);

  const report = await audit_project_dependencies(project([dep('alpha', '1.0.0')]), {
    fetch_impl: async () => new Response('{}', {
      status: 200,
      headers: { 'content-type': 'application/json', 'content-length': String(10 * 1024 * 1024) },
    }),
  });
  assert.equal(report.summary.complete, false);
  assert.equal(report.packages[0].status, 'query-error');
  assert.ok(report.warnings.some(item => item.code === 'ORIX_OSV_QUERY_FAILED'));
});

test('OSV requests are sent in bounded batches', async () => {
  const dependencies = Array.from({ length: OSV_QUERY_BATCH_SIZE + 1 }, (_, index) =>
    dep('package-' + index, '1.0.0')
  );
  const batch_sizes = [];
  const report = await audit_project_dependencies(project(dependencies), {
    fetch_impl: async url => {
      assert.ok(String(url).endsWith('/querybatch'));
      const body = JSON.parse(arguments[1]?.body ?? '{}');
      batch_sizes.push(body.queries.length);
      return json_response({ results: body.queries.map(() => ({ vulns: [] })) });
    },
  });
  assert.deepEqual(batch_sizes, [100, 1]);
  assert.equal(report.summary.queried_packages, OSV_QUERY_BATCH_SIZE + 1);
});
