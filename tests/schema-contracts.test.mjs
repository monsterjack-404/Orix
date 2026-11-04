// JavaScript, tests/schema-contracts.test.mjs, Node.js 20+, public report schema smoke tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const schema_paths = [
  new URL('../schemas/artifact.v1.schema.json', import.meta.url),
  new URL('../schemas/scan.v1.schema.json', import.meta.url),
  new URL('../schemas/indicator.v1.schema.json', import.meta.url),
  new URL('../schemas/ledger.v1.schema.json', import.meta.url),
  new URL('../schemas/comparison.v1.schema.json', import.meta.url),
  new URL('../schemas/project.v1.schema.json', import.meta.url),
  new URL('../schemas/provider-manifest.v1.schema.json', import.meta.url),
  new URL('../schemas/rizin-imports.v1.schema.json', import.meta.url),
  new URL('../schemas/provider-execution.v1.schema.json', import.meta.url),
  new URL('../schemas/provider-probe.v1.schema.json', import.meta.url),
  new URL('../schemas/vulnerability-audit.v1.schema.json', import.meta.url),
];

test('public JSON Schemas are valid JSON and use Draft 2020-12', async () => {
  const schemas = await Promise.all(schema_paths.map(async url => JSON.parse(await readFile(url, 'utf8'))));
  for (const schema of schemas.slice(0, 3)) {
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.equal(schema.type, 'object');
    assert.ok(Array.isArray(schema.required));
    assert.ok(schema.required.length > 0);
    assert.equal(schema.additionalProperties, true);
  }
  assert.equal(schemas[0].properties.schema_version.const, 'orix.artifact.v1');
  assert.equal(schemas[1].properties.schema_version.const, 'orix.scan.v1');
  assert.ok(schemas[2].properties.severity.enum.includes('high'));
  assert.equal(schemas[3].additionalProperties, false);
  assert.equal(schemas[3].properties.format.const, 'orix.evidence-ledger.v1');
  assert.ok(schemas[3].required.includes('previous_hash'));
  assert.ok(schemas[3].required.includes('hash'));
  assert.equal(schemas[4].properties.schema_version.const, 'orix.comparison.v1');
  assert.equal(schemas[4].additionalProperties, false);
  assert.equal(schemas[5].properties.schema_version.const, 'orix.project.v1');
  assert.ok(schemas[5].required.includes('lockfiles'));
  assert.ok(schemas[5].properties.summary.required.includes('locked_packages'));
  assert.equal(schemas[6].properties.contract_version.const, 'orix.provider.v1');
  assert.equal(schemas[6].additionalProperties, false);
  assert.ok(schemas[6].properties.execution.required.includes('requires_authorization'));
  assert.ok(schemas[6].properties.limits.required.includes('timeout_ms'));
  assert.ok(schemas[6].properties.license.properties.redistribution.enum.includes('proprietary'));
  assert.equal(schemas[7].properties.schema_version.const, 'orix.rizin-imports.v1');
  assert.equal(schemas[7].properties.provider.properties.id.const, 'rizin.static');
  assert.ok(schemas[7].required.includes('artifact'));
  assert.ok(schemas[7].properties.artifact.properties.sha256.pattern.includes('a-f'));
  assert.equal(schemas[8].properties.schema_version.const, 'orix.provider-execution.v1');
  assert.equal(schemas[8].additionalProperties, false);
  assert.ok(schemas[8].required.includes('termination_reason'));
  assert.ok(schemas[8].properties.output.required.includes('bytes_captured'));
  assert.ok(schemas[8].properties.limits.required.includes('kill_grace_ms'));
  assert.equal(schemas[9].properties.schema_version.const, 'orix.provider-probe.v1');
  assert.equal(schemas[9].properties.provider.properties.id.const, 'rizin.static');
  assert.equal(schemas[9].properties.status.const, 'available');
  assert.equal(schemas[10].properties.schema_version.const, 'orix.vulnerability-audit.v1');
  assert.equal(schemas[10].properties.source.properties.source_files_uploaded.const, false);
  assert.equal(schemas[10].properties.summary.properties.status.enum.includes('partial'), true);
  assert.ok(schemas[10].properties.packages.items.properties.vulnerability_ids);
  assert.ok(schemas[10].required.includes('unsupported_packages'));
});
