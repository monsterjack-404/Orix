// JavaScript, tests/schema-contracts.test.mjs, Node.js 20+, public report schema smoke tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const schema_paths = [
  new URL('../schemas/artifact.v1.schema.json', import.meta.url),
  new URL('../schemas/scan.v1.schema.json', import.meta.url),
  new URL('../schemas/indicator.v1.schema.json', import.meta.url),
  new URL('../schemas/ledger.v1.schema.json', import.meta.url),
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
});
