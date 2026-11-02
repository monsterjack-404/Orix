// JavaScript, tests/sbom.test.mjs, Node.js 20+, CycloneDX 1.5 export contracts.

import test from 'node:test';
import assert from 'node:assert/strict';
import { render_cyclonedx } from '../src/reports/cyclonedx.mjs';

function project_report() {
  return {
    schema_version: 'orix.project.v1',
    project: { root: '/workspace/demo', name: 'demo', scanned_at: '2026-11-02T12:00:00.000Z' },
    manifests: [{ path: 'package.json', ecosystem: 'npm', name: 'demo-app', version: '1.2.3' }],
    dependencies: [
      { name: '@scope/core', version: '^2.1.0', ecosystem: 'npm', dependency_type: 'dependencies', manifest: 'package.json' },
      { name: 'jest', version: '^30.0.0', ecosystem: 'npm', dependency_type: 'devDependencies', manifest: 'package.json' },
      { name: 'requests', version: '2.31.0', ecosystem: 'pip', dependency_type: 'runtime', manifest: 'requirements.txt' },
      { name: 'org.example:codec', version: '4.0', ecosystem: 'maven', dependency_type: 'runtime', manifest: 'pom.xml' },
      { name: 'unknown-lib', version: '*', ecosystem: 'unknown', dependency_type: 'runtime', manifest: 'custom.txt' },
    ],
    files: [{ path: 'package.json', sha256: 'a'.repeat(64) }],
    coverage: { complete: true },
  };
}

test('CycloneDX export maps ecosystems to purls and preserves dependency provenance', () => {
  const bom = JSON.parse(render_cyclonedx(project_report()));
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.5');
  assert.match(bom.serialNumber, /^urn:uuid:/);
  assert.equal(bom.metadata.component.name, 'demo-app');
  assert.equal(bom.metadata.component.version, '1.2.3');
  assert.ok(bom.components.some(item => item.purl === 'pkg:npm/%40scope/core@%5E2.1.0'));
  assert.ok(bom.components.some(item => item.purl === 'pkg:pypi/requests@2.31.0'));
  assert.ok(bom.components.some(item => item.purl === 'pkg:maven/org/example/codec@4.0'));
  assert.equal(bom.components.find(item => item.name === 'jest').scope, 'optional');
  assert.equal(bom.components.some(item => item.name === 'unknown-lib'), false);
  assert.equal(bom.dependencies[0].dependsOn.length, 4);
  assert.equal(bom.properties.find(item => item.name === 'orix:transitive-resolution-performed').value, 'false');
});

test('CycloneDX output is stable for the same report and rejects non-project reports', () => {
  const report = project_report();
  assert.equal(render_cyclonedx(report), render_cyclonedx(report));
  assert.throws(() => render_cyclonedx({ schema_version: 'orix.scan.v1' }), /requires an ORIX project/);
});
