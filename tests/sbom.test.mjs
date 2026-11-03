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
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(bom.metadata.component.name, 'demo-app');
  assert.equal(bom.metadata.component.version, '1.2.3');
  assert.ok(bom.components.some(item => item.purl === 'pkg:npm/%40scope/core'));
  assert.ok(bom.components.some(item => item.purl === 'pkg:pypi/requests@2.31.0'));
  assert.equal(bom.components.find(item => item.name === '@scope/core').version, undefined);
  assert.ok(bom.components.find(item => item.name === '@scope/core').properties.some(item => item.name === 'orix:declared-version' && item.value === '^2.1.0'));
  assert.deepEqual(bom.metadata.tools[0], { vendor: 'ORIX', name: 'ORIX', version: '0.5.0' });
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


test('CycloneDX exports locked transitive components and actual dependency relationships', () => {
  const report = project_report();
  report.lockfiles = [{
    path: 'package-lock.json',
    ecosystem: 'npm',
    packages: [
      { name: 'alpha', version: '1.2.0', ecosystem: 'npm', location: 'node_modules/alpha', dependency_type: 'direct-or-hoisted', manifest: 'package-lock.json', integrity: 'sha512-YQ==' },
      { name: 'beta', version: '2.3.0', ecosystem: 'npm', location: 'node_modules/alpha/node_modules/beta', dependency_type: 'transitive', manifest: 'package-lock.json' },
    ],
    edges: [{ from: 'node_modules/alpha', to: 'node_modules/alpha/node_modules/beta', name: 'beta', requirement: '^2.0.0', resolved_version: '2.3.0' }],
    root_edges: [{ name: 'alpha', to: 'node_modules/alpha', resolved_version: '1.2.0' }],
  }];
  const bom = JSON.parse(render_cyclonedx(report));
  assert.ok(bom.components.some(item => item.purl === 'pkg:npm/alpha@1.2.0'));
  assert.ok(bom.components.some(item => item.purl === 'pkg:npm/beta@2.3.0'));
  const root = bom.dependencies.find(item => item.ref === bom.metadata.component['bom-ref']);
  assert.deepEqual(root.dependsOn, ['pkg:npm/alpha@1.2.0']);
  const alpha = bom.dependencies.find(item => item.ref === 'pkg:npm/alpha@1.2.0');
  assert.deepEqual(alpha.dependsOn, ['pkg:npm/beta@2.3.0']);
  assert.ok(bom.components.find(item => item.name === 'alpha').properties.some(item => item.name === 'orix:integrity' && item.value === 'sha512-YQ=='));
});


test('CycloneDX export uses exact locked npm versions and preserves package dependency edges', () => {
  const report = project_report();
  report.lockfiles = [{
    path: 'package-lock.json',
    ecosystem: 'npm',
    format: 'npm-package-lock',
    complete: true,
    packages: [
      { name: 'alpha', version: '1.2.0', ecosystem: 'npm', location: 'node_modules/alpha', dependency_type: 'direct-or-hoisted', integrity: 'sha512-YQ==' },
      { name: 'beta', version: '2.3.0', ecosystem: 'npm', location: 'node_modules/alpha/node_modules/beta', dependency_type: 'transitive' },
    ],
    edges: [{ from: 'node_modules/alpha', to: 'node_modules/alpha/node_modules/beta', name: 'beta', requirement: '^2', resolved_version: '2.3.0' }],
    root_edges: [{ name: 'alpha', to: 'node_modules/alpha', resolved_version: '1.2.0' }],
  }];
  const bom = JSON.parse(render_cyclonedx(report));
  assert.ok(bom.components.some(item => item.purl === 'pkg:npm/alpha@1.2.0'));
  assert.ok(bom.components.some(item => item.purl === 'pkg:npm/beta@2.3.0'));
  const alpha = bom.dependencies.find(item => item.ref === 'pkg:npm/alpha@1.2.0');
  assert.deepEqual(alpha.dependsOn, ['pkg:npm/beta@2.3.0']);
  const root = bom.dependencies.find(item => item.ref === bom.metadata.component['bom-ref']);
  assert.deepEqual(root.dependsOn, ['pkg:npm/alpha@1.2.0']);
  assert.equal(bom.properties.find(item => item.name === 'orix:transitive-resolution-performed').value, 'true');
  for (const component of bom.components) assert.ok(bom.dependencies.some(item => item.ref === component['bom-ref']));
});


test('CycloneDX maps pnpm lockfile packages to npm purls and preserves development scope', () => {
  const report = project_report();
  report.lockfiles = [{
    path: 'pnpm-lock.yaml',
    ecosystem: 'pnpm',
    packages: [{
      name: 'alpha', version: '1.2.0', ecosystem: 'pnpm',
      location: 'alpha@1.2.0', dependency_type: 'resolved',
      manifest: 'pnpm-lock.yaml', dev: true, optional: false,
    }],
    edges: [],
    root_edges: [{ name: 'alpha', to: 'alpha@1.2.0', dependency_type: 'devDependencies' }],
  }];
  const bom = JSON.parse(render_cyclonedx(report));
  const component = bom.components.find(item => item.name === 'alpha');
  assert.equal(component.purl, 'pkg:npm/alpha@1.2.0');
  assert.equal(component.scope, 'optional');
  assert.ok(bom.dependencies.find(item => item.ref === bom.metadata.component['bom-ref']).dependsOn.includes(component['bom-ref']));
});


test('CycloneDX exports Go module purls and checksum provenance', () => {
  const report = project_report();
  report.lockfiles = [{
    path: 'go.sum',
    ecosystem: 'go',
    packages: [{
      name: 'github.com/acme/direct', version: 'v1.2.3', ecosystem: 'go',
      location: 'github.com/acme/direct@v1.2.3', dependency_type: 'resolved',
      manifest: 'go.sum', integrity: 'h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      checksum_kind: 'module',
    }],
    edges: [],
    root_edges: [{ name: 'github.com/acme/direct', to: 'github.com/acme/direct@v1.2.3' }],
  }];
  const bom = JSON.parse(render_cyclonedx(report));
  const component = bom.components.find(item => item.name === 'github.com/acme/direct');
  assert.equal(component.purl, 'pkg:golang/github.com/acme/direct@v1.2.3');
  assert.ok(component.properties.some(item => item.name === 'orix:checksum-kind' && item.value === 'module'));
});


test('CycloneDX does not claim transitive resolution for Pipfile.lock inventories', () => {
  const report = project_report();
  report.lockfiles = [{
    path: 'Pipfile.lock',
    ecosystem: 'python',
    format: 'pipfile-lock',
    complete: false,
    packages: [{ name: 'requests', version: '2.31.0', ecosystem: 'python', location: 'requests@2.31.0', dev: false }],
    edges: [],
    root_edges: [{ name: 'requests', to: 'requests@2.31.0' }],
  }];
  const bom = JSON.parse(render_cyclonedx(report));
  assert.equal(bom.properties.find(item => item.name === 'orix:lockfile-graph-complete').value, 'false');
  assert.equal(bom.properties.find(item => item.name === 'orix:transitive-resolution-performed').value, 'false');
  assert.ok(bom.dependencies.some(item => item.ref === 'pkg:pypi/requests@2.31.0'));
});
