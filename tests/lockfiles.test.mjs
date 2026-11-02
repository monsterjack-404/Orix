// JavaScript, tests/lockfiles.test.mjs, Node.js 20+, bounded npm and Yarn lockfile parser tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_lockfile } from '../src/project/lockfiles.mjs';

test('npm package-lock v3 indexes direct, nested and transitive packages with dependency edges', () => {
  const input = JSON.stringify({
    name: 'fixture', lockfileVersion: 3,
    packages: {
      '': { name: 'fixture', dependencies: { alpha: '^1.2.0', gamma: '^3.0.0' }, devDependencies: { gamma: '^3.0.0' } },
      'node_modules/alpha': { version: '1.2.0', dependencies: { beta: '^2.0.0' }, integrity: 'sha512-YQ==' },
      'node_modules/alpha/node_modules/beta': { version: '2.1.0' },
      'node_modules/gamma': { version: '3.0.0', dev: true },
      'node_modules/@scope/core': { version: '4.0.0' },
    },
  });
  const report = parse_lockfile('package-lock.json', input);
  assert.equal(report.lockfile_version, 3);
  assert.equal(report.packages.length, 4);
  assert.equal(report.packages.find(item => item.name === 'alpha').dependency_type, 'direct-or-hoisted');
  assert.equal(report.packages.find(item => item.name === 'beta').dependency_type, 'transitive');
  assert.equal(report.packages.find(item => item.name === '@scope/core').version, '4.0.0');
  assert.deepEqual(report.edges, [{
    from: 'node_modules/alpha', to: 'node_modules/alpha/node_modules/beta',
    name: 'beta', requirement: '^2.0.0', resolved_version: '2.1.0',
  }]);
  assert.equal(report.packages.find(item => item.name === 'alpha').integrity, 'sha512-YQ==');
  assert.deepEqual(report.root_edges.map(edge => edge.name).sort(), ['alpha', 'gamma']);
});

test('npm package-lock rejects malformed documents and bounds package count', () => {
  assert.throws(() => parse_lockfile('package-lock.json', '{broken'), error => error.code === 'ORIX_LOCKFILE_INVALID_JSON');
  const input = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/a': { version: '1.0.0' }, 'node_modules/b': { version: '1.0.0' } } });
  assert.throws(() => parse_lockfile('package-lock.json', input, { max_lockfile_packages: 1 }), error => error.code === 'ORIX_LOCKFILE_PACKAGE_LIMIT');
});

test('Yarn classic lock parser reads selectors, versions, integrity and dependency edges', () => {
  const input = [
    '# yarn lockfile v1',
    'alpha@^1.0.0:',
    '  version "1.2.0"',
    '  resolved "https://registry.yarnpkg.com/alpha/-/alpha-1.2.0.tgz"',
    '  integrity sha512-YQ==',
    '  dependencies:',
    '    beta "^2.0.0"',
    '',
    'beta@^2.0.0:',
    '  version "2.3.0"',
  ].join('\n');
  const report = parse_lockfile('yarn.lock', input);
  assert.equal(report.packages.length, 2);
  assert.equal(report.packages[0].name, 'alpha');
  assert.equal(report.packages[0].version, '1.2.0');
  assert.equal(report.edges.length, 1);
  assert.equal(report.edges[0].resolved_version, '2.3.0');
});

test('unsupported lockfile names are ignored and limits are validated', () => {
  assert.equal(parse_lockfile('pnpm-lock.yaml', 'lockfileVersion: 9'), null);
  assert.throws(() => parse_lockfile('package-lock.json', '{}', { max_lockfile_edges: 0 }), error => error.code === 'ORIX_LOCKFILE_BAD_LIMIT');
});


test('npm v1 lockfiles resolve nested requirements and root package edges', () => {
  const input = JSON.stringify({
    lockfileVersion: 1,
    dependencies: {
      alpha: { version: '1.0.0', requires: { beta: '^2.0.0' }, dependencies: { beta: { version: '2.4.0' } } },
    },
  });
  const report = parse_lockfile('package-lock.json', input);
  assert.equal(report.packages.length, 2);
  assert.equal(report.root_edges[0].to, 'node_modules/alpha');
  assert.ok(report.edges.some(edge => edge.name === 'beta' && edge.resolved_version === '2.4.0'));
});

test('Yarn Berry lockfiles skip metadata and parse resolution and colon fields', () => {
  const input = [
    '__metadata:',
    '  version: 8',
    '  cacheKey: 10c0',
    '',
    '"alpha@npm:^1.0.0":',
    '  version: 1.2.0',
    '  resolution: "alpha@npm:1.2.0"',
    '  checksum: abc123',
    '  dependencies:',
    '    beta: "npm:^2.0.0"',
    '',
    '"beta@npm:^2.0.0":',
    '  version: 2.3.0',
    '  resolution: "beta@npm:2.3.0"',
  ].join('\n');
  const report = parse_lockfile('yarn.lock', input);
  assert.equal(report.packages.length, 2);
  assert.equal(report.packages.find(item => item.name === 'alpha').version, '1.2.0');
  assert.equal(report.packages.find(item => item.name === 'alpha').integrity, 'abc123');
  assert.equal(report.edges.length, 1);
  assert.equal(report.edges[0].resolved_version, '2.3.0');
});


test('Cargo.lock resolves registry packages, checksums and workspace dependency edges', () => {
  const input = [
    'version = 4',
    '',
    '[[package]]',
    'name = "demo-app"',
    'version = "1.0.0"',
    'dependencies = [',
    ' "serde 1.0.200",',
    ']',
    '',
    '[[package]]',
    'name = "serde"',
    'version = "1.0.200"',
    'source = "registry+https://github.com/rust-lang/crates.io-index"',
    'checksum = "abc123"',
    'dependencies = [',
    ' "serde_core 1.0.200",',
    ']',
    '',
    '[[package]]',
    'name = "serde_core"',
    'version = "1.0.200"',
    'source = "registry+https://github.com/rust-lang/crates.io-index"',
    'checksum = "def456"',
  ].join('\n');
  const report = parse_lockfile('Cargo.lock', input);
  assert.equal(report.format, 'cargo-lock');
  assert.equal(report.lockfile_version, 4);
  assert.equal(report.packages.length, 2);
  assert.equal(report.root_edges.length, 1);
  assert.equal(report.root_edges[0].name, 'serde');
  assert.equal(report.edges.length, 1);
  assert.equal(report.edges[0].name, 'serde_core');
  assert.equal(report.edges[0].resolved_version, '1.0.200');
  assert.equal(report.packages.find(item => item.name === 'serde').integrity, 'abc123');
  assert.equal(report.complete, true);
});


test('pnpm v6 lockfile resolves nested package metadata and importer root edges', () => {
  const input = [
    "lockfileVersion: '6.0'",
    'importers:',
    '  .:',
    '    dependencies:',
    '      alpha:',
    '        specifier: ^1.0.0',
    '        version: 1.2.0',
    'packages:',
    '  /alpha/1.2.0:',
    '    resolution:',
    '      integrity: sha512-YQ==',
    '    dependencies:',
    '      beta: 2.3.0',
    '  /beta/2.3.0:',
    '    resolution: {integrity: sha512-ZA==}',
  ].join('\n');
  const report = parse_lockfile('pnpm-lock.yaml', input);
  assert.equal(report.format, 'pnpm-lock');
  assert.equal(report.lockfile_version, 6);
  assert.equal(report.packages.length, 2);
  assert.equal(report.root_edges.length, 1);
  assert.equal(report.root_edges[0].name, 'alpha');
  assert.equal(report.edges.length, 1);
  assert.equal(report.edges[0].resolved_version, '2.3.0');
  assert.equal(report.packages.find(item => item.name === 'alpha').integrity, 'sha512-YQ==');
  assert.equal(report.complete, true);
});

test('pnpm v9 lockfile merges package metadata with snapshot dependency edges', () => {
  const input = [
    "lockfileVersion: '9.0'",
    'importers:',
    '  .:',
    '    devDependencies:',
    '      alpha:',
    '        specifier: ^1.0.0',
    '        version: 1.2.0(peer@4.0.0)',
    'packages:',
    '  alpha@1.2.0(peer@4.0.0):',
    '    resolution: {integrity: sha512-YQ==}',
    '  beta@2.3.0:',
    '    resolution: {integrity: sha512-ZA==}',
    'snapshots:',
    '  alpha@1.2.0(peer@4.0.0):',
    '    dependencies:',
    '      beta: 2.3.0',
    '  beta@2.3.0:',
  ].join('\n');
  const report = parse_lockfile('pnpm-lock.yaml', input);
  assert.equal(report.lockfile_version, 9);
  assert.equal(report.packages.length, 2);
  assert.equal(report.root_edges.length, 1);
  assert.equal(report.root_edges[0].dependency_type, 'devDependencies');
  assert.equal(report.packages.find(item => item.name === 'alpha').dev, true);
  assert.equal(report.edges.length, 1);
  assert.equal(report.edges[0].resolved_version, '2.3.0');
  assert.equal(report.packages.find(item => item.name === 'alpha').peer, true);
});


test('pnpm v9 lockfile resolves importer and snapshot dependency edges', () => {
  const input = [
    "lockfileVersion: '9.0'",
    'importers:',
    '  .:',
    '    dependencies:',
    '      alpha:',
    '        specifier: ^1.0.0',
    '        version: 1.2.0',
    'packages:',
    '  alpha@1.2.0:',
    '    resolution:',
    '      integrity: sha512-alpha',
    '  beta@2.3.0:',
    '    resolution: {integrity: sha512-beta}',
    'snapshots:',
    '  alpha@1.2.0:',
    '    dependencies:',
    '      beta: 2.3.0',
    '  beta@2.3.0: {}',
  ].join('\\n');
  const report = parse_lockfile('pnpm-lock.yaml', input);
  assert.equal(report.format, 'pnpm-lock');
  assert.equal(report.lockfile_version, 9);
  assert.equal(report.packages.length, 2);
  assert.equal(report.root_edges.length, 1);
  assert.equal(report.root_edges[0].name, 'alpha');
  assert.equal(report.edges.length, 1);
  assert.equal(report.edges[0].name, 'beta');
  assert.equal(report.edges[0].resolved_version, '2.3.0');
  assert.equal(report.packages.find(item => item.name === 'alpha').integrity, 'sha512-alpha');
});

test('pnpm v6 lockfile reads legacy root dependency maps', () => {
  const input = [
    "lockfileVersion: '6.0'",
    'dependencies:',
    '  alpha:',
    '    specifier: ^1.0.0',
    '    version: 1.2.0',
    'packages:',
    '  /alpha@1.2.0:',
    '    resolution: {integrity: sha512-alpha}',
  ].join('\\n');
  const report = parse_lockfile('pnpm-lock.yaml', input);
  assert.equal(report.lockfile_version, 6);
  assert.equal(report.packages.length, 1);
  assert.equal(report.root_edges.length, 1);
  assert.equal(report.root_edges[0].to, '/alpha@1.2.0');
});
