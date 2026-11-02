// JavaScript, tests/lockfiles.test.mjs, Node.js 20+, bounded npm and Yarn lockfile parser tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_lockfile } from '../src/project/lockfiles.mjs';

test('npm package-lock v3 indexes direct, nested and transitive packages with dependency edges', () => {
  const input = JSON.stringify({
    name: 'fixture', lockfileVersion: 3,
    packages: {
      '': { name: 'fixture' },
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
