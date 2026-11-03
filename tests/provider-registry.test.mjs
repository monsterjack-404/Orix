// JavaScript, tests/provider-registry.test.mjs, Node.js 20+, provider registry behavior.

import test from 'node:test';
import assert from 'node:assert/strict';
import { ProviderRegistry } from '../src/providers/registry.mjs';

function provider(overrides = {}) {
  return {
    contract_version: 'orix.provider.v1',
    id: 'rizin.static',
    name: 'Rizin static analysis',
    version: '1.2.3',
    description: 'Read-only binary analysis provider.',
    capabilities: ['binary.headers', 'binary.disassembly'],
    supported_platforms: ['linux', 'windows'],
    input_formats: ['pe', 'elf'],
    execution: {
      mode: 'static',
      requires_authorization: false,
      executes_target: false,
      writes_target: false,
      uses_network: false,
    },
    limits: {
      timeout_ms: 30000,
      max_input_bytes: 134217728,
      max_output_bytes: 16777216,
    },
    license: { spdx_id: 'LGPL-3.0-only', redistribution: 'external-install' },
    ...overrides,
  };
}

test('provider registry validates, stores and returns immutable manifests', () => {
  const registry = new ProviderRegistry({ platform: 'linux' });
  const registered = registry.register(provider());
  assert.equal(registry.size, 1);
  assert.equal(registry.get('rizin.static').id, 'rizin.static');
  assert.equal(Object.isFrozen(registered), true);
  assert.equal(Object.isFrozen(registry.get('rizin.static').execution), true);
});

test('provider registry rejects duplicate identifiers without replacing the original', () => {
  const registry = new ProviderRegistry({ platform: 'linux' });
  registry.register(provider());
  assert.throws(
    () => registry.register(provider({ name: 'Replacement provider' })),
    error => error.code === 'ORIX_PROVIDER_DUPLICATE',
  );
  assert.equal(registry.get('rizin.static').name, 'Rizin static analysis');
});

test('provider registry filters by capability, format and platform deterministically', () => {
  const registry = new ProviderRegistry({ platform: 'linux' });
  registry.register(provider());
  registry.register(provider({
    id: 'ghidra.headless',
    name: 'Ghidra headless',
    capabilities: ['binary.decompile'],
    supported_platforms: ['windows', 'macos'],
    input_formats: ['pe', 'elf', 'macho'],
  }));
  registry.register(provider({
    id: 'universal.static',
    name: 'Universal metadata provider',
    capabilities: ['binary.headers'],
    supported_platforms: ['any'],
    input_formats: ['pe'],
  }));

  assert.deepEqual(registry.list({ capability: 'binary.headers' }).map(item => item.id), ['rizin.static', 'universal.static']);
  assert.deepEqual(registry.list({ input_format: 'macho' }).map(item => item.id), []);
  assert.deepEqual(registry.list({ platform: 'windows' }).map(item => item.id), ['ghidra.headless', 'rizin.static', 'universal.static']);
  assert.deepEqual(registry.list({ platform: 'any' }).map(item => item.id), ['ghidra.headless', 'rizin.static', 'universal.static']);
});

test('provider registry snapshot records metadata only and is immutable', () => {
  const registry = new ProviderRegistry({ platform: 'macos' });
  registry.register(provider({ supported_platforms: ['macos'] }));
  const snapshot = registry.snapshot();
  assert.equal(snapshot.schema_version, 'orix.provider-registry.v1');
  assert.equal(snapshot.provider_count, 1);
  assert.equal(snapshot.providers[0].id, 'rizin.static');
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.providers), true);
});

test('provider registry validates platform and query filters', () => {
  assert.throws(() => new ProviderRegistry({ platform: 'freebsd' }), /platform must be/);
  const registry = new ProviderRegistry({ platform: 'linux' });
  assert.throws(() => registry.list({ capability: '../escape' }), /capability is not a valid/);
  assert.throws(() => registry.list({ input_format: '../escape' }), /input_format is not a valid/);
  assert.throws(() => registry.list({ platform: 'freebsd' }), /platform must be/);
  assert.throws(() => registry.list(null), /filters must be an object/);
  assert.throws(() => registry.list({ unreviewed: true }), /Unknown provider registry filter/);
  let getter_called = false;
  const accessor = {};
  Object.defineProperty(accessor, 'capability', {
    enumerable: true,
    get() { getter_called = true; throw new Error('must not execute'); },
  });
  assert.throws(() => registry.list(accessor), /data properties/);
  assert.equal(getter_called, false);
});

test('provider registry unregisters without executing provider code', () => {
  const registry = new ProviderRegistry({ platform: 'linux' });
  registry.register(provider());
  assert.equal(registry.unregister('rizin.static'), true);
  assert.equal(registry.unregister('rizin.static'), false);
  assert.equal(registry.get('rizin.static'), null);
  assert.equal(registry.size, 0);
});
