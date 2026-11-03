// JavaScript, tests/provider-public-api.test.mjs, Node.js 20+, provider API export contracts.

import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../src/index.mjs';

test('public API exports provider metadata, registry, runner and Rizin adapter', () => {
  assert.equal(api.PROVIDER_CONTRACT_VERSION, 'orix.provider.v1');
  assert.equal(typeof api.validate_provider_manifest, 'function');
  assert.equal(typeof api.read_provider_manifest, 'function');
  assert.equal(typeof api.ProviderRegistry, 'function');
  assert.equal(typeof api.run_static_provider, 'function');
  assert.equal(typeof api.analyze_rizin_imports, 'function');
  assert.equal(api.RIZIN_PROVIDER_MANIFEST.id, 'rizin.static');
  assert.equal(api.RIZIN_ADAPTER_VERSION, '0.1.0');
});
