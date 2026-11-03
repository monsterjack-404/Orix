// JavaScript, tests/provider-manifest.test.mjs, Node.js 20+, provider contract and filesystem boundary tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  DEFAULT_PROVIDER_MANIFEST_LIMIT,
  parse_provider_manifest_json,
  read_provider_manifest,
  validate_provider_manifest,
} from '../src/providers/manifest.mjs';

function valid_manifest() {
  return {
    contract_version: 'orix.provider.v1',
    id: 'rizin.static',
    name: 'Rizin static analysis',
    version: '1.2.3',
    description: 'Read-only native binary metadata and disassembly provider.',
    capabilities: ['binary.headers', 'binary.disassembly'],
    supported_platforms: ['linux', 'windows', 'macos'],
    input_formats: ['pe', 'elf', 'macho', 'wasm'],
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
    license: {
      spdx_id: 'LGPL-3.0-only',
      redistribution: 'external-install',
      source_url: 'https://github.com/rizinorg/rizin',
    },
    documentation_url: 'https://rizin.re/',
  };
}

async function with_temp_directory(callback) {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-provider-test-'));
  try { await callback(directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

test('provider manifest validator normalizes and freezes a valid static provider', () => {
  const manifest = validate_provider_manifest(valid_manifest());
  assert.equal(manifest.contract_version, 'orix.provider.v1');
  assert.equal(manifest.id, 'rizin.static');
  assert.equal(manifest.execution.mode, 'static');
  assert.equal(Object.isFrozen(manifest), true);
  assert.equal(Object.isFrozen(manifest.capabilities), true);
});

test('provider manifest accepts an explicitly authorized dynamic provider', () => {
  const input = valid_manifest();
  input.id = 'frida.runtime';
  input.execution = {
    mode: 'dynamic',
    requires_authorization: true,
    executes_target: true,
    writes_target: false,
    uses_network: false,
  };
  const manifest = validate_provider_manifest(input);
  assert.equal(manifest.execution.executes_target, true);
  assert.equal(manifest.execution.requires_authorization, true);
});

test('provider manifest rejects target execution or network access without authorization', () => {
  const input = valid_manifest();
  input.execution.uses_network = true;
  assert.throws(
    () => validate_provider_manifest(input),
    error => error.code === 'ORIX_PROVIDER_MANIFEST_INVALID' && /require explicit authorization/.test(error.message),
  );
});

test('provider manifest rejects inconsistent static and network declarations', () => {
  const static_provider = valid_manifest();
  static_provider.execution.executes_target = true;
  static_provider.execution.requires_authorization = true;
  assert.throws(() => validate_provider_manifest(static_provider), /Static providers cannot declare/);

  const network_provider = valid_manifest();
  network_provider.execution.mode = 'network';
  assert.throws(() => validate_provider_manifest(network_provider), /must declare network access/);
});

test('provider manifest rejects malformed identifiers, versions, duplicate capabilities and unknown keys', () => {
  for (const mutate of [
    value => { value.id = '../escape'; },
    value => { value.version = 'latest'; },
    value => { value.capabilities = ['binary.scan', 'binary.scan']; },
    value => { value.unreviewed = true; },
  ]) {
    const input = valid_manifest();
    mutate(input);
    assert.throws(() => validate_provider_manifest(input), error => error.code === 'ORIX_PROVIDER_MANIFEST_INVALID');
  }
});

test('provider manifest rejects non-enumerable unknown fields and custom array properties', () => {
  const hidden = valid_manifest();
  Object.defineProperty(hidden, 'hidden_policy', { value: 'bypass', enumerable: false });
  assert.throws(() => validate_provider_manifest(hidden), /Unknown property/);

  const custom_array = valid_manifest();
  custom_array.capabilities.extra = 'unreviewed';
  assert.throws(() => validate_provider_manifest(custom_array), /Array custom properties/);
});

test('provider manifest array validation rejects sparse arrays and accessors without invoking getters', () => {
  const sparse = valid_manifest();
  sparse.capabilities = new Array(1);
  assert.throws(() => validate_provider_manifest(sparse), /Sparse arrays/);

  let getter_called = false;
  const accessor = valid_manifest();
  accessor.capabilities = [];
  Object.defineProperty(accessor.capabilities, '0', {
    enumerable: true,
    get() { getter_called = true; throw new Error('must not execute'); },
  });
  accessor.capabilities.length = 1;
  assert.throws(() => validate_provider_manifest(accessor), /Accessor elements/);
  assert.equal(getter_called, false);
});

test('provider manifest JSON parser enforces UTF-8 byte budget and JSON syntax', () => {
  const source = JSON.stringify(valid_manifest());
  assert.equal(parse_provider_manifest_json(source).id, 'rizin.static');
  assert.throws(
    () => parse_provider_manifest_json(source, { max_bytes: 8 }),
    error => error.code === 'ORIX_PROVIDER_MANIFEST_TOO_LARGE',
  );
  assert.throws(
    () => parse_provider_manifest_json('{broken'),
    error => error.code === 'ORIX_PROVIDER_MANIFEST_JSON',
  );
  assert.equal(DEFAULT_PROVIDER_MANIFEST_LIMIT, 65536);
});

test('provider manifest reader loads a bounded regular file without executing it', async () => {
  await with_temp_directory(async directory => {
    const manifest_path = path.join(directory, 'provider.json');
    await writeFile(manifest_path, JSON.stringify(valid_manifest()));
    const manifest = await read_provider_manifest(manifest_path);
    assert.equal(manifest.id, 'rizin.static');
    assert.equal((await readFile(manifest_path, 'utf8')).includes('rizin.static'), true);
  });
});

test('provider manifest reader rejects symlinks, directories and oversized files', async () => {
  await with_temp_directory(async directory => {
    const target = path.join(directory, 'target.json');
    const link = path.join(directory, 'link.json');
    await writeFile(target, JSON.stringify(valid_manifest()));
    await symlink(target, link);
    await assert.rejects(read_provider_manifest(link), error => error.code === 'ORIX_PROVIDER_MANIFEST_SYMLINK');
    await assert.rejects(read_provider_manifest(directory), error => error.code === 'ORIX_PROVIDER_MANIFEST_NOT_FILE');
    await assert.rejects(
      read_provider_manifest(target, { max_bytes: 16 }),
      error => error.code === 'ORIX_PROVIDER_MANIFEST_TOO_LARGE',
    );
  });
});
