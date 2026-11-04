// JavaScript, tests/rizin-provider.test.mjs, Node.js 20+, Rizin adapter contract regressions.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze_rizin_imports, analyze_rizin_functions, probe_rizin, RIZIN_PROVIDER_MANIFEST } from '../src/providers/rizin.mjs';

const RIZIN_STUB = fileURLToPath(new URL('./fixtures/rizin-stub.mjs', import.meta.url));

async function with_fixture(callback) {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-rizin-test-'));
  try {
    const input_path = path.join(directory, 'native input with spaces.bin');
    const config_path = path.join(directory, 'rizin-stub-config.json');
    await writeFile(input_path, Buffer.from('fixture bytes'));
    await writeFile(config_path, '{}');
    const executable = await realpath(process.execPath);
    const executable_args = [RIZIN_STUB, config_path];
    const write_config = async config => writeFile(config_path, JSON.stringify(config));
    await callback({ directory, input_path, executable, executable_args, write_config });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('Rizin adapter probes version and normalizes static import metadata through argv', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    const report = await analyze_rizin_imports({ input_path, executable, executable_args });
    assert.equal(report.schema_version, 'orix.rizin-imports.v1');
    assert.equal(report.provider.id, 'rizin.static');
    assert.equal(report.provider.engine_version, '0.8.2');
    assert.match(report.artifact.sha256, /^[a-f0-9]{64}$/);
    assert.equal(report.artifact.stable_during_analysis, true);
    assert.deepEqual(report.summary, { imports: 2, libraries: 2 });
    assert.deepEqual(report.imports[0], {
      name: 'puts',
      library: 'libc.so.6',
      ordinal: 1,
      bind: 'GLOBAL',
      type: 'FUNC',
      plt: 4096,
    });
    assert.equal(report.imports[1].library, 'libdemo.so');
    assert.equal(report.imports[1].plt, '0x2000');
    assert.ok(report.notes.some(note => /not an OS sandbox/.test(note)));
  });
});

test('Rizin function adapter returns a bounded function inventory and address-scoped disassembly', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    const report = await analyze_rizin_functions({
      input_path, executable, executable_args, address: '0x401000', max_instructions: 3, decompile: true,
    });
    assert.equal(report.schema_version, 'orix.rizin-functions.v1');
    assert.equal(report.provider.engine_version, '0.8.2');
    assert.equal(report.functions.length, 1);
    assert.deepEqual(report.functions[0], {
      name: 'sym.main',
      offset: 4198400,
      size: 40,
      real_size: 40,
      bits: 64,
      type: 'fcn',
      call_type: 'amd64',
      signature: null,
      basic_blocks: 3,
      edges: 2,
      arguments: 1,
      locals: 2,
      no_return: false,
    });
    assert.equal(report.disassembly.address, 4198400);
    assert.equal(report.disassembly.instructions.length, 3);
    assert.equal(report.disassembly.instructions[0].disassembly, 'push rbp');
    assert.equal(report.disassembly.instruction_limit_reached, true);
    assert.equal(report.summary.disassembly_included, true);
    assert.equal(report.summary.decompilation_included, true);
    assert.equal(report.decompilation.backend, 'rizin-pdg');
    assert.match(report.decompilation.source, /int main/);
    assert.match(report.artifact.sha256, /^[a-f0-9]{64}$/);
    assert.ok(report.notes.some(note => /not decompiled source/.test(note)));
  });
});

test('Rizin function adapter refuses disassembly addresses that are not returned function entries', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    await assert.rejects(
      analyze_rizin_functions({ input_path, executable, executable_args, address: '0x401001' }),
      error => error.code === 'ORIX_RIZIN_FUNCTION_NOT_FOUND',
    );
  });
});

test('Rizin decompilation requires an exact function-entry address', async () => {
  await assert.rejects(
    analyze_rizin_functions({ input_path: '/not/opened/file', executable: '/not/launched/rizin', decompile: true }),
    /decompile requires an exact function-entry address/,
  );
});

test('Rizin function adapter validates result budgets and hexadecimal addresses before launching a provider', async () => {
  await assert.rejects(
    analyze_rizin_functions({ input_path: '/not/opened/file', executable: '/not/launched/rizin', max_instructions: 1001 }),
    /max_instructions must be an integer/,
  );
  await assert.rejects(
    analyze_rizin_functions({ input_path: '/not/opened/file', executable: '/not/launched/rizin', address: '0xnot-hex' }),
    /address must be a non-negative safe integer/,
  );
});

test('Rizin adapter rejects a missing or non-absolute input before launching a provider', async () => {
  await assert.rejects(
    analyze_rizin_imports({ input_path: 'relative.bin', executable: '/bin/false' }),
    /absolute filesystem path/,
  );
});

test('Rizin adapter validates import limits before launching the external process', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, executable_args, max_imports: -1 }),
      /max_imports must be an integer/,
    );
  });
});

test('Rizin adapter reports malformed import JSON without accepting a partial result', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    await write_config({ import_output: 'not-json' });
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, executable_args }),
      error => error.code === 'ORIX_RIZIN_IMPORT_JSON_INVALID',
    );
  });
});

test('Rizin adapter rejects input files exceeding provider byte ceiling', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    const manifest = {
      contract_version: 'orix.provider.v1',
      id: 'rizin.static',
      name: 'Rizin static binary imports',
      version: '0.1.0',
      description: 'Test manifest.',
      capabilities: ['binary.imports'],
      supported_platforms: ['linux', 'windows', 'macos'],
      input_formats: ['pe', 'elf', 'macho'],
      execution: {
        mode: 'static',
        requires_authorization: false,
        executes_target: false,
        writes_target: false,
        uses_network: false,
      },
      limits: { timeout_ms: 1000, max_input_bytes: 4, max_output_bytes: 1024 },
      license: { spdx_id: 'LGPL-3.0-only', redistribution: 'external-install' },
    };
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, executable_args, manifest }),
      error => error.code === 'ORIX_RIZIN_INPUT_TOO_LARGE',
    );
  });
});


test('Rizin adapter enforces the import result ceiling without returning partial imports', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, executable_args, max_imports: 1 }),
      error => error.code === 'ORIX_RIZIN_IMPORT_LIMIT',
    );
  });
});

test('Rizin adapter applies one total timeout across version and import probes', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    await write_config({ delay_import_ms: 5000 });
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, executable_args, timeout_ms: 500 }),
      error => error.code === 'ORIX_RIZIN_TIMEOUT',
    );
  });
});

test('Rizin adapter isolates the original artifact and discards results if a provider mutates its snapshot', async () => {
  await with_fixture(async ({ input_path, executable, executable_args, write_config }) => {
    const original = await import('node:fs/promises').then(fs => fs.readFile(input_path));
    await write_config({ mutate_snapshot: true });
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, executable_args }),
      error => error.code === 'ORIX_RIZIN_SNAPSHOT_CHANGED',
    );
    const after = await import('node:fs/promises').then(fs => fs.readFile(input_path));
    assert.deepEqual(after, original);
  });
});

test('Rizin adapter and doctor reject manifests that exclude the current runtime platform', async () => {
  const current = process.platform === 'win32'
    ? 'windows'
    : process.platform === 'darwin' ? 'macos' : process.platform;
  const unsupported = current === 'windows' ? 'linux' : 'windows';
  const manifest = { ...RIZIN_PROVIDER_MANIFEST, supported_platforms: [unsupported] };
  await assert.rejects(
    probe_rizin({ executable: '/not/started/rizin', manifest }),
    error => error.code === 'ORIX_RIZIN_PLATFORM_UNSUPPORTED',
  );
  await assert.rejects(
    analyze_rizin_imports({ input_path: '/not/opened/sample.elf', executable: '/not/started/rizin', manifest }),
    error => error.code === 'ORIX_RIZIN_PLATFORM_UNSUPPORTED',
  );
});
