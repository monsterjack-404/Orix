// JavaScript, tests/rizin-provider.test.mjs, Node.js 20+, Rizin adapter contract regressions.

import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { analyze_rizin_imports, analyze_rizin_functions, probe_rizin, RIZIN_PROVIDER_MANIFEST } from '../src/providers/rizin.mjs';

async function with_fixture(callback) {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-rizin-test-'));
  try {
    const input_path = path.join(directory, 'native input with spaces.bin');
    const executable = path.join(directory, 'rizin-stub');
    await writeFile(input_path, Buffer.from('fixture bytes'));
    const script = [
      '#!/bin/sh',
      'if [ "$1" = "-v" ]; then',
      '  printf "%s\\n" "rizin 0.8.2 0 @ test-build"',
      '  exit 0',
      'fi',
      'if [ "$1" = "-N" ] && [ "$3" = "-A" ] && [ "$5" = "aflj" ]; then',
      '  printf "%s" \'[{"offset":4198400,"name":"sym.main","size":40,"realsz":40,"bits":64,"type":"fcn","calltype":"amd64","nbbs":3,"edges":2,"nargs":1,"nlocals":2,"noreturn":false}]\'',
      '  exit 0',
      'fi',
      'if [ "$1" = "-N" ] && [ "$3" = "-c" ]; then',
      '  case "$4" in',
      '    pdj*) printf "%s" \'[{"offset":4198400,"size":5,"bytes":"554889e5","opcode":"push rbp","disasm":"push rbp","type":"push"},{"offset":4198401,"size":3,"bytes":"4889e5","opcode":"mov rbp, rsp","disasm":"mov rbp, rsp","type":"mov"},{"offset":4198404,"size":1,"bytes":"c3","opcode":"ret","disasm":"ret","type":"ret"}]\'; exit 0 ;;',
      '  esac',
      'fi',
      'if [ "$1" = "-N" ] && [ "$4" = "iij" ]; then',
      '  printf "%s" \'[{"name":"puts","libname":"libc.so.6","ordinal":1,"bind":"GLOBAL","type":"FUNC","plt":4096},{"name":"custom","library":"libdemo.so","ordinal":2,"bind":"WEAK","type":"FUNC","plt":"0x2000"}]\'',
      '  exit 0',
      'fi',
      'exit 64',
      '',
    ].join('\n');
    await writeFile(executable, script, { mode: 0o700 });
    await chmod(executable, 0o700);
    await callback({ directory, input_path, executable });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('Rizin adapter probes version and normalizes static import metadata through argv', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX executable fixture is used for the process adapter contract test');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
    const report = await analyze_rizin_imports({ input_path, executable });
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

test('Rizin function adapter returns a bounded function inventory and address-scoped disassembly', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX executable fixture is used for the process adapter contract test');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
    const report = await analyze_rizin_functions({
      input_path, executable, address: '0x401000', max_instructions: 3,
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
    assert.match(report.artifact.sha256, /^[a-f0-9]{64}$/);
    assert.ok(report.notes.some(note => /not decompiled source/.test(note)));
  });
});

test('Rizin function adapter refuses disassembly addresses that are not returned function entries', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX executable fixture is used for the process adapter contract test');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
    await assert.rejects(
      analyze_rizin_functions({ input_path, executable, address: '0x401001' }),
      error => error.code === 'ORIX_RIZIN_FUNCTION_NOT_FOUND',
    );
  });
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

test('Rizin adapter validates import limits before launching the external process', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX executable fixture is used for the process adapter contract test');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, max_imports: -1 }),
      /max_imports must be an integer/,
    );
  });
});

test('Rizin adapter reports malformed import JSON without accepting a partial result', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX executable fixture is used for the process adapter contract test');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
    const { writeFile: write } = await import('node:fs/promises');
    const script = [
      '#!/bin/sh',
      'if [ "$1" = "-v" ]; then printf "%s\\n" "rizin 0.8.2"; exit 0; fi',
      'printf "%s" "not-json"',
      '',
    ].join('\n');
    await write(executable, script, { mode: 0o700 });
    await chmod(executable, 0o700);
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable }),
      error => error.code === 'ORIX_RIZIN_IMPORT_JSON_INVALID',
    );
  });
});

test('Rizin adapter rejects input files exceeding provider byte ceiling', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX executable fixture is used for the process adapter contract test');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
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
      analyze_rizin_imports({ input_path, executable, manifest }),
      error => error.code === 'ORIX_RIZIN_INPUT_TOO_LARGE',
    );
  });
});


test('Rizin adapter enforces the import result ceiling without returning partial imports', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX executable fixture is used for the process adapter contract test');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, max_imports: 1 }),
      error => error.code === 'ORIX_RIZIN_IMPORT_LIMIT',
    );
  });
});

test('Rizin adapter applies one total timeout across version and import probes', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX process-group termination is tested on Unix runners');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
    const script = [
      '#!/bin/sh',
      'if [ "$1" = "-v" ]; then printf "%s\\n" "rizin 0.8.2"; exit 0; fi',
      'if [ "$1" = "-N" ] && [ "$4" = "iij" ]; then /bin/sleep 5; exit 0; fi',
      'exit 64',
      '',
    ].join('\n');
    await writeFile(executable, script, { mode: 0o700 });
    await chmod(executable, 0o700);
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable, timeout_ms: 500 }),
      error => error.code === 'ORIX_RIZIN_TIMEOUT',
    );
  });
});

test('Rizin adapter isolates the original artifact and discards results if a provider mutates its snapshot', async context => {
  if (process.platform === 'win32') {
    context.skip('POSIX executable fixture is used for the process adapter contract test');
    return;
  }
  await with_fixture(async ({ input_path, executable }) => {
    const original = await import('node:fs/promises').then(fs => fs.readFile(input_path));
    const script = [
      '#!/bin/sh',
      'if [ "$1" = "-v" ]; then printf "%s\\n" "rizin 0.8.2"; exit 0; fi',
      'if [ "$1" = "-N" ] && [ "$4" = "iij" ]; then',
      '  /bin/chmod u+w "$5"',
      '  printf "%s" "provider-mutated-snapshot" > "$5"',
      '  printf "%s" "[]"',
      '  exit 0',
      'fi',
      'exit 64',
      '',
    ].join('\n');
    await writeFile(executable, script, { mode: 0o700 });
    await chmod(executable, 0o700);
    await assert.rejects(
      analyze_rizin_imports({ input_path, executable }),
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
