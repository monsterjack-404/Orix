// JavaScript, tests/providers-cli.test.mjs, Node.js 20+, provider CLI contract tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from '../src/cli/main.mjs';
import { parse_arguments } from '../src/cli/arguments.mjs';
import { HELP_TEXT } from '../src/cli/help.mjs';
import { render_rizin_imports_markdown, render_rizin_functions_markdown } from '../src/reports/rizin.mjs';

const RIZIN_STUB = fileURLToPath(new URL('./fixtures/rizin-stub.mjs', import.meta.url));

async function with_fixture(callback) {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-provider-cli-'));
  try {
    const config_path = path.join(directory, 'rizin-stub-config.json');
    const input = path.join(directory, 'sample with spaces.elf');
    await writeFile(input, Buffer.from('ELF fixture'));
    await writeFile(config_path, '{}');
    const executable = process.execPath;
    const executable_args = [RIZIN_STUB, config_path];
    await callback({ directory, executable, executable_args, input });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('provider CLI parser accepts list and Rizin import operations', () => {
  const listing = parse_arguments(['providers', 'list', '--json']);
  assert.equal(listing.command, 'providers');
  assert.equal(listing.provider_action, 'list');
  assert.equal(listing.flags.format, 'json');

  const doctor = parse_arguments(['providers', 'rizin', 'doctor', '--executable', '/opt/rizin/bin/rizin', '--json']);
  assert.equal(doctor.provider_action, 'doctor');
  assert.equal(doctor.target, null);
  assert.equal(doctor.flags.provider_executable, '/opt/rizin/bin/rizin');

  const invocation = parse_arguments([
    'providers', 'rizin', 'imports', './sample.elf',
    '--executable', '/opt/rizin/bin/rizin',
    '--timeout-ms', '12000',
    '--max-output-kib', '2048',
    '--max-imports', '25000',
    '--json',
  ]);
  assert.equal(invocation.provider_action, 'imports');
  assert.equal(invocation.target, './sample.elf');
  assert.equal(invocation.flags.provider_executable, '/opt/rizin/bin/rizin');
  assert.equal(invocation.flags.timeout_ms, 12000);
  assert.equal(invocation.flags.max_output_bytes, 2 * 1024 * 1024);
  assert.equal(invocation.flags.max_imports, 25000);
  assert.equal(invocation.flags.format, 'json');
});

test('provider CLI parser accepts bounded Rizin function and disassembly options', () => {
  const parsed = parse_arguments([
    'providers', 'rizin', 'functions', './sample.elf',
    '--executable', '/opt/rizin/bin/rizin',
    '--max-functions', '4000',
    '--address', '0x401000',
    '--max-instructions', '75',
    '--decompile',
    '--json',
  ]);
  assert.equal(parsed.provider_action, 'functions');
  assert.equal(parsed.target, './sample.elf');
  assert.equal(parsed.flags.max_functions, 4000);
  assert.equal(parsed.flags.rizin_address, '0x401000');
  assert.equal(parsed.flags.max_instructions, 75);
  assert.equal(parsed.flags.rizin_decompile, true);
});

test('provider CLI parser rejects unknown actions and missing Rizin input', () => {
  assert.throws(
    () => parse_arguments(['providers', 'rizin', 'decompile', './a']),
    error => error.code === 'ORIX_CLI_PROVIDER_ACTION',
  );
  assert.throws(
    () => parse_arguments(['providers', 'rizin', 'imports']),
    error => error.code === 'ORIX_CLI_PROVIDER_INPUT',
  );
  assert.throws(
    () => parse_arguments(['providers', 'ghidra']),
    error => error.code === 'ORIX_CLI_PROVIDER_UNKNOWN',
  );
  assert.throws(
    () => parse_arguments(['providers', 'list', 'unexpected']),
    error => error.code === 'ORIX_CLI_PROVIDER_ARGUMENTS',
  );
});

test('providers list creates a report without probing or requiring an external installation', async () => {
  await with_fixture(async ({ directory }) => {
    const output = path.join(directory, 'providers.json');
    const exit_code = await main(['providers', 'list', '--out', output]);
    assert.equal(exit_code, 0);
    const report = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(report.schema_version, 'orix.providers.v1');
    assert.equal(report.providers.length, 1);
    assert.equal(report.providers[0].id, 'rizin.static');
    assert.equal(report.providers[0].availability, 'external-install-not-probed');
  });
});

test('providers rizin imports writes the actual normalized JSON report', async () => {
  await with_fixture(async ({ directory, executable, executable_args, input }) => {
    const output = path.join(directory, 'rizin-imports.json');
    const exit_code = await main([
      'providers', 'rizin', 'imports', input,
      '--executable', executable,
      ...executable_args.flatMap(argument => ['--executable-arg', argument]),
      '--format', 'json',
      '--out', output,
    ]);
    assert.equal(exit_code, 0);
    const report = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(report.schema_version, 'orix.rizin-imports.v1');
    assert.equal(report.imports[0].name, 'open');
    assert.equal(report.imports[0].library, 'libc.so.6');
    assert.match(report.artifact.sha256, /^[a-f0-9]{64}$/);
  });
});

test('providers rizin functions writes the actual bounded function/disassembly report', async () => {
  await with_fixture(async ({ directory, executable, executable_args, input }) => {
    const output = path.join(directory, 'rizin-functions.json');
    const exit_code = await main([
      'providers', 'rizin', 'functions', input,
      '--executable', executable,
      ...executable_args.flatMap(argument => ['--executable-arg', argument]),
      '--address', '0x401000',
      '--max-instructions', '1',
      '--decompile',
      '--format', 'json',
      '--out', output,
    ]);
    assert.equal(exit_code, 0);
    const report = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(report.schema_version, 'orix.rizin-functions.v1');
    assert.equal(report.functions[0].name, 'sym.main');
    assert.equal(report.disassembly.instructions[0].disassembly, 'push rbp');
    assert.match(report.decompilation.source, /int main/);
  });
});

test('Rizin function Markdown renderer bounds rows and displays instruction output', () => {
  const report = {
    schema_version: 'orix.rizin-functions.v1',
    provider: { id: 'rizin.static', engine_version: '0.8.2' },
    artifact: { path: '/tmp/sample.elf', size_bytes: 1, sha256: 'a'.repeat(64) },
    functions: [
      { name: 'sym.main', offset: 4198400, size: 32, bits: 64, type: 'fcn', basic_blocks: 2 },
      { name: 'hidden', offset: 4198432, size: 8, bits: 64, type: 'fcn', basic_blocks: 1 },
    ],
    disassembly: {
      function_name: 'sym.main', address: 4198400, instruction_limit: 1,
      instructions: [{ offset: 4198400, bytes: 'c3', disassembly: 'ret|safe' }],
      instruction_limit_reached: true,
    },
    decompilation: {
      function_name: 'sym.main', address: 4198400, backend: 'rizin-pdg',
      source: 'int main(void) { return 0; }', characters_returned: 28, truncated: false,
    },
    summary: { functions_total: 2, functions_returned: 2, functions_truncated: false },
  };
  const markdown = render_rizin_functions_markdown(report, { max_rows: 1 });
  assert.match(markdown, /sym\.main/);
  assert.match(markdown, /1 additional functions omitted/);
  assert.match(markdown, /Bounded disassembly/);
  assert.match(markdown, /Optional pseudocode decompilation/);
  assert.match(markdown, /int main/);
  assert.ok(markdown.includes('ret\\|safe'));
});

test('provider CLI refuses missing executable configuration and invalid output formats', async () => {
  await assert.rejects(
    main(['providers', 'rizin', 'imports', './sample.elf']),
    /requires --executable/,
  );
  await assert.rejects(
    main(['providers', 'rizin', 'imports', './sample.elf', '--executable', '/bin/rizin', '--format', 'sarif']),
    /supports JSON or Markdown only/,
  );
});

test('Rizin Markdown renderer escapes table delimiters and bounds displayed rows', () => {
  const report = {
    schema_version: 'orix.rizin-imports.v1',
    provider: { id: 'rizin.static', engine_version: '0.8.2' },
    artifact: {
      path: '/tmp/sample.elf',
      size_bytes: 1,
      sha256: 'a'.repeat(64),
      stable_during_analysis: true,
    },
    imports: [
      { name: 'str|with|pipes', library: 'lib\nbad.so', ordinal: null, bind: 'GLOBAL', type: 'FUNC', plt: 1 },
      { name: 'hidden', library: 'libx.so', ordinal: 2, bind: 'GLOBAL', type: 'FUNC', plt: 2 },
    ],
    summary: { imports: 2, libraries: 2 },
    diagnostics: { stderr: '' },
  };
  const markdown = render_rizin_imports_markdown(report, { max_rows: 1 });
  assert.match(markdown, /str\\\|with\\\|pipes/);
  assert.match(markdown, /lib bad\.so/);
  assert.match(markdown, /1 additional imports omitted/);
  assert.doesNotMatch(markdown, /\| hidden \|/);
});

test('provider help documents the opt-in provider commands and limits', () => {
  assert.match(HELP_TEXT, /providers list/);
  assert.match(HELP_TEXT, /providers rizin doctor/);
  assert.match(HELP_TEXT, /providers rizin imports/);
  assert.match(HELP_TEXT, /providers rizin functions/);
  assert.match(HELP_TEXT, /not an OS sandbox/);
});

test('providers rizin doctor performs a real explicit executable version probe', async () => {
  await with_fixture(async ({ directory, executable }) => {
    const output = path.join(directory, 'rizin-doctor.json');
    const exit_code = await main([
      'providers', 'rizin', 'doctor',
      '--executable', executable,
      ...executable_args.flatMap(argument => ['--executable-arg', argument]),
      '--json',
      '--out', output,
    ]);
    assert.equal(exit_code, 0);
    const report = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(report.schema_version, 'orix.provider-probe.v1');
    assert.equal(report.status, 'available');
    assert.equal(report.provider.id, 'rizin.static');
    assert.equal(report.provider.engine_version, '0.8.2');
    assert.equal(report.runtime.platform, process.platform);
  });
});

test('providers rizin doctor requires an explicit executable and rejects extra positionals', async () => {
  await assert.rejects(
    main(['providers', 'rizin', 'doctor']),
    /requires --executable/,
  );
  assert.throws(
    () => parse_arguments(['providers', 'rizin', 'doctor', 'unexpected']),
    error => error.code === 'ORIX_CLI_PROVIDER_ARGUMENTS',
  );
});
