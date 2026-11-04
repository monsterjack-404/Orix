// JavaScript, tests/integration.test.mjs, Node.js 20+, real filesystem and CLI integration.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile, symlink, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { inspect_file } from '../src/core/inspect.mjs';
import { scan_directory } from '../src/analyzer/scan.mjs';
import { main as cli_main } from '../src/cli/main.mjs';
import { parse_arguments } from '../src/cli/arguments.mjs';
import { verify_ledger } from '../src/evidence/ledger.mjs';
import { create_elf_fixture, create_pe_fixture, create_zip_fixture } from './helpers.mjs';

async function with_temp_dir(callback) {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-test-'));
  try { await callback(directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

test('inspect_file reports complete hash, parser status, bounded metrics and evidence', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'sample.elf');
    await writeFile(file, create_elf_fixture());
    const report = await inspect_file(file);
    assert.equal(report.schema_version, 'orix.artifact.v1');
    assert.equal(report.detection.format, 'ELF');
    assert.equal(report.parser.status, 'parsed');
    assert.equal(report.integrity.digest.length, 64);
    assert.equal(report.artifact.analysis_complete_for_file, true);
    assert.ok(report.evidence.length >= 3);
  });
});

test('inspect_file rejects symlinks and directories', async () => {
  await with_temp_dir(async directory => {
    const target = path.join(directory, 'target.bin');
    const link = path.join(directory, 'link.bin');
    await writeFile(target, Buffer.from('safe sample'));
    await symlink(target, link);
    await assert.rejects(inspect_file(link), error => error.code === 'ORIX_SYMLINK_REJECTED');
    await assert.rejects(inspect_file(directory), error => error.code === 'ORIX_NOT_REGULAR_FILE');
  });
});

test('scan_directory inventories nested files, ignores dependency trees and aggregates formats', async () => {
  await with_temp_dir(async directory => {
    await mkdir(path.join(directory, 'nested'));
    await mkdir(path.join(directory, 'node_modules'));
    await writeFile(path.join(directory, 'nested', 'sample.elf'), create_elf_fixture());
    await writeFile(path.join(directory, 'unknown.bin'), Buffer.from('plain data with readable words'));
    await writeFile(path.join(directory, 'node_modules', 'ignored.bin'), Buffer.from('ignored'));
    const report = await scan_directory(directory, { limits: { max_scan_files: 50, max_scan_concurrency: 2 } });
    assert.equal(report.scan.files_analyzed, 2);
    assert.equal(report.scan.formats.ELF, 1);
    assert.equal(report.scan.formats.Unknown, 1);
    assert.equal(report.scan.coverage.truncated, false);
  });
});

test('CLI rejects malformed limits and exposes commands through help', () => {
  assert.throws(() => parse_arguments(['scan','.', '--max-files','0']), error => error.code === 'ORIX_CLI_NUMBER_OUT_OF_RANGE');
  assert.throws(() => parse_arguments(['inspect','a.bin','--unknown']), error => error.code === 'ORIX_CLI_UNKNOWN_OPTION');
  const cli = spawnSync(process.execPath, ['src/cli.mjs','help'], { encoding: 'utf8', cwd: path.resolve('.') });
  assert.equal(cli.status, 0);
  assert.match(cli.stdout, /ORIX — Open Research/);
  assert.match(cli.stdout, /Symlinks/);
});

test('CLI JSON output is valid machine-readable JSON', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'sample.bin');
    await writeFile(file, Buffer.from('static artifact data'));
    const cli = spawnSync(process.execPath, ['src/cli.mjs','inspect',file,'--json'], { encoding: 'utf8', cwd: path.resolve('.') });
    assert.equal(cli.status, 0, cli.stderr);
    const parsed = JSON.parse(cli.stdout);
    assert.equal(parsed.schema_version, 'orix.artifact.v1');
  });
});

test('formats command distinguishes structural parsers from signature-only formats', () => {
  const cli = spawnSync(process.execPath, ['src/cli.mjs','formats','--json'], { encoding: 'utf8', cwd: path.resolve('.') });
  assert.equal(cli.status, 0, cli.stderr);
  const report = JSON.parse(cli.stdout);
  const pdf = report.formats.find(item => item.format === 'PDF');
  const png = report.formats.find(item => item.format === 'PNG');
  assert.equal(pdf.parser_status, 'available');
  assert.equal(png.parser_status, 'available');
});

test('scan coverage marks an actually exceeded file cap as truncated', async () => {
  await with_temp_dir(async directory => {
    await writeFile(path.join(directory, 'a.bin'), Buffer.from('first'));
    await writeFile(path.join(directory, 'b.bin'), Buffer.from('second'));
    const report = await scan_directory(directory, { limits: { max_scan_files: 1, max_scan_directories: 10, max_scan_entries: 20 } });
    assert.equal(report.scan.files_analyzed, 1);
    assert.equal(report.scan.coverage.truncated, true);
  });
});


test('inspect_file attaches explainable PE section indicators to the artifact report', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'review.exe');
    const image = create_pe_fixture();
    const section_table = 0x80 + 4 + 20 + 224;
    image.writeUInt32LE(0xe0000020, section_table + 36);
    await writeFile(file, image);
    const report = await inspect_file(file);
    assert.ok(report.indicators.some(item => item.rule_id === 'ORIX-PE-WRITABLE-EXECUTABLE-001'));
    assert.equal(report.indicators.find(item => item.rule_id === 'ORIX-PE-WRITABLE-EXECUTABLE-001').confidence, 'derived');
  });
});

test('inspect_file reports unsafe ZIP metadata without extracting archive entries', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'archive.zip');
    await writeFile(file, create_zip_fixture('../outside.txt', 'metadata-only'));
    const report = await inspect_file(file);
    assert.equal(report.parser.status, 'parsed');
    assert.ok(report.indicators.some(item => item.rule_id === 'ORIX-ZIP-UNSAFE-ENTRY-001'));
    assert.match(report.parser.result.notes.join(' '), /does not extract/);
  });
});

test('directory scan aggregates indicator counts independently of format counts', async () => {
  await with_temp_dir(async directory => {
    const image = create_pe_fixture();
    const section_table = 0x80 + 4 + 20 + 224;
    image.writeUInt32LE(0xe0000020, section_table + 36);
    await writeFile(path.join(directory, 'review.exe'), image);
    await writeFile(path.join(directory, 'plain.bin'), Buffer.from('ordinary printable content'));
    const report = await scan_directory(directory);
    assert.equal(report.scan.files_with_indicators, 1);
    assert.equal(report.scan.indicator_counts.high, 1);
    assert.equal(report.scan.formats.PE, 1);
    assert.equal(report.artifacts.length, 2);
  });
});


test('CLI emits SARIF 2.1 for an inspected artifact', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'sample.exe');
    const image = create_pe_fixture();
    const section_table = 0x80 + 4 + 20 + 224;
    image.writeUInt32LE(0xe0000020, section_table + 36);
    await writeFile(file, image);
    const cli = spawnSync(process.execPath, ['src/cli.mjs','inspect',file,'--format','sarif'], { encoding: 'utf8', cwd: path.resolve('.') });
    assert.equal(cli.status, 0, cli.stderr);
    const sarif = JSON.parse(cli.stdout);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].tool.driver.name, 'ORIX');
    assert.ok(sarif.runs[0].results.some(item => item.ruleId === 'ORIX-PE-WRITABLE-EXECUTABLE-001'));
  });
});


test('CLI inspection appends a durable receipt and ledger verification reads it back', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'sample.bin');
    const ledger = path.join(directory, '.orix', 'evidence.jsonl');
    await writeFile(file, Buffer.from('integration evidence sample'));
    const inspect = spawnSync(process.execPath, ['src/cli.mjs', 'inspect', file, '--json', '--ledger', ledger], { encoding: 'utf8', cwd: path.resolve('.') });
    assert.equal(inspect.status, 0, inspect.stderr);
    const report = JSON.parse(inspect.stdout);
    assert.equal(report.ledger_receipt.sequence, 1);
    assert.equal(report.ledger_receipt.record_hash.length, 64);
    const verify = spawnSync(process.execPath, ['src/cli.mjs', 'ledger', 'verify', ledger], { encoding: 'utf8', cwd: path.resolve('.') });
    assert.equal(verify.status, 0, verify.stderr);
    const result = JSON.parse(verify.stdout);
    assert.equal(result.valid, true);
    assert.equal(result.records_verified, 1);
    const list = spawnSync(process.execPath, ['src/cli.mjs', 'ledger', 'list', ledger], { encoding: 'utf8', cwd: path.resolve('.') });
    assert.equal(list.status, 0, list.stderr);
    assert.equal(JSON.parse(list.stdout).records[0].type, 'inspect.completed');
  });
});

test('CLI parser accepts ledger operations and validates missing paths', () => {
  const parsed = parse_arguments(['ledger', 'verify', './evidence.jsonl']);
  assert.equal(parsed.command, 'ledger');
  assert.equal(parsed.flags.ledger_operation, 'verify');
  assert.equal(parsed.flags.ledger_path, './evidence.jsonl');
  assert.throws(() => parse_arguments(['ledger', 'verify']), error => error.code === 'ORIX_CLI_LEDGER_PATH');
});


test('CLI compares prior scan reports without rescanning their source directories', async () => {
  await with_temp_dir(async directory => {
    const baseline_root = path.join(directory, 'baseline');
    const current_root = path.join(directory, 'current');
    await mkdir(baseline_root);
    await mkdir(current_root);
    await writeFile(path.join(baseline_root, 'same.bin'), Buffer.from('before'));
    await writeFile(path.join(current_root, 'same.bin'), Buffer.from('after'));
    await writeFile(path.join(current_root, 'new.bin'), Buffer.from('new file'));
    const baseline = await scan_directory(baseline_root);
    const current = await scan_directory(current_root);
    const baseline_file = path.join(directory, 'baseline.json');
    const current_file = path.join(directory, 'current.json');
    await writeFile(baseline_file, JSON.stringify(baseline));
    await writeFile(current_file, JSON.stringify(current));
    const cli = spawnSync(process.execPath, ['src/cli.mjs','compare',baseline_file,current_file,'--json'], { encoding: 'utf8', cwd: path.resolve('.') });
    assert.equal(cli.status, 0, cli.stderr);
    const comparison = JSON.parse(cli.stdout);
    assert.equal(comparison.schema_version, 'orix.comparison.v1');
    assert.equal(comparison.comparison.modified, 1);
    assert.equal(comparison.comparison.added, 1);
  });
});

test('CLI comparison rejects symbolic-link report inputs', async () => {
  await with_temp_dir(async directory => {
    const target = path.join(directory, 'report.json');
    const link = path.join(directory, 'link.json');
    await writeFile(target, JSON.stringify({ schema_version: 'orix.scan.v1', scan: { root: directory }, artifacts: [] }));
    await symlink(target, link);
    const cli = spawnSync(process.execPath, ['src/cli.mjs','compare',link,target,'--json'], { encoding: 'utf8', cwd: path.resolve('.') });
    assert.equal(cli.status, 1);
    assert.match(cli.stderr, /ORIX_COMPARE_UNSAFE_FILE/);
  });
});


test('CLI emits a CycloneDX SBOM from project dependency declarations', async () => {
  await with_temp_dir(async directory => {
    await writeFile(path.join(directory, 'package.json'), JSON.stringify({
      name: 'sbom-fixture',
      version: '2.0.0',
      dependencies: { 'safe-lib': '^1.2.3' },
      devDependencies: { 'test-lib': '^4.5.6' },
    }));
    const cli = spawnSync(process.execPath, ['src/cli.mjs','project',directory,'--format','cyclonedx'], { encoding: 'utf8', cwd: path.resolve('.') });
    assert.equal(cli.status, 0, cli.stderr);
    const bom = JSON.parse(cli.stdout);
    assert.equal(bom.bomFormat, 'CycloneDX');
    assert.equal(bom.specVersion, '1.5');
    assert.equal(bom.metadata.component.name, 'sbom-fixture');
    assert.equal(bom.components.length, 2);
  });
});


test('directory scan initializes and appends its evidence ledger receipt', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'sample.bin');
    const ledger = path.join(directory, '.orix', 'nested', 'scan.jsonl');
    await writeFile(file, Buffer.from('scan evidence ledger regression'));
    const report = await scan_directory(directory, { evidence_ledger: ledger });
    assert.equal(report.evidence_ledger.sequence, 1);
    assert.equal(report.evidence_ledger.hash.length, 64);
    assert.equal(report.evidence_ledger.artifacts_recorded, 1);
    const verified = await verify_ledger(ledger);
    assert.equal(verified.valid, true);
    assert.equal(verified.records_verified, 1);
  });
});


test('CLI rejects command-specific options that would otherwise be ignored', async () => {
  await assert.rejects(cli_main(['project', '.', '--concurrency', '4']), /project does not support option/);
  await assert.rejects(cli_main(['compare', 'before.json', 'after.json', '--ledger', 'events.jsonl']), /compare does not support option/);
});

test('CLI rejects output formats unsupported by compare, ledger and formats commands', async () => {
  await assert.rejects(cli_main(['compare', 'before.json', 'after.json', '--format', 'cyclonedx']), /compare output supports JSON or Markdown/);
  await assert.rejects(cli_main(['ledger', 'verify', 'events.jsonl', '--format', 'sarif']), /ledger output currently supports JSON only/);
  await assert.rejects(cli_main(['formats', '--format', 'markdown']), /formats output currently supports JSON only/);
});


test('CLI validates read-prefix limits against default and overridden file limits', () => {
  assert.throws(
    () => parse_arguments(['inspect', 'sample.bin', '--max-read-mib', '512']),
    error => error.code === 'ORIX_CLI_LIMIT_CONFLICT',
  );
  assert.equal(parse_arguments(['inspect', 'sample.bin', '--max-file-mib', '1']).flags.max_file_bytes, 1024 * 1024);
});


test('CLI emits SARIF for project source findings without exporting matched values', async () => {
  await with_temp_dir(async directory => {
    const source = path.join(directory, 'src');
    await mkdir(source);
    const secret = 'this-is-a-local-fixture-token-12345';
    await writeFile(path.join(source, 'config.js'), 'const api_key = "' + secret + '";\\n');
    const cli = spawnSync(process.execPath, ['src/cli.mjs', 'project', directory, '--format', 'sarif'], {
      encoding: 'utf8',
      cwd: path.resolve('.'),
    });
    assert.equal(cli.status, 0, cli.stderr);
    const sarif = JSON.parse(cli.stdout);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results.length, 1);
    assert.equal(sarif.runs[0].results[0].ruleId, 'ORIX-PROJECT-SECRET-GENERIC-001');
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 1);
    assert.equal(JSON.stringify(sarif).includes(secret), false);
  });
});
