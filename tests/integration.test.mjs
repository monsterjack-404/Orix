// JavaScript, tests/integration.test.mjs, Node.js 20+, real filesystem and CLI integration.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile, symlink, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { inspect_file } from '../src/core/inspect.mjs';
import { scan_directory } from '../src/analyzer/scan.mjs';
import { parse_arguments } from '../src/cli/arguments.mjs';
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
  assert.equal(png.parser_status, 'signature-only');
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
