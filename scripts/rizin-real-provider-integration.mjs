// JavaScript, scripts/rizin-real-provider-integration.mjs, pinned upstream Rizin conformance check.
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { analyze_rizin_functions } from '../src/providers/rizin.mjs';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 2 * 1024 * 1024,
    ...options,
  });
  if (result.error || result.status !== 0) {
    throw new Error([
      command + ' failed with status ' + String(result.status),
      result.error?.message ?? '',
      result.stdout ?? '',
      result.stderr ?? '',
    ].filter(Boolean).join('\n'));
  }
  return result;
}

async function main() {
  const executable = process.env.RIZIN_BIN;
  assert.equal(typeof executable, 'string', 'RIZIN_BIN must name the pinned real Rizin executable');
  assert.ok(path.isAbsolute(executable), 'RIZIN_BIN must be an absolute path');

  const version = run(executable, ['-v']).stdout;
  assert.match(version, /0\.9\.1/, 'CI must exercise the pinned Rizin 0.9.1 release');

  const directory = await mkdtemp(path.join(tmpdir(), 'orix-rizin-real-'));
  try {
    const sourcePath = path.join(directory, 'callgraph-fixture.c');
    const binaryPath = path.join(directory, 'callgraph-fixture');
    await writeFile(sourcePath, [
      '__attribute__((noinline, used)) int orix_helper(int value) {',
      '  volatile int local = value;',
      '  return local * 3 + 1;',
      '}',
      '__attribute__((noinline, used)) int orix_caller(int value) {',
      '  return orix_helper(value) + 7;',
      '}',
      'int main(int argc, char **argv) {',
      '  (void)argv;',
      '  return orix_caller(argc);',
      '}',
      '',
    ].join('\n'));

    run(process.env.CC ?? 'cc', [
      '-O0', '-g', '-fno-inline', '-fno-pie', '-no-pie',
      '-fno-omit-frame-pointer', sourcePath, '-o', binaryPath,
    ]);

    const report = await analyze_rizin_functions({
      executable,
      input_path: binaryPath,
      max_functions: 20000,
      include_references: true,
      max_references: 100000,
      timeout_ms: 60000,
      max_output_bytes: 8 * 1024 * 1024,
    });

    assert.equal(report.provider.engine_version, '0.9.1');
    assert.equal(report.artifact.stable_during_analysis, true);
    assert.match(report.artifact.sha256, /^[a-f0-9]{64}$/);
    assert.equal(report.summary.functions_truncated, false);
    assert.ok(report.references.length > 0, 'real Rizin must return at least one axlj record');

    const caller = report.functions.find(item => item.name.includes('orix_caller'));
    const helper = report.functions.find(item => item.name.includes('orix_helper'));
    assert.ok(caller, 'Rizin must identify the caller function from the compiled ELF');
    assert.ok(helper, 'Rizin must identify the helper function from the compiled ELF');

    const reference = report.references.find(item =>
      item.type === 'CALL' &&
      item.from_function_offset === caller.offset &&
      item.to_function_offset === helper.offset);
    assert.ok(reference, 'axlj must contain the real CALL reference from orix_caller to orix_helper');

    const edge = report.call_graph.edges.find(item =>
      item.from_function_offset === caller.offset &&
      item.to_function_offset === helper.offset);
    assert.ok(edge, 'ORIX must map the real Rizin CALL reference to the expected call-graph edge');
    assert.equal(report.summary.call_graph_edges, report.call_graph.edges.length);
    assert.ok(Number.isSafeInteger(report.diagnostics.reference_scan_duration_ms));

    process.stdout.write(JSON.stringify({
      provider: report.provider,
      artifact: { size_bytes: report.artifact.size_bytes, sha256: report.artifact.sha256 },
      functions: report.summary.functions_returned,
      references: report.summary.references_returned,
      call_graph_edges: report.summary.call_graph_edges,
      verified_edge: {
        caller: caller.name,
        callee: helper.name,
        call_site: edge.call_site,
        target_address: edge.target_address,
      },
      reference_scan_duration_ms: report.diagnostics.reference_scan_duration_ms,
    }, null, 2) + '\n');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write((error?.stack ?? error?.message ?? String(error)) + '\n');
  process.exitCode = 1;
});
