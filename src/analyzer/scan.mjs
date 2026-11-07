// JavaScript, src/analyzer/scan.mjs, Node.js 20+, bounded concurrent artifact scan.

import { inspect_file } from '../core/inspect.mjs';
import { resolve_limits } from '../core/limits.mjs';
import { walk_directory } from './walk.mjs';
import { normalize_error } from '../core/errors.mjs';
import { append_ledger } from '../evidence/ledger.mjs';

async function run_pool(items, concurrency, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function consume() {
    while (true) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, consume));
  return results;
}

export async function scan_directory(root_path, options = {}) {
  const limits = resolve_limits(options.limits);
  const inventory = await walk_directory(root_path, { ...options, limits });
  const started_at = new Date();
  const results = await run_pool(inventory.files, limits.max_scan_concurrency, async file_path => {
    try {
      const artifact = await inspect_file(file_path, { ...options, limits });
      return { status: 'analyzed', path: file_path, artifact };
    } catch (error) {
      return { status: 'skipped', path: file_path, error: normalize_error(error) };
    }
  });
  const completed_at = new Date();
  const analyzed = results.filter(item => item.status === 'analyzed');
  const skipped = results.filter(item => item.status === 'skipped');
  const formats = {};
  const indicator_counts = {};
  const files_with_indicators = new Set();
  let total_bytes = 0;
  for (const item of analyzed) {
    total_bytes += item.artifact.artifact.size_bytes;
    const format = item.artifact.detection.format;
    formats[format] = (formats[format] ?? 0) + 1;
    if (item.artifact.indicators?.length) files_with_indicators.add(item.path);
    for (const indicator of item.artifact.indicators ?? []) {
      indicator_counts[indicator.severity] = (indicator_counts[indicator.severity] ?? 0) + 1;
    }
  }
  const report = {
    schema_version: 'orix.scan.v1',
    scan: {
      root: inventory.root,
      started_at: started_at.toISOString(),
      completed_at: completed_at.toISOString(),
      duration_ms: Math.max(0, completed_at.getTime() - started_at.getTime()),
      coverage: inventory.coverage,
      files_analyzed: analyzed.length,
      files_skipped: skipped.length + inventory.skipped.length,
      total_bytes_analyzed: total_bytes,
      formats: Object.fromEntries(Object.entries(formats).sort(([a], [b]) => a.localeCompare(b))),
      files_with_indicators: files_with_indicators.size,
      indicator_counts: Object.fromEntries(['critical','high','medium','low','info'].filter(key => indicator_counts[key]).map(key => [key, indicator_counts[key]])),
    },
    artifacts: analyzed.map(item => item.artifact),
    errors: skipped,
    inventory_skips: inventory.skipped,
    limitations: [
      'Directory traversal does not follow symbolic links.',
      'Inspection is static and read-only; it does not execute files, load plugins, or contact remote services.',
      'Per-file parser and byte limits are recorded in each artifact result.',
    ],
  };
  if (options.evidence_ledger) {
    const maximum = options.max_ledger_artifacts ?? 1000;
    if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 10000) throw new TypeError('max_ledger_artifacts must be between 0 and 10000');
    const evidence = analyzed.slice(0, maximum).map(item => ({
      path: item.path,
      sha256: item.artifact.integrity.digest,
      size_bytes: item.artifact.artifact.size_bytes,
      format: item.artifact.detection.format,
      indicator_count: item.artifact.indicators?.length ?? 0,
    }));
    const record = await append_ledger(options.evidence_ledger, {
      type: 'scan.completed',
      payload: {
        root: inventory.root,
        started_at: report.scan.started_at,
        completed_at: report.scan.completed_at,
        files_analyzed: report.scan.files_analyzed,
        files_skipped: report.scan.files_skipped,
        total_bytes_analyzed: report.scan.total_bytes_analyzed,
        formats: report.scan.formats,
        indicator_counts: report.scan.indicator_counts,
        artifacts: evidence,
        artifacts_omitted: Math.max(0, analyzed.length - evidence.length),
      },
    });
    report.evidence_ledger = {
      path: record.path,
      sequence: record.sequence,
      hash: record.record_hash,
      artifacts_recorded: evidence.length,
      artifacts_omitted: Math.max(0, analyzed.length - evidence.length),
    };
  }
  return report;
}
