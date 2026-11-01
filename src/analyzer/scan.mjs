// JavaScript, src/analyzer/scan.mjs, Node.js 20+, bounded concurrent artifact scan.

import { inspect_file } from '../core/inspect.mjs';
import { resolve_limits } from '../core/limits.mjs';
import { walk_directory } from './walk.mjs';
import { normalize_error } from '../core/errors.mjs';

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
  return {
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
}
