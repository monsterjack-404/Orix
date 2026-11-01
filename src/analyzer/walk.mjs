// JavaScript, src/analyzer/walk.mjs, Node.js 20+, bounded directory inventory without symlink traversal.

import path from 'node:path';
import { promises as fs } from 'node:fs';
import { OrixError } from '../core/errors.mjs';
import { resolve_limits } from '../core/limits.mjs';

const DEFAULT_IGNORES = new Set(['.git', '.hg', '.svn', 'node_modules', '.orix', '.next', 'dist', 'build', 'coverage']);

export async function walk_directory(root_path, options = {}) {
  if (typeof root_path !== 'string' || root_path.length === 0) throw new TypeError('root_path must be a non-empty string');
  const limits = resolve_limits(options.limits);
  const root = path.resolve(root_path);
  let root_stats;
  try { root_stats = await fs.lstat(root); }
  catch (error) { throw new OrixError('ORIX_SCAN_ROOT_UNAVAILABLE', `Cannot access scan root: ${root}`, { cause: error, details: { system_code: error.code }, recoverable: true }); }
  if (root_stats.isSymbolicLink()) throw new OrixError('ORIX_SCAN_SYMLINK_ROOT', 'A symbolic link cannot be used as the scan root', { details: { root }, recoverable: true });
  if (!root_stats.isDirectory()) throw new OrixError('ORIX_SCAN_ROOT_NOT_DIRECTORY', 'Scan root must be a directory', { details: { root }, recoverable: true });

  const ignores = new Set([...DEFAULT_IGNORES, ...(options.ignore ?? [])]);
  const files = [];
  const skipped = [];
  const pending = [{ directory: root, depth: 0 }];
  let directories_examined = 0;
  let entries_examined = 0;
  let truncated = false;
  while (pending.length > 0 && !truncated) {
    const current = pending.pop();
    directories_examined += 1;
    if (directories_examined > limits.max_scan_directories) { truncated = true; break; }
    let entries;
    try { entries = await fs.readdir(current.directory, { withFileTypes: true }); }
    catch (error) { skipped.push({ path: current.directory, reason: 'directory-unreadable', system_code: error.code ?? null }); continue; }
    entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const entry of entries) {
      entries_examined += 1;
      if (entries_examined > limits.max_scan_entries) { truncated = true; break; }
      const absolute = path.join(current.directory, entry.name);
      if (entry.isSymbolicLink()) { skipped.push({ path: absolute, reason: 'symbolic-link' }); continue; }
      if (entry.isDirectory()) {
        if (ignores.has(entry.name)) continue;
        if (current.depth >= limits.max_scan_depth) { skipped.push({ path: absolute, reason: 'depth-limit' }); truncated = true; continue; }
        pending.push({ directory: absolute, depth: current.depth + 1 });
        continue;
      }
      if (entry.isFile()) {
        if (files.length >= limits.max_scan_files) { truncated = true; break; }
        files.push(absolute);
      }
    }
  }
  if (pending.length > 0) truncated = true;
  files.sort((left, right) => left.localeCompare(right, 'en'));
  return {
    root,
    files,
    skipped,
    coverage: { directories_examined, entries_examined, files_discovered: files.length, skipped_entries: skipped.length, truncated, max_scan_files: limits.max_scan_files, max_scan_directories: limits.max_scan_directories, max_scan_entries: limits.max_scan_entries, max_scan_depth: limits.max_scan_depth },
  };
}
