// JavaScript, src/core/read-report.mjs, Node.js 20+, bounded no-follow JSON report acquisition.

import { constants as FS_CONSTANTS, promises as fs } from 'node:fs';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { OrixError } from './errors.mjs';

export async function read_json_report(file_path) {
  const absolute = path.resolve(file_path);
  let before;
  try { before = await fs.lstat(absolute); }
  catch (error) { throw new OrixError('ORIX_COMPARE_FILE_UNAVAILABLE', 'Cannot access comparison report: ' + absolute, { cause: error, details: { system_code: error.code }, recoverable: true }); }
  if (before.isSymbolicLink() || !before.isFile()) throw new OrixError('ORIX_COMPARE_UNSAFE_FILE', 'Comparison input must be a regular non-symlink file', { details: { path: absolute }, recoverable: true });
  if (!Number.isSafeInteger(before.size) || before.size > 64 * 1024 * 1024) throw new OrixError('ORIX_COMPARE_FILE_LIMIT', 'Comparison report exceeds the 64 MiB input limit', { details: { size: before.size }, recoverable: true });
  let handle;
  let text;
  let bytes;
  try {
    handle = await fs.open(absolute, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size || String(opened.ino) !== String(before.ino) || String(opened.dev) !== String(before.dev)) {
      throw new OrixError('ORIX_COMPARE_FILE_CHANGED', 'Comparison report changed between metadata lookup and open', { recoverable: true });
    }
    bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) throw new OrixError('ORIX_COMPARE_FILE_CHANGED', 'Comparison report ended during bounded read', { recoverable: true });
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      throw new OrixError('ORIX_COMPARE_FILE_CHANGED', 'Comparison report changed during bounded read', { recoverable: true });
    }

  } catch (error) {
    if (error instanceof OrixError) throw error;
    throw new OrixError('ORIX_COMPARE_FILE_UNAVAILABLE', 'Cannot open or read comparison report: ' + absolute, {
      cause: error,
      details: { path: absolute, system_code: error.code ?? null },
      recoverable: true,
    });
  } finally { await handle?.close().catch(() => {}); }
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch (error) { throw new OrixError('ORIX_COMPARE_INVALID_UTF8', 'Comparison input is not valid UTF-8: ' + absolute, { cause: error, details: { path: absolute }, recoverable: true }); }
  try { return JSON.parse(text); }
  catch (error) { throw new OrixError('ORIX_COMPARE_INVALID_JSON', 'Comparison input is not valid JSON: ' + absolute, { cause: error, details: { path: absolute }, recoverable: true }); }
}

