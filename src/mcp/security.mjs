// JavaScript, src/mcp/security.mjs, Node.js 20+, workspace-confined MCP path acquisition.
import { constants as fs_constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';

function fail(code, message, details = null, cause = undefined) {
  throw new OrixError(code, message, { details, cause, recoverable: true });
}
export function configured_workspace_roots(environment = process.env) {
  const configured = environment.ORIX_MCP_ROOTS;
  return configured ? configured.split(path.delimiter).map(value => value.trim()).filter(Boolean) : [process.cwd()];
}
async function real_roots(roots) {
  if (!Array.isArray(roots) || roots.length === 0) fail('ORIX_MCP_NO_WORKSPACE', 'At least one MCP workspace root is required');
  const resolved = [];
  for (const root of roots) {
    if (typeof root !== 'string' || root.length === 0) fail('ORIX_MCP_BAD_WORKSPACE', 'Workspace roots must be non-empty paths');
    try {
      const absolute = path.resolve(root);
      const stats = await fs.lstat(absolute);
      if (stats.isSymbolicLink() || !stats.isDirectory()) fail('ORIX_MCP_BAD_WORKSPACE', 'Workspace root must be a regular non-symlink directory', { root: absolute });
      resolved.push({ absolute, real: await fs.realpath(absolute) });
    } catch (error) {
      if (error instanceof OrixError) throw error;
      fail('ORIX_MCP_WORKSPACE_UNAVAILABLE', 'Cannot access MCP workspace root', { root, system_code: error.code }, error);
    }
  }
  const unique = new Map();
  for (const root of resolved) {
    if (!unique.has(root.real)) unique.set(root.real, root);
  }
  return [...unique.values()];
}
function within_root(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}
export async function resolve_workspace_path(input_path, roots = configured_workspace_roots(), options = {}) {
  if (typeof input_path !== 'string' || input_path.length === 0 || input_path.includes('\0')) fail('ORIX_MCP_BAD_PATH', 'MCP path must be a non-empty string without NUL bytes');
  const absolute = path.resolve(input_path);
  let stats;
  try { stats = await fs.lstat(absolute); }
  catch (error) { fail('ORIX_MCP_PATH_UNAVAILABLE', 'MCP path does not exist or cannot be accessed', { path: absolute, system_code: error.code }, error); }
  if (stats.isSymbolicLink()) fail('ORIX_MCP_SYMLINK_REJECTED', 'MCP does not follow symbolic links', { path: absolute });
  if (options.kind === 'file' && !stats.isFile()) fail('ORIX_MCP_NOT_FILE', 'MCP operation requires a regular file', { path: absolute });
  if (options.kind === 'file' && stats.nlink > 1) fail('ORIX_MCP_HARDLINK_REJECTED', 'MCP does not accept hard-linked workspace files', { path: absolute, link_count: stats.nlink });
  if (options.kind === 'directory' && !stats.isDirectory()) fail('ORIX_MCP_NOT_DIRECTORY', 'MCP operation requires a directory', { path: absolute });
  const real = await fs.realpath(absolute);
  const allowed = await real_roots(roots);
  const allowed_root = allowed.find(root => within_root(real, root.real));
  if (!allowed_root) fail('ORIX_MCP_PATH_OUTSIDE_WORKSPACE', 'MCP path is outside configured workspace roots', { path: real, roots: allowed.map(root => root.real) });

  // Inspect every component below the caller's configured root spelling.
  // The root itself may have an OS-managed alias (for example /var -> /private/var
  // on macOS), so component checks start at the configured root, not its realpath.
  if (!within_root(absolute, allowed_root.absolute)) {
    fail('ORIX_MCP_PATH_OUTSIDE_WORKSPACE', 'MCP path is outside the configured workspace path', { path: absolute, root: allowed_root.absolute });
  }
  const relative = path.relative(allowed_root.absolute, absolute);
  let current = allowed_root.absolute;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    let component;
    try { component = await fs.lstat(current); }
    catch (error) {
      fail('ORIX_MCP_PATH_UNAVAILABLE', 'MCP path component does not exist or cannot be accessed', { path: current, system_code: error.code }, error);
    }
    if (component.isSymbolicLink()) {
      fail('ORIX_MCP_SYMLINK_REJECTED', 'MCP does not follow symbolic links in workspace paths', { path: current });
    }
  }
  return { path: real, stats };
}
export async function resolve_workspace_output(input_path, roots = configured_workspace_roots()) {
  if (typeof input_path !== 'string' || input_path.length === 0 || input_path.includes('\0')) fail('ORIX_MCP_BAD_PATH', 'MCP output path must be a non-empty string without NUL bytes');
  const absolute = path.resolve(input_path);
  const parent = await resolve_workspace_path(path.dirname(absolute), roots, { kind: 'directory' });
  const destination = path.join(parent.path, path.basename(absolute));
  try {
    const stats = await fs.lstat(destination);
    if (stats.isSymbolicLink() || !stats.isFile()) fail('ORIX_MCP_UNSAFE_OUTPUT', 'MCP evidence output must be a regular non-symlink file', { path: destination });
    if (stats.nlink > 1) fail('ORIX_MCP_HARDLINK_REJECTED', 'MCP does not write to hard-linked workspace outputs', { path: destination, link_count: stats.nlink });
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return destination;
}
export async function read_workspace_json(input_path, roots = configured_workspace_roots(), options = {}) {
  const maximum = options.max_bytes ?? 64 * 1024 * 1024;
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 256 * 1024 * 1024) fail('ORIX_MCP_BAD_LIMIT', 'JSON report byte limit must be between 1 and 256 MiB');
  const resolved = await resolve_workspace_path(input_path, roots, { kind: 'file' });
  if (resolved.stats.size > maximum) fail('ORIX_MCP_INPUT_LIMIT', 'JSON report exceeds configured input limit', { size: resolved.stats.size, maximum });
  let handle;
  try {
    handle = await fs.open(resolved.path, fs_constants.O_RDONLY | (fs_constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== resolved.stats.dev || opened.ino !== resolved.stats.ino) fail('ORIX_MCP_FILE_CHANGED', 'JSON report identity changed between lookup and open', { path: resolved.path });
    if (opened.nlink > 1) fail('ORIX_MCP_HARDLINK_REJECTED', 'MCP does not read hard-linked workspace reports', { path: resolved.path, link_count: opened.nlink });
    if (!Number.isSafeInteger(opened.size) || opened.size > maximum) fail('ORIX_MCP_INPUT_LIMIT', 'JSON report exceeds configured input limit', { size: opened.size, maximum });
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) fail('ORIX_MCP_FILE_CHANGED', 'JSON report ended during bounded read', { path: resolved.path });
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (after.nlink > 1) fail('ORIX_MCP_HARDLINK_REJECTED', 'MCP report acquired a hard-link alias during bounded read', { path: resolved.path, link_count: after.nlink });
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) fail('ORIX_MCP_FILE_CHANGED', 'JSON report changed during bounded read', { path: resolved.path });
    const text = bytes.toString('utf8');
    try { return JSON.parse(text); }
    catch (error) { fail('ORIX_MCP_INVALID_JSON', 'Workspace report is not valid JSON', { path: resolved.path }, error); }
  } catch (error) {
    if (error instanceof OrixError) throw error;
    fail('ORIX_MCP_READ_FAILED', 'Cannot read workspace report', { path: resolved.path, system_code: error.code }, error);
  } finally { await handle?.close().catch(() => {}); }
}
