// JavaScript, src/project/git-metadata.mjs, Node.js 20+, bounded read-only Git metadata inventory.

import { createHash } from 'node:crypto';
import { constants as fs_constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { inflateSync } from 'node:zlib';
import { OrixError } from '../core/errors.mjs';

const DEFAULTS = Object.freeze({ max_refs: 5000, max_ref_depth: 24, max_metadata_bytes: 4 * 1024 * 1024, max_object_bytes: 2 * 1024 * 1024, max_pack_files: 1000 });

function fail(code, message, details = {}, cause = undefined) {
  throw new OrixError(code, message, { details, cause, recoverable: true });
}

function inside(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

function limits_from(options = {}) {
  const result = {};
  for (const [name, fallback] of Object.entries(DEFAULTS)) {
    const value = options[name] ?? fallback;
    if (!Number.isSafeInteger(value) || value < 1 || value > fallback) {
      fail('ORIX_GIT_BAD_LIMIT', name + ' must be between 1 and ' + fallback, { name, value, maximum: fallback });
    }
    result[name] = value;
  }
  return result;
}

async function read_regular_file(file_path, root, maximum) {
  let before;
  try { before = await fs.lstat(file_path); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    fail('ORIX_GIT_METADATA_READ', 'Cannot inspect Git metadata file', { path: file_path, system_code: error.code }, error);
  }
  if (before.isSymbolicLink() || !before.isFile()) fail('ORIX_GIT_UNSAFE_METADATA', 'Git metadata input must be a regular non-symlink file', { path: file_path });
  if (!Number.isSafeInteger(before.size) || before.size > maximum) fail('ORIX_GIT_METADATA_LIMIT', 'Git metadata file exceeds configured byte limit', { path: file_path, size: before.size, maximum });
  let real;
  try { real = await fs.realpath(file_path); }
  catch (error) { fail('ORIX_GIT_METADATA_READ', 'Cannot resolve Git metadata path', { path: file_path, system_code: error.code }, error); }
  if (!inside(real, root)) fail('ORIX_GIT_PATH_ESCAPE', 'Git metadata path resolves outside the repository metadata directory', { path: real });
  let handle;
  try {
    handle = await fs.open(file_path, fs_constants.O_RDONLY | (fs_constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) fail('ORIX_GIT_FILE_CHANGED', 'Git metadata file identity changed between lookup and open', { path: file_path });
    if (opened.size > maximum) fail('ORIX_GIT_METADATA_LIMIT', 'Git metadata file exceeds configured byte limit', { path: file_path, size: opened.size, maximum });
    const buffer = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) fail('ORIX_GIT_FILE_CHANGED', 'Git metadata file ended during read', { path: file_path });
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) fail('ORIX_GIT_FILE_CHANGED', 'Git metadata file changed during read', { path: file_path });
    return buffer;
  } catch (error) {
    if (error instanceof OrixError) throw error;
    fail('ORIX_GIT_METADATA_READ', 'Cannot read Git metadata file', { path: file_path, system_code: error.code }, error);
  } finally {
    await handle?.close().catch(() => {});
  }
}

function parse_remote_url(value) {
  const input = value.trim().replace(/^['"]|['"]$/g, '');
  if (!input || input.length > 4096) return { transport: 'unknown', host: null, repository: null };
  const scp = /^(?:[^@/:]+@)?([^:/]+):(.+)$/.exec(input);
  if (scp && !/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
    return { transport: 'ssh', host: scp[1].toLowerCase(), repository: scp[2].replace(/\.git$/i, '').slice(0, 1024) };
  }
  try {
    const url = new URL(input);
    if (!['https:', 'http:', 'ssh:', 'git:'].includes(url.protocol)) return { transport: 'local', host: null, repository: null };
    return {
      transport: url.protocol.slice(0, -1),
      host: url.hostname.toLowerCase() || null,
      repository: url.pathname.replace(/^\//, '').replace(/\.git$/i, '').slice(0, 1024) || null,
    };
  } catch {
    return { transport: 'local', host: null, repository: null };
  }
}

function parse_config(text) {
  const values = { object_format: 'sha1', bare: false, remotes: new Map() };
  let section = '';
  for (const line of text.split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)]\s*$/.exec(line);
    if (header) {
      section = header[1].trim();
      continue;
    }
    const pair = /^\s*([A-Za-z][A-Za-z0-9.-]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!pair) continue;
    const key = pair[1].toLowerCase();
    const raw = pair[2].replace(/^['"]|['"]$/g, '');
    if (section.toLowerCase() === 'extensions' && key === 'objectformat' && raw.toLowerCase() === 'sha256') values.object_format = 'sha256';
    if (section.toLowerCase() === 'core' && key === 'bare') values.bare = raw.toLowerCase() === 'true';
    const remote = /^remote\s+"([^"]+)"$/i.exec(section);
    if (remote && key === 'url') {
      const name = remote[1].slice(0, 128);
      const list = values.remotes.get(name) ?? [];
      list.push(parse_remote_url(raw));
      values.remotes.set(name, list);
    }
  }
  return values;
}

function parse_packed_refs(text, refs) {
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#') || line.startsWith('^')) continue;
    const match = /^([a-f0-9]{40}|[a-f0-9]{64})\s+(.+)$/.exec(line);
    if (match && !refs.has(match[2])) refs.set(match[2], match[1]);
  }
}

async function collect_loose_refs(refs_root, git_root, refs, limits, warnings) {
  let visited = 0;
  async function visit(directory, relative, depth) {
    if (depth > limits.max_ref_depth) {
      warnings.push({ code: 'ORIX_GIT_REF_DEPTH_LIMIT', path: relative });
      return;
    }
    let entries;
    try {
      const directory_stat = await fs.lstat(directory);
      const directory_real = await fs.realpath(directory);
      if (directory_stat.isSymbolicLink() || !directory_stat.isDirectory() || !inside(directory_real, git_root)) { warnings.push({ code: 'ORIX_GIT_REF_DIRECTORY_UNSAFE', path: relative }); return; }
      entries = await fs.readdir(directory, { withFileTypes: true });
    }
    catch (error) {
      if (error.code !== 'ENOENT') warnings.push({ code: 'ORIX_GIT_REF_DIRECTORY_READ', path: relative, system_code: error.code });
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      visited += 1;
      if (visited > limits.max_refs * 2) {
        warnings.push({ code: 'ORIX_GIT_REF_LIMIT', maximum: limits.max_refs });
        return;
      }
      const absolute = path.join(directory, entry.name);
      const child = relative ? relative + '/' + entry.name : entry.name;
      if (entry.isSymbolicLink()) {
        warnings.push({ code: 'ORIX_GIT_REF_SYMLINK_SKIPPED', path: child });
        continue;
      }
      if (entry.isDirectory()) {
        await visit(absolute, child, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      if (refs.size >= limits.max_refs) {
        warnings.push({ code: 'ORIX_GIT_REF_LIMIT', maximum: limits.max_refs });
        return;
      }
      try {
        const buffer = await read_regular_file(absolute, git_root, 256);
        const value = buffer?.toString('utf8').trim();
        if (/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value ?? '')) refs.set('refs/' + child, value);
        else warnings.push({ code: 'ORIX_GIT_REF_INVALID', path: child });
      } catch (error) {
        warnings.push({ code: error.code ?? 'ORIX_GIT_REF_READ', path: child });
      }
    }
  }
  await visit(refs_root, '', 0);
}

function parse_loose_commit(buffer, expected_oid, object_format, maximum) {
  let raw;
  try { raw = inflateSync(buffer, { maxOutputLength: maximum }); }
  catch { return { status: 'unavailable', reason: 'loose-object-decompression-failed' }; }
  const separator = raw.indexOf(0);
  if (separator < 0) return { status: 'unavailable', reason: 'loose-object-header-invalid' };
  const header = raw.subarray(0, separator).toString('ascii');
  const match = /^commit (\d+)$/.exec(header);
  if (!match || Number(match[1]) !== raw.length - separator - 1) return { status: 'unavailable', reason: 'head-object-is-not-a-valid-commit' };
  const payload = raw.subarray(separator + 1);
  const actual_oid = createHash(object_format).update(raw).digest('hex');
  if (actual_oid !== expected_oid) return { status: 'unavailable', reason: 'loose-object-hash-mismatch' };
  const text = payload.toString('utf8');
  const split = text.indexOf('\n\n');
  if (split < 0) return { status: 'unavailable', reason: 'commit-header-terminator-missing' };
  const header_lines = text.slice(0, split).split('\n');
  const oid_length = object_format === 'sha256' ? 64 : 40;
  const oid_pattern = new RegExp('^[a-f0-9]{' + oid_length + '}$');
  const tree_lines = header_lines.filter(line => line.startsWith('tree '));
  const parent_lines = header_lines.filter(line => line.startsWith('parent '));
  const author_lines = header_lines.filter(line => line.startsWith('author '));
  const committer_lines = header_lines.filter(line => line.startsWith('committer '));
  if (tree_lines.length !== 1 || !oid_pattern.test(tree_lines[0].slice(5)) ||
      parent_lines.some(line => !oid_pattern.test(line.slice(7))) ||
      author_lines.length !== 1 || committer_lines.length !== 1) {
    return { status: 'unavailable', reason: 'commit-headers-invalid' };
  }
  const tree = tree_lines[0].slice(5);
  const parents = parent_lines.map(line => line.slice(7));
  const author = author_lines[0];
  const committer = committer_lines[0];
  const timestamp = line => {
    const value = /\s(\d{9,12})\s[+-]\d{4}$/.exec(line);
    return value ? Number(value[1]) : null;
  };
  const subject = text.slice(split + 2).split(/\r?\n/, 1)[0].replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 256);
  return {
    status: 'parsed',
    object_id: expected_oid,
    tree,
    parents,
    author_timestamp: timestamp(author),
    committer_timestamp: timestamp(committer),
    subject,
  };
}

export async function scan_git_metadata(root_path, options = {}) {
  const limits = limits_from(options);
  const root = path.resolve(root_path);
  let root_real;
  try {
    const root_stat = await fs.lstat(root);
    if (root_stat.isSymbolicLink() || !root_stat.isDirectory()) fail('ORIX_GIT_ROOT_INVALID', 'Git metadata scan requires a regular repository directory', { root });
    root_real = await fs.realpath(root);
  } catch (error) {
    if (error instanceof OrixError) throw error;
    fail('ORIX_GIT_ROOT_INVALID', 'Cannot access repository root', { root, system_code: error.code }, error);
  }
  const dot_git = path.join(root_real, '.git');
  let git_stat;
  try { git_stat = await fs.lstat(dot_git); }
  catch (error) {
    if (error.code === 'ENOENT') return { present: false, supported: true, kind: 'not-a-repository', branch: null, head_oid: null, branches: [], tags: [], remotes: [], shallow: false, object_format: null, storage: null, head_commit: null, warnings: [] };
    fail('ORIX_GIT_METADATA_READ', 'Cannot inspect .git entry', { path: dot_git, system_code: error.code }, error);
  }
  if (git_stat.isSymbolicLink()) fail('ORIX_GIT_UNSAFE_GITDIR', '.git must not be a symbolic link', { path: dot_git });
  if (git_stat.isFile()) {
    const pointer = await read_regular_file(dot_git, root_real, 4096);
    const target = /^gitdir:\s*(.+)\s*$/im.exec(pointer?.toString('utf8') ?? '')?.[1] ?? null;
    return { present: true, supported: false, kind: 'worktree-pointer', branch: null, head_oid: null, branches: [], tags: [], remotes: [], shallow: false, object_format: null, storage: null, head_commit: null, warnings: [{ code: 'ORIX_GIT_WORKTREE_POINTER_NOT_FOLLOWED', target_present: Boolean(target) }] };
  }
  if (!git_stat.isDirectory()) fail('ORIX_GIT_UNSAFE_GITDIR', '.git must be a regular directory', { path: dot_git });
  const git_root = await fs.realpath(dot_git);
  if (!inside(git_root, root_real)) fail('ORIX_GIT_PATH_ESCAPE', '.git resolves outside repository root', { path: git_root });
  const warnings = [];
  const config_buffer = await read_regular_file(path.join(git_root, 'config'), git_root, limits.max_metadata_bytes);
  const config = parse_config(config_buffer?.toString('utf8') ?? '');
  const head_buffer = await read_regular_file(path.join(git_root, 'HEAD'), git_root, 4096);
  const head_text = head_buffer?.toString('utf8').trim() ?? '';
  const symbolic = /^ref:\s*(refs\/[A-Za-z0-9._/-]+)$/.exec(head_text);
  let branch = symbolic?.[1].startsWith('refs/heads/') ? symbolic[1].slice('refs/heads/'.length) : null;
  let head_oid = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(head_text) ? head_text : null;
  const refs = new Map();
  await collect_loose_refs(path.join(git_root, 'refs'), git_root, refs, limits, warnings);
  const packed = await read_regular_file(path.join(git_root, 'packed-refs'), git_root, limits.max_metadata_bytes);
  if (packed) parse_packed_refs(packed.toString('utf8'), refs);
  if (symbolic) {
    head_oid = refs.get(symbolic[1]) ?? null;
    if (!head_oid) warnings.push({ code: 'ORIX_GIT_HEAD_REF_UNRESOLVED', ref: symbolic[1] });
  } else if (!head_oid) {
    warnings.push({ code: 'ORIX_GIT_HEAD_INVALID' });
  }
  const branches = [...refs].filter(([name]) => name.startsWith('refs/heads/')).map(([name, oid]) => ({ name: name.slice(11), object_id: oid })).sort((a, b) => a.name.localeCompare(b.name));
  const tags = [...refs].filter(([name]) => name.startsWith('refs/tags/')).map(([name, oid]) => ({ name: name.slice(10), object_id: oid })).sort((a, b) => a.name.localeCompare(b.name));
  const remote_map = [];
  for (const [name, urls] of config.remotes) for (const remote of urls) remote_map.push({ name, ...remote });
  remote_map.sort((a, b) => a.name.localeCompare(b.name) || String(a.host).localeCompare(String(b.host)));
  const shallow_buffer = await read_regular_file(path.join(git_root, 'shallow'), git_root, limits.max_metadata_bytes);
  const shallow_ids = shallow_buffer ? shallow_buffer.toString('utf8').split(/\r?\n/).filter(value => /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value)) : [];
  let pack_files = [];
  try {
    const pack_root = path.join(git_root, 'objects', 'pack');
    const pack_stat = await fs.lstat(pack_root);
    const pack_real = await fs.realpath(pack_root);
    if (pack_stat.isSymbolicLink() || !pack_stat.isDirectory() || !inside(pack_real, git_root)) throw Object.assign(new Error('Unsafe pack directory'), { code: 'ORIX_GIT_PACK_DIRECTORY_UNSAFE' });
    const entries = await fs.readdir(pack_root, { withFileTypes: true });
    pack_files = entries.filter(item => item.isFile() && /^pack-[a-f0-9]+\.pack$/.test(item.name)).map(item => item.name).sort().slice(0, limits.max_pack_files);
    if (entries.length > limits.max_pack_files) warnings.push({ code: 'ORIX_GIT_PACK_FILE_LIMIT', maximum: limits.max_pack_files });
  } catch (error) { if (error.code !== 'ENOENT') warnings.push({ code: 'ORIX_GIT_PACK_DIRECTORY_READ', system_code: error.code }); }
  let head_commit = null;
  if (head_oid) {
    const object_path = path.join(git_root, 'objects', head_oid.slice(0, 2), head_oid.slice(2));
    const compressed = await read_regular_file(object_path, git_root, Math.min(limits.max_object_bytes, 4 * 1024 * 1024)).catch(error => {
      if (error.code === 'ORIX_GIT_METADATA_READ' && error.details?.system_code === 'ENOENT') return null;
      warnings.push({ code: error.code ?? 'ORIX_GIT_HEAD_OBJECT_READ' });
      return null;
    });
    head_commit = compressed ? parse_loose_commit(compressed, head_oid, config.object_format, limits.max_object_bytes) : { status: pack_files.length ? 'packed-object-not-decoded' : 'object-not-found' };
  }
  return {
    present: true,
    supported: true,
    kind: 'git-directory',
    branch,
    head_oid,
    detached: Boolean(head_oid && !branch),
    branches,
    tags,
    remotes: remote_map,
    shallow: shallow_ids.length > 0,
    shallow_boundary_count: shallow_ids.length,
    object_format: config.object_format,
    bare: config.bare,
    storage: { pack_files: pack_files.length, packed_objects_parsed: false, loose_head_commit_parsed: head_commit?.status === 'parsed' },
    head_commit,
    warnings,
  };
}
