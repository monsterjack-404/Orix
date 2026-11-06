// Shared Linux provider-rootfs trust checks. This is preflight validation,
// not a descriptor-pinned filesystem transaction; callers must preserve the
// documented validation-to-spawn race boundary.
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';

function rootfs_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

export function assess_linux_rootfs_directory_permissions(metadata, expected_uid, allow_root_sticky = false) {
  const valid_expected_uid = Number.isSafeInteger(expected_uid) &&
    expected_uid >= 0 && expected_uid <= 0xffff_ffff;
  const valid = metadata !== null && typeof metadata === 'object' &&
    Number.isSafeInteger(metadata.uid) && metadata.uid >= 0 && metadata.uid <= 0xffff_ffff &&
    Number.isSafeInteger(metadata.mode) && metadata.mode >= 0 && metadata.mode <= 0o177777 &&
    typeof metadata.is_directory === 'boolean' &&
    typeof metadata.is_symlink === 'boolean';
  const directory = valid && metadata.is_directory;
  const symlink = !valid || metadata.is_symlink;
  const owner_is_trusted = valid && valid_expected_uid &&
    (metadata.uid === 0 || metadata.uid === expected_uid);
  const group_or_other_writable = !valid || (metadata.mode & 0o022) !== 0;
  const sticky_root_exception = valid && allow_root_sticky &&
    metadata.uid === 0 && (metadata.mode & 0o1000) !== 0;
  const writable_by_untrusted = group_or_other_writable && !sticky_root_exception;
  return Object.freeze({
    directory,
    symlink,
    owner_is_trusted,
    group_or_other_writable,
    sticky_root_exception,
    trusted: directory && !symlink && owner_is_trusted && !writable_by_untrusted,
  });
}

async function assert_no_symlink_components(absolute_path) {
  const parsed_root = path.parse(absolute_path).root;
  const relative = path.relative(parsed_root, absolute_path);
  let current = parsed_root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    let info;
    try { info = await lstat(current); }
    catch (error) {
      rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_UNAVAILABLE',
        'A provider sandbox root path component cannot be inspected',
        { component: current, reason: error.code ?? 'filesystem-error' });
    }
    if (info.isSymbolicLink() || !info.isDirectory()) {
      rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID',
        'Provider sandbox root path must contain only real directories',
        { component: current });
    }
  }
}

/**
 * Validate the provider-visible Linux rootfs before it is used for snapshot
 * staging or passed to Bubblewrap. Returns a canonical path and directory
 * identity so callers can revalidate the same object before launch.
 */
export async function validate_linux_rootfs_directory(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    throw new TypeError('sandbox_root must be an absolute filesystem path');
  }
  const requested_root = path.resolve(value);
  if (requested_root === path.parse(requested_root).root) {
    rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID',
      'The filesystem root cannot be used as a provider sandbox root');
  }

  let requested_info;
  try { requested_info = await lstat(requested_root); }
  catch (error) {
    rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_UNAVAILABLE',
      'Provider sandbox root cannot be inspected',
      { reason: error.code ?? 'filesystem-error' });
  }
  if (requested_info.isSymbolicLink() || !requested_info.isDirectory()) {
    rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID',
      'Provider sandbox root must be a non-symlink directory');
  }

  await assert_no_symlink_components(requested_root);

  let canonical_root;
  try { canonical_root = await realpath(requested_root); }
  catch (error) {
    rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_UNAVAILABLE',
      'Provider sandbox root cannot be canonicalized',
      { reason: error.code ?? 'filesystem-error' });
  }
  let canonical_info;
  try { canonical_info = await lstat(canonical_root); }
  catch (error) {
    rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_UNAVAILABLE',
      'Canonical provider sandbox root cannot be inspected',
      { reason: error.code ?? 'filesystem-error' });
  }
  if (canonical_info.isSymbolicLink() || !canonical_info.isDirectory() ||
      canonical_info.dev !== requested_info.dev || canonical_info.ino !== requested_info.ino) {
    rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_CHANGED',
      'Provider sandbox root identity changed while resolving its canonical path');
  }

  const expected_uid = process.geteuid();
  let current = canonical_root;
  let is_rootfs = true;
  for (;;) {
    let info;
    try { info = await lstat(current); }
    catch (error) {
      rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_UNAVAILABLE',
        'A canonical provider sandbox root component cannot be inspected',
        { component: current, reason: error.code ?? 'filesystem-error' });
    }
    const assessment = assess_linux_rootfs_directory_permissions({
      uid: info.uid,
      mode: info.mode,
      is_directory: info.isDirectory(),
      is_symlink: info.isSymbolicLink(),
    }, expected_uid, !is_rootfs);
    if (!assessment.trusted) {
      rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_UNTRUSTED',
        is_rootfs
          ? 'Provider sandbox root must be owned by root or the ORIX service account and not group/other writable'
          : 'Provider sandbox root ancestors must be trusted and not group/other writable (except root-owned sticky directories)',
        {
          component: current,
          owner_uid: info.uid,
          expected_uid,
          mode: info.mode & 0o7777,
          rootfs_component: is_rootfs,
        });
    }
    if (current === path.parse(current).root) break;
    current = path.dirname(current);
    is_rootfs = false;
  }

  for (const required of ['proc', 'dev', 'tmp']) {
    const mount_path = path.join(canonical_root, required);
    let entry;
    try { entry = await lstat(mount_path); }
    catch (error) {
      rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID',
        'Sandbox root is missing a required mount point',
        { mount_point: '/' + required, reason: error.code ?? 'filesystem-error' });
    }
    if (entry.isSymbolicLink() || !entry.isDirectory()) {
      rootfs_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID',
        'Sandbox mount points must be real directories',
        { mount_point: '/' + required });
    }
  }

  return Object.freeze({
    path: canonical_root,
    dev: canonical_info.dev,
    ino: canonical_info.ino,
  });
}
