// JavaScript, src/providers/rizin-snapshot.mjs, Node.js 20+, private Rizin snapshot placement.
import { lstat, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';
import { validate_linux_rootfs_directory } from './linux-rootfs-trust.mjs';

function snapshot_error(reason) {
  throw new OrixError(
    'ORIX_RIZIN_SNAPSHOT_DIRECTORY_UNAVAILABLE',
    'Rizin private analysis snapshot directory could not be created',
    { details: { reason }, recoverable: true },
  );
}

function snapshot_root_changed() {
  throw new OrixError(
    'ORIX_PROVIDER_SANDBOX_ROOT_CHANGED',
    'Provider sandbox root changed while preparing the private Rizin snapshot',
    { recoverable: true },
  );
}

export async function create_rizin_snapshot_directory(prefix, options = {}) {
  const isolation = options.isolation ?? 'none';
  if (isolation !== 'none' && isolation !== 'required') {
    throw new TypeError('isolation must be either none or required');
  }

  let parent_directory = tmpdir();
  let initial_rootfs = null;
  if (isolation === 'required') {
    if (process.platform !== 'linux') {
      throw new OrixError(
        'ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
        'Required provider isolation currently has no enforced backend for this operating system',
        { details: { platform: process.platform }, recoverable: true },
      );
    }
    // Do not stage an artifact in an untrusted, missing, or incomplete rootfs.
    // Bubblewrap replaces /tmp with a fresh tmpfs, so the private snapshot must
    // live inside the already-validated read-only rootfs tree.
    initial_rootfs = await validate_linux_rootfs_directory(options.sandbox_root);
    parent_directory = initial_rootfs.path;
  }

  let snapshot_directory = null;
  try {
    snapshot_directory = await mkdtemp(path.join(parent_directory, prefix));
    if (initial_rootfs) {
      // Narrow the mkdir hand-off window: prove that the parent is still the
      // exact directory validated before mkdtemp, and that the new directory
      // is directly contained by that canonical rootfs.
      const final_rootfs = await validate_linux_rootfs_directory(options.sandbox_root);
      if (final_rootfs.path !== initial_rootfs.path ||
          final_rootfs.dev !== initial_rootfs.dev ||
          final_rootfs.ino !== initial_rootfs.ino) {
        snapshot_root_changed();
      }
      const [snapshot_info, snapshot_realpath] = await Promise.all([
        lstat(snapshot_directory),
        realpath(snapshot_directory),
      ]);
      if (snapshot_info.isSymbolicLink() || !snapshot_info.isDirectory() ||
          path.dirname(snapshot_realpath) !== initial_rootfs.path) {
        snapshot_root_changed();
      }
    }
    return snapshot_directory;
  } catch (error) {
    if (snapshot_directory) {
      await rm(snapshot_directory, { recursive: true, force: true }).catch(() => {});
    }
    if (error instanceof OrixError || error instanceof TypeError) throw error;
    snapshot_error(error.code ?? error.name ?? 'filesystem-error');
  }
}
