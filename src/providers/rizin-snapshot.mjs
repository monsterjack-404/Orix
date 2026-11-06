// JavaScript, src/providers/rizin-snapshot.mjs, Node.js 20+, private Rizin snapshot placement.
import { lstat, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';

function snapshot_error(reason) {
  throw new OrixError(
    'ORIX_RIZIN_SNAPSHOT_DIRECTORY_UNAVAILABLE',
    'Rizin private analysis snapshot directory could not be created',
    { details: { reason }, recoverable: true },
  );
}

export async function create_rizin_snapshot_directory(prefix, options = {}) {
  let parent_directory = tmpdir();
  const isolation = options.isolation;
  const sandbox_root = options.sandbox_root;
  if (isolation === 'required' && process.platform === 'linux' &&
      typeof sandbox_root === 'string' && path.isAbsolute(sandbox_root) && !sandbox_root.includes('\0')) {
    try {
      const root_info = await lstat(sandbox_root);
      if (!root_info.isSymbolicLink() && root_info.isDirectory()) {
        // Bubblewrap overlays /tmp with a fresh tmpfs. Put the private snapshot
        // elsewhere in the read-only root bind so the provider can read it.
        parent_directory = sandbox_root;
      }
    } catch {
      // Let the process runner report the canonical sandbox-root validation error.
    }
  }
  try {
    return await mkdtemp(path.join(parent_directory, prefix));
  } catch (error) {
    snapshot_error(error.code ?? error.name ?? 'filesystem-error');
  }
}
