#define _DARWIN_C_SOURCE
#include <errno.h>
#include <limits.h>
#include <sandbox.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Apple does not publish these Seatbelt SPI prototypes in the public SDK
 * sandbox.h. The symbols are reserved and may disappear in a future macOS
 * release; keep the dependency explicit and fail closed if the runtime cannot
 * provide them. The signatures match Apple's private header and Chromium's
 * established macOS Seatbelt integration.
 */
enum sandbox_filter_type {
  SANDBOX_FILTER_NONE = 0
};
extern int sandbox_init_with_parameters(
  const char *profile,
  uint64_t flags,
  const char *const parameters[],
  char **errorbuf
);
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/acl.h>
#include <fts.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int set_limit(int resource, rlim_t value, const char *label) {
  struct rlimit limit;
  limit.rlim_cur = value;
  limit.rlim_max = value;
  if (setrlimit(resource, &limit) != 0) {
    fprintf(stderr, "ORIX_MACOS_RLIMIT_ERROR=%s:%s\n", label, strerror(errno));
    return -1;
  }
  return 0;
}

static char *read_profile(const char *path) {
  FILE *file = fopen(path, "rb");
  if (!file) return NULL;
  if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
  long length = ftell(file);
  if (length < 1 || length > 65535) { fclose(file); errno = EFBIG; return NULL; }
  rewind(file);
  char *buffer = (char *)malloc((size_t)length + 1);
  if (!buffer) { fclose(file); return NULL; }
  size_t read_count = fread(buffer, 1, (size_t)length, file);
  fclose(file);
  if (read_count != (size_t)length) { free(buffer); errno = EIO; return NULL; }
  buffer[length] = '\0';
  return buffer;
}


/*
 * macOS ACL entries are independent of the POSIX mode bits checked by the
 * JavaScript preflight. Reject every non-empty extended ACL in the rootfs
 * and on its ancestors before entering Seatbelt. ENOENT means no extended
 * ACL is attached on current macOS filesystems; unsupported ACL filesystems
 * are safe only insofar as they cannot represent these entries.
 */
static int check_extended_acl(const char *path) {
  errno = 0;
  acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
  if (acl == NULL) {
    if (errno == ENOENT || errno == EOPNOTSUPP) return 0;
    fprintf(stderr, "ORIX_MACOS_ACL_CHECK_ERROR=%s:%s\\n", path, strerror(errno));
    return -1;
  }
  acl_entry_t entry;
  int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  int saved_errno = errno;
  acl_free(acl);
  if (result > 0) {
    fprintf(stderr, "ORIX_MACOS_ACL_DENIED=%s\\n", path);
    return 1;
  }
  if (result < 0) {
    fprintf(stderr, "ORIX_MACOS_ACL_CHECK_ERROR=%s:%s\\n", path, strerror(saved_errno));
    return -1;
  }
  return 0;
}

static int check_ancestor_acls(const char *root) {
  char *path = strdup(root);
  if (!path) return -1;
  for (;;) {
    int result = check_extended_acl(path);
    if (result != 0) { free(path); return result; }
    if (strcmp(path, "/") == 0) break;
    char *slash = strrchr(path, '/');
    if (!slash) { free(path); errno = EINVAL; return -1; }
    if (slash == path) path[1] = '\\0';
    else *slash = '\\0';
  }
  free(path);
  return 0;
}

static int check_rootfs_acls(const char *root) {
  int ancestors = check_ancestor_acls(root);
  if (ancestors != 0) return ancestors;

  char *paths[] = { (char *)root, NULL };
  FTS *tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
  if (!tree) {
    fprintf(stderr, "ORIX_MACOS_ACL_SCAN_ERROR=%s\\n", strerror(errno));
    return -1;
  }
  int result = 0;
  FTSENT *entry;
  for (;;) {
    errno = 0;
    entry = fts_read(tree);
    if (entry == NULL) {
      if (errno != 0 && result == 0) {
        fprintf(stderr, "ORIX_MACOS_ACL_SCAN_ERROR=%s\\n", strerror(errno));
        result = -1;
      }
      break;
    }
    if (entry->fts_info == FTS_DP) continue;
    if (entry->fts_info != FTS_D && entry->fts_info != FTS_F) {
      fprintf(stderr, "ORIX_MACOS_ACL_SCAN_ERROR=unexpected-rootfs-entry:%s\\n", entry->fts_path);
      result = -1;
      break;
    }
    int acl_result = check_extended_acl(entry->fts_accpath);
    if (acl_result != 0) { result = acl_result; break; }
  }
  if (fts_close(tree) != 0 && result == 0) {
    fprintf(stderr, "ORIX_MACOS_ACL_SCAN_ERROR=close:%s\\n", strerror(errno));
    result = -1;
  }
  return result;
}

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "ORIX_MACOS_LAUNCHER_ERROR=invalid-arguments\n");
    return 64;
  }

  const char *profile_path = argv[1];
  const char *root = argv[2];
  const char *tmp = argv[3];
  const char *provider = argv[4];

  if (set_limit(RLIMIT_CPU, 60, "cpu") != 0 ||
      set_limit(RLIMIT_FSIZE, 67108864, "file-size") != 0 ||
      set_limit(RLIMIT_NOFILE, 256, "open-files") != 0 ||
      set_limit(RLIMIT_CORE, 0, "core") != 0) return 125;

  int acl_result = check_rootfs_acls(root);
  if (acl_result != 0) {
    if (acl_result > 0)
      fprintf(stderr, "ORIX_MACOS_ACL_DENIED=provider-rootfs-or-ancestor\\n");
    else
      fprintf(stderr, "ORIX_MACOS_ACL_CHECK_FAILED=fail-closed\\n");
    return 125;
  }

  char *profile = read_profile(profile_path);
  if (!profile) {
    fprintf(stderr, "ORIX_MACOS_LAUNCHER_ERROR=profile-read:%s\n", strerror(errno));
    return 125;
  }

  /*
   * sandbox_init_with_parameters expects NULL-terminated key/value pairs,
   * not "KEY=value" strings. Keep path values separate so the profile's
   * (param ...) expressions resolve to strings rather than booleans.
   */
  const char *parameters[] = {
    "ORIX_ROOT", root,
    "ORIX_TMP", tmp,
    NULL
  };

  char *error_buffer = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  int sandbox_result = sandbox_init_with_parameters(profile, 0, parameters, &error_buffer);
  if (error_buffer) sandbox_free_error(error_buffer);
#pragma clang diagnostic pop
  free(profile);
  if (sandbox_result != 0) {
    fprintf(stderr, "ORIX_MACOS_SEATBELT_ERROR=profile-apply-failed\n");
    return 125;
  }
  if (sandbox_check(getpid(), NULL, SANDBOX_FILTER_NONE) != 1) {
    fprintf(stderr, "ORIX_MACOS_SEATBELT_ERROR=kernel-sandbox-verification-failed\n");
    return 125;
  }

  dprintf(STDERR_FILENO,
    "ORIX_MACOS_SEATBELT=1;RLIMIT_CPU=60;RLIMIT_FSIZE=67108864;RLIMIT_NOFILE=256;RLIMIT_CORE=0\n");
  execv(provider, &argv[4]);
  fprintf(stderr, "ORIX_MACOS_LAUNCHER_ERROR=exec:%s\n", strerror(errno));
  return 126;
}
