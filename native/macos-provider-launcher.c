#define _DARWIN_C_SOURCE
#include <errno.h>
#include <limits.h>
#include <sandbox.h>
#include <stdint.h>

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

  char *profile = read_profile(profile_path);
  if (!profile) {
    fprintf(stderr, "ORIX_MACOS_LAUNCHER_ERROR=profile-read:%s\n", strerror(errno));
    return 125;
  }

  size_t root_size = strlen(root) + 16;
  size_t tmp_size = strlen(tmp) + 16;
  char *root_parameter = (char *)malloc(root_size);
  char *tmp_parameter = (char *)malloc(tmp_size);
  if (!root_parameter || !tmp_parameter) {
    free(profile); free(root_parameter); free(tmp_parameter);
    fprintf(stderr, "ORIX_MACOS_LAUNCHER_ERROR=parameter-allocation\n");
    return 125;
  }
  snprintf(root_parameter, root_size, "ORIX_ROOT=%s", root);
  snprintf(tmp_parameter, tmp_size, "ORIX_TMP=%s", tmp);
  const char *parameters[] = { root_parameter, tmp_parameter, NULL };

  char *error_buffer = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  int sandbox_result = sandbox_init_with_parameters(profile, 0, parameters, &error_buffer);
  if (error_buffer) sandbox_free_error(error_buffer);
#pragma clang diagnostic pop
  free(profile);
  free(root_parameter);
  free(tmp_parameter);
  if (sandbox_result != 0) {
    fprintf(stderr, "ORIX_MACOS_SEATBELT_ERROR=profile-apply-failed\n");
    return 125;
  }
  if (sandbox_check(getpid(), NULL, 0) != 1) {
    fprintf(stderr, "ORIX_MACOS_SEATBELT_ERROR=kernel-sandbox-verification-failed\n");
    return 125;
  }

  dprintf(STDERR_FILENO,
    "ORIX_MACOS_SEATBELT=1;RLIMIT_CPU=60;RLIMIT_FSIZE=67108864;RLIMIT_NOFILE=256;RLIMIT_CORE=0\n");
  execv(provider, &argv[4]);
  fprintf(stderr, "ORIX_MACOS_LAUNCHER_ERROR=exec:%s\n", strerror(errno));
  return 126;
}
