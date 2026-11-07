// Explicit guard for the destructive real-kernel cgroup integration harness.
// The CI workflow supplies both markers inside its disposable privileged VM.
const REQUIRED_OPT_IN = 'GITHUB_ACTIONS_DISPOSABLE_VM';

export function assert_linux_cgroup_integration_authorized(environment = process.env) {
  if (environment?.GITHUB_ACTIONS !== 'true' ||
      environment?.ORIX_CGROUP_TEST_ALLOW_ROOT_MUTATION !== REQUIRED_OPT_IN) {
    const error = new Error(
      'The real-kernel cgroup integration harness mutates root-level cgroup controller state; ' +
      'run it only from the explicitly authorized disposable GitHub Actions VM',
    );
    error.code = 'ORIX_CGROUP_TEST_AUTHORIZATION_REQUIRED';
    throw error;
  }
  return true;
}
