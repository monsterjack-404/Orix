import test from 'node:test';
import assert from 'node:assert/strict';
import { assert_linux_cgroup_integration_authorized } from '../src/providers/linux-cgroup-v2-test-gate.mjs';

const optIn = {
  GITHUB_ACTIONS: 'true',
  ORIX_CGROUP_TEST_ALLOW_ROOT_MUTATION: 'GITHUB_ACTIONS_DISPOSABLE_VM',
};

test('real-kernel cgroup integration refuses by default before host mutation', () => {
  assert.throws(
    () => assert_linux_cgroup_integration_authorized({}),
    error => error.code === 'ORIX_CGROUP_TEST_AUTHORIZATION_REQUIRED',
  );
});

test('real-kernel cgroup integration requires the explicit disposable-runner opt-in', () => {
  assert.throws(
    () => assert_linux_cgroup_integration_authorized({ GITHUB_ACTIONS: 'true' }),
    error => error.code === 'ORIX_CGROUP_TEST_AUTHORIZATION_REQUIRED',
  );
  assert.throws(
    () => assert_linux_cgroup_integration_authorized({ ...optIn, GITHUB_ACTIONS: 'false' }),
    error => error.code === 'ORIX_CGROUP_TEST_AUTHORIZATION_REQUIRED',
  );
  assert.throws(
    () => assert_linux_cgroup_integration_authorized({ ...optIn, ORIX_CGROUP_TEST_ALLOW_ROOT_MUTATION: '1' }),
    error => error.code === 'ORIX_CGROUP_TEST_AUTHORIZATION_REQUIRED',
  );
});

test('real-kernel cgroup integration accepts only both exact CI opt-in markers', () => {
  assert.equal(assert_linux_cgroup_integration_authorized(optIn), true);
});
