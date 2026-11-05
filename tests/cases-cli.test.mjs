// JavaScript, tests/cases-cli.test.mjs, Node.js 20+, case command parsing contracts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_arguments } from '../src/cli/arguments.mjs';

test('case CLI parser preserves operation arguments and supports JSON output', () => {
  const create = parse_arguments(['case', 'create', './workspace', 'Sample case', 'Authorized review', '--json']);
  assert.equal(create.command, 'case');
  assert.equal(create.flags.case_operation, 'create');
  assert.deepEqual(create.flags.case_args, ['./workspace', 'Sample case', 'Authorized review']);
  assert.equal(create.flags.format, 'json');
  const verify = parse_arguments(['case', 'verify', './workspace', '00000000-0000-4000-8000-000000000001']);
  assert.equal(verify.flags.case_operation, 'verify');
  assert.deepEqual(verify.flags.case_args, ['./workspace', '00000000-0000-4000-8000-000000000001']);
});

test('case CLI parser rejects unknown operations and unexpected options', () => {
  assert.throws(() => parse_arguments(['case', 'destroy', './workspace']), /case requires/);
  assert.throws(() => parse_arguments(['case', 'list', './workspace', '--unknown']), /Unknown option/);
});
