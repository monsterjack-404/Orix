// JavaScript, tests/git-metadata.test.mjs, Node.js 20+, bounded Git metadata parser tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { scan_git_metadata } from '../src/project/git-metadata.mjs';

async function with_repo(callback) {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-git-'));
  try { await callback(root); } finally { await rm(root, { recursive: true, force: true }); }
}

async function write_loose_commit(git_dir) {
  const payload = Buffer.from([
    'tree ' + 'a'.repeat(40),
    'parent ' + 'b'.repeat(40),
    'author Test User <test@example.invalid> 1793600000 +0000',
    'committer Test User <test@example.invalid> 1793600000 +0000',
    '',
    'initial fixture commit',
    '',
  ].join('\n'));
  const raw = Buffer.concat([Buffer.from('commit ' + payload.length + '\0'), payload]);
  const oid = createHash('sha1').update(raw).digest('hex');
  await mkdir(path.join(git_dir, 'objects', oid.slice(0, 2)), { recursive: true });
  await writeFile(path.join(git_dir, 'objects', oid.slice(0, 2), oid.slice(2)), deflateSync(raw));
  return oid;
}

async function write_loose_commit_payload(git_dir, payload_text) {
  const payload = Buffer.from(payload_text);
  const raw = Buffer.concat([Buffer.from('commit ' + payload.length + '\0'), payload]);
  const oid = createHash('sha1').update(raw).digest('hex');
  await mkdir(path.join(git_dir, 'objects', oid.slice(0, 2)), { recursive: true });
  await writeFile(path.join(git_dir, 'objects', oid.slice(0, 2), oid.slice(2)), deflateSync(raw));
  return oid;
}

test('Git metadata reads HEAD, branches, tags, remotes and verifies loose commit identity', async () => with_repo(async root => {
  const git = path.join(root, '.git');
  await mkdir(path.join(git, 'refs', 'heads'), { recursive: true });
  await mkdir(path.join(git, 'refs', 'tags'), { recursive: true });
  const oid = await write_loose_commit(git);
  await writeFile(path.join(git, 'HEAD'), 'ref: refs/heads/main\n');
  await writeFile(path.join(git, 'refs', 'heads', 'main'), oid + '\n');
  await writeFile(path.join(git, 'refs', 'tags', 'v1.0.0'), 'c'.repeat(40) + '\n');
  await writeFile(path.join(git, 'config'), '[core]\n repositoryformatversion = 0\n bare = false\n[remote "origin"]\n url = https://user:secret@github.com/monsterjack-404/Orix.git\n');
  const report = await scan_git_metadata(root);
  assert.equal(report.present, true);
  assert.equal(report.branch, 'main');
  assert.equal(report.head_oid, oid);
  assert.equal(report.head_commit.status, 'parsed');
  assert.equal(report.head_commit.subject, 'initial fixture commit');
  assert.equal(report.head_commit.parents.length, 1);
  assert.deepEqual(report.branches.map(item => item.name), ['main']);
  assert.deepEqual(report.tags.map(item => item.name), ['v1.0.0']);
  assert.deepEqual(report.remotes[0], { name: 'origin', transport: 'https', host: 'github.com', repository: 'monsterjack-404/Orix' });
}));

test('Git metadata resolves packed refs and detached HEADs', async () => with_repo(async root => {
  const git = path.join(root, '.git');
  await mkdir(path.join(git, 'refs'), { recursive: true });
  await writeFile(path.join(git, 'HEAD'), 'd'.repeat(40) + '\n');
  await writeFile(path.join(git, 'packed-refs'), '# pack-refs with: peeled fully-peeled\n' + 'e'.repeat(40) + ' refs/heads/release\n' + 'f'.repeat(40) + ' refs/tags/v2\n');
  const report = await scan_git_metadata(root);
  assert.equal(report.detached, true);
  assert.equal(report.head_oid, 'd'.repeat(40));
  assert.equal(report.branches[0].name, 'release');
  assert.equal(report.tags[0].name, 'v2');
}));

test('Git metadata does not follow .git symlinks or worktree pointer files', async () => with_repo(async root => {
  const outside = path.join(root, 'outside');
  await mkdir(outside);
  await symlink(outside, path.join(root, '.git'));
  await assert.rejects(scan_git_metadata(root), error => error.code === 'ORIX_GIT_UNSAFE_GITDIR');
  await rm(path.join(root, '.git'));
  await writeFile(path.join(root, '.git'), 'gitdir: ../shared/worktrees/example\n');
  const report = await scan_git_metadata(root);
  assert.equal(report.supported, false);
  assert.equal(report.kind, 'worktree-pointer');
  assert.equal(report.warnings[0].code, 'ORIX_GIT_WORKTREE_POINTER_NOT_FOLLOWED');
}));

test('Git metadata returns a stable not-a-repository record', async () => with_repo(async root => {
  const report = await scan_git_metadata(root);
  assert.equal(report.present, false);
  assert.equal(report.kind, 'not-a-repository');
  assert.deepEqual(report.branches, []);
}));

test('Git metadata validates resource limits and rejects malformed loose object hashes', async () => with_repo(async root => {
  await assert.rejects(scan_git_metadata(root, { max_refs: 0 }), error => error.code === 'ORIX_GIT_BAD_LIMIT');
  const git = path.join(root, '.git');
  await mkdir(path.join(git, 'objects'), { recursive: true });
  await writeFile(path.join(git, 'HEAD'), 'a'.repeat(40));
  const report = await scan_git_metadata(root);
  assert.equal(report.head_commit.status, 'object-not-found');
}));


test('Git metadata refuses to parse loose commits with invalid object headers', async () => with_repo(async root => {
  const git = path.join(root, '.git');
  await mkdir(path.join(git, 'objects'), { recursive: true });
  const oid = await write_loose_commit_payload(git, [
    'parent ' + 'b'.repeat(40),
    'author Test User <test@example.invalid> 1793600000 +0000',
    'committer Test User <test@example.invalid> 1793600000 +0000',
    '',
    'missing tree header',
  ].join('\\n'));
  await writeFile(path.join(git, 'HEAD'), oid + '\\n');
  const report = await scan_git_metadata(root);
  assert.equal(report.head_commit.status, 'unavailable');
  assert.equal(report.head_commit.reason, 'commit-headers-invalid');
}));
