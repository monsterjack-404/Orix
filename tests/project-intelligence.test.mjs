// JavaScript, tests/project-intelligence.test.mjs, Node.js 20+, project analyzer regression tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,mkdir,rm,symlink,writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan_project,render_project_markdown } from '../src/project/intelligence.mjs';
async function with_project(callback){const root=await mkdtemp(path.join(os.tmpdir(),'orix-project-'));try{await callback(root);}finally{await rm(root,{recursive:true,force:true});}}
test('indexes languages, manifests, dependencies, symbols and local imports',async()=>with_project(async root=>{
 await mkdir(path.join(root,'src'),{recursive:true});
 await writeFile(path.join(root,'package.json'),JSON.stringify({name:'fixture-app',version:'1.2.3',dependencies:{'tiny-lib':'^2.0.0'},devDependencies:{'test-runner':'^1.0.0'},scripts:{postinstall:'echo must-not-run'}}));
 await writeFile(path.join(root,'src','index.ts'),"import { run } from './worker';\nexport function main() { return run(); }\n");
 await writeFile(path.join(root,'src','worker.ts'),"export function run() { return 42; }\n");
 await mkdir(path.join(root,'tests'));await writeFile(path.join(root,'tests','sample.test.ts'),'export const testValue = 1;\n');
 const report=await scan_project(root);
 assert.equal(report.schema_version,'orix.project.v1');assert.equal(report.summary.files_analyzed,4);
 assert.equal(report.summary.declared_dependencies,2);assert.ok(report.detection.package_managers.includes('npm-compatible'));
 assert.equal(report.detection.has_tests,true);assert.ok(report.summary.source_symbols>=3);assert.equal(report.graph.edges.length,1);
 assert.equal(report.manifests[0].scripts[0].name,'postinstall');assert.equal(report.coverage.complete,true);
}));
test('credential-shaped content is redacted from findings',async()=>with_project(async root=>{
 await writeFile(path.join(root,'config.js'),"const api_key = 'super-secret-value-123456';\n");
 const report=await scan_project(root);assert.equal(report.findings.length,1);assert.equal(report.findings[0].severity,'high');
 assert.equal(JSON.stringify(report.findings).includes('super-secret-value-123456'),false);assert.equal(report.findings[0].line,1);
}));
test('symbolic links are skipped without traversal',async()=>with_project(async root=>{
 const outside=path.join(root,'outside'),inside=path.join(root,'project');await mkdir(outside);await mkdir(inside);
 await writeFile(path.join(outside,'secret.js'),'export const outsideValue = 1;');await symlink(outside,path.join(inside,'linked'));
 const report=await scan_project(inside);assert.equal(report.files.length,0);
 assert.ok(report.coverage.skipped_entries.some(item=>item.reason==='symbolic-link'));
}));
test('file limit produces incomplete coverage',async()=>with_project(async root=>{
 await writeFile(path.join(root,'a.js'),'export const a = 1;');await writeFile(path.join(root,'b.js'),'export const b = 2;');
 const report=await scan_project(root,{max_files:1});assert.equal(report.summary.files_analyzed,1);
 assert.equal(report.coverage.truncated,true);assert.equal(report.coverage.complete,false);
}));
test('invalid manifest remains a warning and markdown renders',async()=>with_project(async root=>{
 await writeFile(path.join(root,'package.json'),'{ broken json');const report=await scan_project(root);
 assert.equal(report.manifests.length,1);assert.equal(report.manifests[0].warnings.length,1);
 assert.match(render_project_markdown(report),/ORIX Project Intelligence Report/);
}));

test('project CLI emits the versioned JSON report without executing scripts',async()=>with_project(async root=>{
 await writeFile(path.join(root,'package.json'),JSON.stringify({name:'cli-fixture',scripts:{postinstall:'throw new Error("must not execute")'}}));
 const {spawnSync}=await import('node:child_process');
 const result=spawnSync(process.execPath,['src/cli.mjs','project',root,'--json'],{cwd:path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);
 const report=JSON.parse(result.stdout);
 assert.equal(report.schema_version,'orix.project.v1');
 assert.equal(report.manifests[0].scripts[0].name,'postinstall');
}));


test('project intelligence indexes npm lockfile packages without executing install hooks', async () => with_project(async root => {
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'locked-fixture', dependencies: { alpha: '^1.0.0' }, scripts: { postinstall: 'throw new Error("must not run")' } }));
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
    name: 'locked-fixture',
    lockfileVersion: 3,
    packages: {
      '': { name: 'locked-fixture', dependencies: { alpha: '^1.0.0' } },
      'node_modules/alpha': { version: '1.2.0', dependencies: { beta: '^2.0.0' }, integrity: 'sha512-YQ==' },
      'node_modules/alpha/node_modules/beta': { version: '2.3.0' },
    },
  }));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.summary.locked_packages, 2);
  assert.equal(report.summary.lockfile_edges, 1);
  assert.equal(report.lockfiles[0].root_edges[0].name, 'alpha');
  assert.equal(report.lockfiles[0].edges[0].resolved_version, '2.3.0');
  assert.equal(report.manifests[0].scripts[0].name, 'postinstall');
}));


test('project intelligence inventories Git metadata without traversing .git objects', async () => with_project(async root => {
  const git = path.join(root, '.git');
  await mkdir(path.join(git, 'refs', 'heads'), { recursive: true });
  await writeFile(path.join(git, 'HEAD'), 'ref: refs/heads/main\n');
  await writeFile(path.join(git, 'refs', 'heads', 'main'), 'a'.repeat(40) + '\n');
  await writeFile(path.join(git, 'config'), '[core]\n repositoryformatversion = 0\n[remote "origin"]\n url = git@github.com:monsterjack-404/Orix.git\n');
  await writeFile(path.join(root, 'src.js'), 'export const value = 1;\n');
  const report = await scan_project(root);
  assert.equal(report.git.present, true);
  assert.equal(report.git.branch, 'main');
  assert.equal(report.git.head_oid, 'a'.repeat(40));
  assert.equal(report.git.remotes[0].host, 'github.com');
  assert.equal(report.summary.git_present, true);
  assert.equal(report.files.some(file => file.path.startsWith('.git/')), false);
}));


test('project Markdown includes lockfile graph status and resolved package provenance', async () => with_project(async root => {
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'markdown-fixture', dependencies: { alpha: '^1.0.0' } }));
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'markdown-fixture', dependencies: { alpha: '^1.0.0' } },
      'node_modules/alpha': { version: '1.2.0', integrity: 'sha512-YQ==' },
    },
  }));
  const report = await scan_project(root);
  const markdown = render_project_markdown(report);
  assert.match(markdown, /## Lockfile inventory/);
  assert.match(markdown, /npm-package-lock/);
  assert.match(markdown, /## Resolved package sample/);
  assert.match(markdown, /alpha/);
  assert.doesNotMatch(markdown, /\\\n/);
}));


test('project intelligence indexes pnpm lockfile package graph', async () => with_project(async root => {
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'pnpm-fixture', dependencies: { alpha: '^1.0.0' } }));
  await writeFile(path.join(root, 'pnpm-lock.yaml'), [
    "lockfileVersion: '9.0'",
    'importers:',
    '  .:',
    '    dependencies:',
    '      alpha:',
    '        specifier: ^1.0.0',
    '        version: 1.2.0',
    'packages:',
    '  alpha@1.2.0:',
    '    resolution:',
    '      integrity: sha512-alpha',
    '  beta@2.3.0:',
    '    resolution: {integrity: sha512-beta}',
    'snapshots:',
    '  alpha@1.2.0:',
    '    dependencies:',
    '      beta: 2.3.0',
    '  beta@2.3.0: {}',
  ].join('\n'));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.lockfiles[0].format, 'pnpm-lock');
  assert.equal(report.summary.locked_packages, 2);
  assert.equal(report.summary.lockfile_edges, 1);
  assert.equal(report.lockfiles[0].root_edges[0].name, 'alpha');
}));


test('project intelligence integrates Composer lockfile graph with manifest roots', async () => with_project(async root => {
  await writeFile(path.join(root, 'composer.json'), JSON.stringify({ name: 'vendor/root', require: { 'vendor/app': '^1.0' }, 'require-dev': { 'phpunit/phpunit': '^10.0' } }));
  await writeFile(path.join(root, 'composer.lock'), JSON.stringify({
    packages: [{ name: 'vendor/app', version: '1.4.0', require: { 'vendor/lib': '^2.0' } }, { name: 'vendor/lib', version: '2.3.0', require: {} }],
    'packages-dev': [{ name: 'phpunit/phpunit', version: '10.2.0', require: {} }],
  }));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.lockfiles[0].format, 'composer-lock');
  assert.equal(report.summary.locked_packages, 3);
  assert.equal(report.lockfiles[0].root_edges.length, 2);
  assert.equal(report.lockfiles[0].edges.length, 1);
}));


test('project intelligence matches go.sum checksums to go.mod direct dependencies', async () => with_project(async root => {
  await writeFile(path.join(root, 'go.mod'), 'module example.invalid/root\n\nrequire github.com/acme/direct v1.2.3\n');
  await writeFile(path.join(root, 'go.sum'), [
    'github.com/acme/direct v1.2.3 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'github.com/acme/direct v1.2.3/go.mod h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    'github.com/acme/transitive v0.9.0 h1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
  ].join('\n'));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.lockfiles[0].format, 'go-sum');
  assert.equal(report.summary.locked_packages, 2);
  assert.equal(report.lockfiles[0].root_edges.length, 1);
  assert.equal(report.lockfiles[0].root_edges[0].name, 'github.com/acme/direct');
}));


test('project intelligence resolves Poetry lock packages and dependency groups', async () => with_project(async root => {
  await writeFile(path.join(root, 'pyproject.toml'), [
    '[tool.poetry]',
    'name = "poetry-fixture"',
    'version = "1.0.0"',
    '[tool.poetry.dependencies]',
    'python = "^3.11"',
    'requests = "^2.31.0"',
    '[tool.poetry.group.dev.dependencies]',
    'pytest = "^7.0"',
  ].join('\n'));
  await writeFile(path.join(root, 'poetry.lock'), [
    '[[package]]',
    'name = "requests"',
    'version = "2.31.0"',
    'groups = ["main"]',
    '[package.dependencies]',
    'urllib3 = ">=1.21.1,<3"',
    '',
    '[[package]]',
    'name = "urllib3"',
    'version = "2.0.7"',
    'groups = ["main"]',
    '',
    '[[package]]',
    'name = "pytest"',
    'version = "7.4.0"',
    'groups = ["dev"]',
    '',
    '[metadata]',
    'lock-version = "2.0"',
  ].join('\n'));
  const report = await scan_project(root);
  assert.equal(report.lockfiles[0].format, 'poetry-lock');
  assert.equal(report.summary.locked_packages, 3);
  assert.equal(report.lockfiles[0].root_edges.length, 2);
  assert.equal(report.lockfiles[0].edges.length, 1);
  assert.equal(report.dependencies.find(item => item.name === 'pytest').dependency_type, 'dev');
}));

test('project intelligence integrates Pipfile.lock with declared runtime and development packages', async () => with_project(async root => {
  await writeFile(path.join(root, 'Pipfile'), [
    '[packages]',
    'requests = "==2.31.0"',
    '[dev-packages]',
    'pytest = "==7.4.0"',
  ].join('\n'));
  await writeFile(path.join(root, 'Pipfile.lock'), JSON.stringify({
    _meta: { pipfile_spec: 6 },
    default: { requests: { version: '==2.31.0', hashes: [] } },
    develop: { pytest: { version: '==7.4.0', hashes: [] } },
  }));
  const report = await scan_project(root);
  assert.equal(report.lockfiles[0].format, 'pipfile-lock');
  assert.equal(report.summary.locked_packages, 2);
  assert.equal(report.lockfiles[0].root_edges.length, 2);
  assert.equal(report.lockfiles[0].complete, false);
}));


test('project intelligence integrates NuGet and Gradle lock inventories', async () => with_project(async root => {
  await writeFile(path.join(root, 'packages.lock.json'), JSON.stringify({
    version: 1,
    dependencies: {
      'net8.0': {
        'Newtonsoft.Json': { type: 'Direct', requested: '[13.0.3, )', resolved: '13.0.3', contentHash: 'sha512-hash', dependencies: {} },
      },
    },
  }));
  await writeFile(path.join(root, 'gradle.lockfile'), 'com.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath\n');
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 2);
  assert.ok(report.lockfiles.some(item => item.format === 'nuget-packages-lock'));
  assert.ok(report.lockfiles.some(item => item.format === 'gradle-lock'));
  assert.equal(report.summary.locked_packages, 2);
}));


test('malformed JSON lockfiles retain their ecosystem and format identity', async () => {
  const cases = [
    ['package-lock.json', 'npm', 'npm-package-lock'],
    ['composer.lock', 'composer', 'composer-lock'],
    ['Pipfile.lock', 'python', 'pipfile-lock'],
    ['packages.lock.json', 'nuget', 'nuget-packages-lock'],
  ];
  for (const [filename, ecosystem, format] of cases) {
    await with_project(async root => {
      await writeFile(path.join(root, filename), '{ malformed json');
      const report = await scan_project(root);
      assert.equal(report.lockfiles.length, 1, filename);
      assert.equal(report.lockfiles[0].ecosystem, ecosystem, filename);
      assert.equal(report.lockfiles[0].format, format, filename);
      assert.equal(report.lockfiles[0].complete, false, filename);
      assert.ok(report.lockfiles[0].warnings.some(item => item.code === 'ORIX_LOCKFILE_INVALID_JSON'), filename);
    });
  }
});


test('project intelligence resolves uv.lock workspace roots and transitive dependencies', async () => with_project(async root => {
  await writeFile(path.join(root, 'pyproject.toml'), [
    '[project]',
    'name = "uv-fixture"',
    'version = "1.0.0"',
    'dependencies = ["requests>=2.31.0"]',
  ].join('\n'));
  await writeFile(path.join(root, 'uv.lock'), [
    'version = 1',
    'revision = 3',
    'requires-python = ">=3.11"',
    '',
    '[[package]]',
    'name = "uv-fixture"',
    'version = "1.0.0"',
    'source = { editable = "." }',
    'dependencies = [',
    '  { name = "requests", version = ">=2.31.0" },',
    ']',
    '',
    '[[package]]',
    'name = "requests"',
    'version = "2.31.0"',
    'source = { registry = "https://pypi.org/simple" }',
    'dependencies = [',
    '  { name = "urllib3", version = ">=1.26" },',
    ']',
    '',
    '[[package]]',
    'name = "urllib3"',
    'version = "2.2.0"',
    'source = { registry = "https://pypi.org/simple" }',
  ].join('\n'));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.lockfiles[0].ecosystem, 'python');
  assert.equal(report.lockfiles[0].format, 'uv-lock');
  assert.equal(report.lockfiles[0].lockfile_version, 1);
  assert.equal(report.lockfiles[0].packages.length, 3);
  assert.equal(report.lockfiles[0].root_edges.length, 1);
  assert.equal(report.lockfiles[0].root_edges[0].name, 'requests');
  assert.equal(report.lockfiles[0].edges.length, 1);
  assert.equal(report.lockfiles[0].edges[0].resolved_version, '2.2.0');
  assert.equal(report.lockfiles[0].complete, true);
  assert.equal(report.summary.locked_packages, 3);
}));


test('malformed JSON manifest maps do not create phantom dependencies or scripts', async () => with_project(async root => {
  await writeFile(path.join(root, 'package.json'), JSON.stringify({
    name: 'malformed-fixture',
    dependencies: 'not-an-object',
    devDependencies: ['not-a-map'],
    scripts: { postinstall: { command: 'must-not-be-stringified' } },
  }));
  const report = await scan_project(root);
  assert.equal(report.manifests.length, 1);
  assert.equal(report.manifests[0].dependencies.length, 0);
  assert.equal(report.manifests[0].scripts.length, 0);
  assert.ok(report.manifests[0].warnings.length >= 3);
  assert.equal(report.summary.declared_dependencies, 0);
}));


test('project intelligence treats files with late NUL bytes as binary', async () => with_project(async root => {
  const binary = Buffer.concat([
    Buffer.from('export const visiblePrefix = 1;\\n' + 'A'.repeat(9000)),
    Buffer.from([0]),
    Buffer.from('const api_key = "late-secret-value-123456";'),
  ]);
  await writeFile(path.join(root, 'payload.js'), binary);
  const report = await scan_project(root);
  assert.equal(report.files.length, 1);
  assert.equal(report.files[0].text_analyzed, false);
  assert.equal(report.files[0].symbols.length, 0);
  assert.equal(report.findings.length, 0);
}));


test('project file-size skips make inventory coverage explicitly incomplete', async () => with_project(async root => {
  await writeFile(path.join(root, 'large.js'), 'export const largePayload = 123456789;');
  const report = await scan_project(root, { max_file_bytes: 8 });
  assert.equal(report.files.length, 0);
  assert.equal(report.coverage.complete, false);
  assert.equal(report.coverage.truncated, true);
  assert.ok(report.coverage.skipped_entries.some(item => item.reason === 'file-size-limit'));
}));


test('project intelligence rejects zero Git limits before calling the Git reader', async () => with_project(async root => {
  await assert.rejects(
    scan_project(root, { max_git_refs: 0 }),
    /Invalid project limit: max_git_refs/,
  );
}));


test('project intelligence integrates offline website structure and findings', async () => with_project(async root => {
  await mkdir(path.join(root, 'assets'), { recursive: true });
  await writeFile(path.join(root, 'index.html'), '<html lang="en"><head><title>Project site</title><script src="./assets/app.js"></script></head><body><a href="javascript:alert(1)">bad</a></body></html>');
  await writeFile(path.join(root, 'assets', 'app.js'), 'void 0;');
  const report = await scan_project(root);
  assert.equal(report.website.detected, true);
  assert.equal(report.website.summary.pages_analyzed, 1);
  assert.equal(report.website.pages[0].title, 'Project site');
  assert.ok(report.summary.website_findings >= 1);
  assert.ok(report.findings.some(item => item.rule_id === 'ORIX_WEB_JAVASCRIPT_URL'));
  assert.match(render_project_markdown(report), /Website pages/);
}));

test('project intelligence inventories declarations and imports across a broad polyglot repository', async () => with_project(async root => {
  const fixtures = {
    'web/main.ts': "import type { Config } from './types';\nexport interface AppConfig {}\nexport type Mode = 'fast' | 'safe';\n",
    'web/types.ts': "export type Config = { enabled: boolean };\n",
    'python/app.py': "import os\nfrom .helpers import normalize\nclass Worker:\n    def run(self):\n        return normalize(os.getcwd())\n",
    'python/helpers.py': "def normalize(value):\n    return value.strip()\n",
    'go/app.go': 'package app\nimport "fmt"\ntype Service struct {}\nfunc Start() { fmt.Println("ok") }\n',
    'rust/lib.rs': 'use std::fmt;\npub struct Engine;\npub fn start() {}\n',
    'native/main.cpp': '#include <iostream>\n#include "./helpers.hpp"\nclass Engine {};\nvoid launch() {}\n',
    'native/helpers.hpp': 'struct Helper {};\n',
    'native/c_main.c': '#include "./helpers.h"\nstruct Record { int id; };\nint main(void) { return 0; }\n',
    'native/helpers.h': 'typedef struct Helper { int value; } Helper;\n',
    'objc/App.mm': '#import <Foundation/Foundation.h>\n@interface Bridge : NSObject\n@end\n',
    'jvm/Main.java': 'import java.util.List;\npublic class Main {}\n',
    'jvm/App.kt': 'import kotlin.collections.List\nclass App\n',
    'dotnet/Program.cs': 'using System.Collections.Generic;\npublic class Runner {}\n',
    'apple/App.swift': 'import Foundation\nstruct App {}\nfunc launch() {}\n',
    'php/index.php': 'use App\\Service;\nrequire "./Service.php";\nclass Controller {}\nfunction handle() {}\n',
    'php/Service.php': '<?php class Service {}',
    'ruby/app.rb': "require 'json'\nrequire_relative './worker'\nclass Worker\n  def run\n  end\nend\n",
    'ruby/worker.rb': 'class WorkerHelper; end\n',
    'scripts/build.sh': 'source ./helpers.sh\nfunction deploy() { :; }\n',
    'scripts/helpers.sh': 'function prepare() { :; }\n',
    'db/schema.sql': 'CREATE TABLE users (id INTEGER);\nCREATE OR REPLACE VIEW active_users AS SELECT * FROM users;\n',
    'dart/main.dart': "import './models.dart';\nclass Runner {}\n",
    'dart/models.dart': 'class Model {}\n',
    'scala/App.scala': 'import scala.collection.mutable\nobject App {}\n',
    'lua/init.lua': "local json = require('json')\nfunction boot() end\n",
    'perl/script.pl': 'sub main { return 1; }\n',
    'r/analysis.R': 'fit <- function(x) { x }\n',
    'elixir/lib.ex': 'defmodule Demo do\n  def run, do: :ok\nend\n',
    'haskell/Main.hs': 'module Main where\nmain :: IO ()\nmain = pure ()\n',
    'clojure/core.clj': '(ns demo.core)\n(defn start [] :ok)\n',
    'fsharp/Library.fs': 'module Library\nlet run value = value\n',
    'powershell/build.ps1': 'function Invoke-Build { Write-Output "ok" }\n',
    'vb/Program.vb': 'Public Class Program\nEnd Class\n',
    'objc/App.m': '#import <Foundation/Foundation.h>\n@interface App : NSObject\n@end\n',
  };
  for (const [file, content] of Object.entries(fixtures)) {
    await mkdir(path.dirname(path.join(root, file)), { recursive: true });
    await writeFile(path.join(root, file), content);
  }
  const report = await scan_project(root);
  const expected = ['TypeScript','Python','Go','Rust','C++','C','Java','Kotlin','C#','Swift','PHP','Ruby','Shell','SQL','Dart','Scala','Lua','Perl','R','Elixir','Haskell','Clojure','F#','PowerShell','Visual Basic','Objective-C','Objective-C++'];
  for (const language of expected) assert.ok(report.summary.languages[language] >= 1, 'missing language: ' + language);
  assert.ok(report.summary.source_symbols >= 25);
  assert.ok(report.summary.source_import_edges >= 6);
  assert.ok(report.files.find(file => file.path === 'web/main.ts').symbols.some(symbol => symbol.name === 'AppConfig'));
  assert.ok(report.files.find(file => file.path === 'python/app.py').symbols.some(symbol => symbol.name === 'Worker'));
  assert.ok(report.files.find(file => file.path === 'dotnet/Program.cs').symbols.some(symbol => symbol.name === 'Runner'));
  assert.ok(report.files.find(file => file.path === 'db/schema.sql').symbols.some(symbol => symbol.name === 'users'));
  assert.ok(report.graph.edges.some(edge => edge.from === 'web/main.ts' && edge.to === 'web/types.ts'));
  assert.ok(report.graph.edges.some(edge => edge.from === 'python/app.py' && edge.to === 'python/helpers.py'));
  assert.ok(report.graph.edges.some(edge => edge.from === 'dart/main.dart' && edge.to === 'dart/models.dart'));
  assert.ok(report.graph.edges.some(edge => edge.from === 'native/main.cpp' && edge.to === 'native/helpers.hpp'));
  assert.ok(report.graph.edges.some(edge => edge.from === 'native/c_main.c' && edge.to === 'native/helpers.h'));
  assert.ok(report.graph.edges.some(edge => edge.from === 'php/index.php' && edge.to === 'php/Service.php'));
  assert.ok(report.graph.edges.some(edge => edge.from === 'ruby/app.rb' && edge.to === 'ruby/worker.rb'));
  assert.equal(report.coverage.complete, true);
}));


test('TypeScript type-only imports and exported declaration metadata are preserved', async () => with_project(async root => {
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(path.join(root, 'src', 'types.ts'), 'export interface User { id: string; }\\n');
  await writeFile(path.join(root, 'src', 'index.ts'), [
    "import type { User } from './types';",
    "export type { User as PublicUser } from './types';",
    'export interface UserShape { id: string; }',
    'export declare const API_VERSION: string;',
    'export class InternalHelper {}',
  ].join('\\n'));
  const report = await scan_project(root);
  const source = report.files.find(file => file.path === 'src/index.ts');
  assert.ok(source);
  assert.deepEqual(source.imports.map(item => item.kind).sort(), ['type-import', 'type-re-export']);
  assert.ok(source.imports.every(item => item.resolved_path === 'src/types.ts'));
  assert.equal(source.symbols.find(item => item.name === 'UserShape')?.exported, true);
  assert.equal(source.symbols.find(item => item.name === 'API_VERSION')?.exported, true);
  assert.equal(source.symbols.find(item => item.name === 'InternalHelper')?.exported, true);
}));
