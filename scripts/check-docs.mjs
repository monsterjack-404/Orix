// JavaScript, scripts/check-docs.mjs, Node.js 20+, source/documentation contract checks.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { list_format_capabilities } from '../src/formats/index.mjs';
import { MCP_PROTOCOL_VERSION } from '../src/mcp/server.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = relative => fs.readFile(path.join(root, relative), 'utf8');
const [package_text, readme, cli, formats, indicators, roadmap, charter, matrix, mcp] = await Promise.all([
  read('package.json'),
  read('README.md'),
  read('docs/CLI.md'),
  read('docs/FORMATS.md'),
  read('docs/INDICATORS.md'),
  read('docs/ROADMAP.md'),
  read('docs/PRODUCT_CHARTER.md'),
  read('docs/CAPABILITY_MATRIX.md'),
  read('docs/MCP.md'),
]);
const pkg = JSON.parse(package_text);
const errors = [];

function check(label, action) {
  try { action(); }
  catch (error) { errors.push(label + ': ' + error.message); }
}

check('README release marker', () => {
  assert.match(readme, new RegExp('Current release line: \\\\*\\\\*' + pkg.version.replaceAll('.', '\\\\.') + ' —'));
});
check('CLI guide release marker', () => {
  assert.ok(cli.includes('ORIX ' + pkg.version), 'CLI guide does not mention package version ' + pkg.version);
  assert.ok(!cli.includes('ORIX 0.2.1'), 'stale 0.2.1 release claim remains');
});
check('Product charter discoverability', () => {
  assert.ok(readme.includes('[PRODUCT_CHARTER.md](docs/PRODUCT_CHARTER.md)'));
  assert.ok(readme.includes('[CAPABILITY_MATRIX.md](docs/CAPABILITY_MATRIX.md)'));
  assert.ok(charter.includes('Definition of done'));
  assert.ok(matrix.includes('Priority order'));
});
check('MCP protocol documentation', () => {
  assert.ok(mcp.includes(MCP_PROTOCOL_VERSION), 'MCP docs must state implemented protocol ' + MCP_PROTOCOL_VERSION);
  assert.ok(mcp.includes('2026-07-28'), 'MCP docs must distinguish the newer research target');
});
check('format table matches parser registry', () => {
  const table_lines = formats.split(/\r?\n/).filter(line => line.startsWith('|'));
  for (const capability of list_format_capabilities()) {
    const label = capability.format === 'PE' ? 'PE / COFF (PE)' : capability.format;
    const row = table_lines.find(line => line.startsWith('| ' + label + ' |'));
    assert.ok(row, 'missing format row for ' + capability.format);
    const columns = row.split('|').map(value => value.trim());
    const documented_parser = columns[3] === 'Yes';
    assert.equal(documented_parser, capability.parser_status === 'available',
      'parser status mismatch for ' + capability.format);
  }
});
check('indicator catalogue covers source rules', () => {
  const source = await fs.readFile(path.join(root, 'src/analyzer/indicators.mjs'), 'utf8');
  const rule_ids = [...source.matchAll(/make_indicator\(\s*['"]([^'"]+)['"]/g)].map(match => match[1]);
  assert.ok(rule_ids.length > 0, 'no source indicator rules found');
  for (const rule_id of rule_ids) assert.ok(indicators.includes(rule_id), 'missing indicator documentation: ' + rule_id);
});

if (errors.length) {
  for (const error of errors) process.stderr.write('FAIL ' + error + '\n');
  process.stderr.write('Documentation contract checks failed: ' + errors.length + '\n');
  process.exitCode = 1;
} else {
  process.stdout.write(
    'Documentation contracts passed: release ' + pkg.version +
    ', ' + list_format_capabilities().length + ' format rows, ' +
    'MCP ' + MCP_PROTOCOL_VERSION + ', and source indicator coverage.\n',
  );
}
