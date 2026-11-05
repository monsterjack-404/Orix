// JavaScript, tests/capabilities.test.mjs, Node.js 20+, source-backed capability inventory tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { build_capability_report } from '../src/capabilities/registry.mjs';
import { list_format_capabilities } from '../src/formats/index.mjs';
import { ORIX_MCP_TOOLS, MCP_PROTOCOL_VERSION } from '../src/mcp/server.mjs';
import { RIZIN_PROVIDER_MANIFEST } from '../src/providers/rizin.mjs';

test('capability inventory is exported through the package subpath', async () => {
  const public_api = await import('@orix/cli/capabilities');
  assert.equal(typeof public_api.build_capability_report, 'function');
});

test('capability inventory is derived from live parser, MCP and provider registries', () => {
  const report = build_capability_report({
    mcp_protocol_version: MCP_PROTOCOL_VERSION,
    mcp_tools: ORIX_MCP_TOOLS,
  });
  assert.equal(report.schema_version, 'orix.capabilities.v1');
  assert.deepEqual(report.formats, list_format_capabilities().map(item => ({
    format: item.format,
    signature_recognized: true,
    parser_status: item.parser_status,
  })));
  const mcp = report.interfaces.find(item => item.id === 'mcp.stdio');
  assert.equal(mcp.protocol_version, MCP_PROTOCOL_VERSION);
  assert.deepEqual(mcp.tools.map(item => item.name), ORIX_MCP_TOOLS.map(item => item.name));
  assert.ok(mcp.tools.some(item => item.name === 'orix.capabilities'));
  const provider = report.providers.find(item => item.id === RIZIN_PROVIDER_MANIFEST.id);
  assert.equal(provider.availability, 'external-install-not-probed');
  assert.deepEqual(provider.capabilities, [...RIZIN_PROVIDER_MANIFEST.capabilities]);
});

test('capability inventory labels important missing domains instead of claiming completion', () => {
  const report = build_capability_report();
  const status = id => report.intelligence.find(item => item.id === id)?.status;
  assert.equal(status('dynamic-analysis'), 'planned');
  assert.equal(status('ai-agent-workflows'), 'planned');
  assert.equal(status('dependency-vulnerability-audit'), 'partial');
  assert.equal(status('android-apk-analysis'), 'partial');
  assert.equal(status('dotnet-analysis'), 'partial');
  assert.equal(status('website-structure-analysis'), 'partial');
  assert.equal(status('firmware-analysis'), 'partial');
  assert.equal(status('evidence-investigation-workflows'), 'partial');
  assert.equal(status('pcap-network-analysis'), 'partial');
  assert.equal(report.formats.find(item => item.format === 'CPIO newc')?.parser_status, 'available');
  assert.equal(report.formats.find(item => item.format === 'GZIP')?.parser_status, 'available');
  assert.equal(report.formats.find(item => item.format === 'PCAP')?.parser_status, 'available');
  assert.equal(status('android-device-observation'), 'planned');
  assert.equal(report.interfaces.find(item => item.id === 'desktop').status, 'planned');
  assert.ok(report.global_boundaries.length >= 3);
});
