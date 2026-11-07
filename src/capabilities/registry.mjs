// JavaScript, src/capabilities/registry.mjs, Node.js 20+, source-backed capability inventory.

import { list_format_capabilities } from '../formats/index.mjs';
import { RIZIN_PROVIDER_MANIFEST } from '../providers/rizin.mjs';

const text = (value, maximum = 2_000) =>
  typeof value === 'string' && value.length > 0 ? value.slice(0, maximum) : null;

/**
 * Build a deterministic capability inventory from the active parser registry,
 * declared provider manifest and the MCP tool definitions supplied by caller.
 * Provider availability is never probed as a side effect.
 */
export function build_capability_report({
  mcp_protocol_version = null,
  mcp_tools = [],
} = {}) {
  const tools = Array.isArray(mcp_tools)
    ? mcp_tools.filter(tool => tool && typeof tool.name === 'string').map(tool => ({
      name: text(tool.name, 128),
      description: text(tool.description, 500),
      annotations: {
        read_only: tool.annotations?.readOnlyHint === true,
        destructive: tool.annotations?.destructiveHint === true,
        idempotent: tool.annotations?.idempotentHint === true,
        open_world: tool.annotations?.openWorldHint === true,
      },
    }))
    : [];

  return {
    schema_version: 'orix.capabilities.v1',
    product: {
      name: 'ORIX — Open Research & Intelligence eXplorer',
      promise: 'Understand. Analyze. Engineer.',
      operating_model: 'local-first static analysis with explicit opt-in bounded providers and network lookups',
    },
    formats: list_format_capabilities().map(item => ({
      format: item.format,
      signature_recognized: true,
      parser_status: item.parser_status,
    })),
    interfaces: [
      {
        id: 'cli',
        status: 'implemented',
        entrypoint: 'src/cli.mjs',
        boundaries: ['Local command-line execution; external provider and OSV network actions are explicit opt-ins.'],
      },
      {
        id: 'programmatic-api',
        status: 'implemented',
        entrypoint: 'src/index.mjs',
        boundaries: ['Node.js ESM API; no promise of ABI stability before a documented stable release.'],
      },
      {
        id: 'mcp.stdio',
        status: 'implemented',
        entrypoint: 'src/mcp.mjs',
        protocol_version: text(mcp_protocol_version, 40),
        tools,
        boundaries: [
          'Local stdio transport only; no HTTP listener or remote authorization.',
          'Tool annotations are client hints, not an authorization boundary.',
          'Workspace confinement and server-side argument validation remain authoritative.',
        ],
      },
      {
        id: 'web.report-viewer',
        status: 'partial',
        entrypoint: 'scripts/serve-web.mjs',
        boundaries: ['Local report viewer; imports saved reports and does not run live analysis in the browser.'],
      },
      {
        id: 'desktop',
        status: 'planned',
        entrypoint: null,
        boundaries: ['No desktop shell is currently shipped.'],
      },
    ],
    providers: [{
      id: RIZIN_PROVIDER_MANIFEST.id,
      name: RIZIN_PROVIDER_MANIFEST.name,
      status: 'partial',
      capabilities: [...RIZIN_PROVIDER_MANIFEST.capabilities],
      input_formats: [...RIZIN_PROVIDER_MANIFEST.input_formats],
      supported_platforms: [...RIZIN_PROVIDER_MANIFEST.supported_platforms],
      availability: 'external-install-not-probed',
      execution: { ...RIZIN_PROVIDER_MANIFEST.execution },
      boundaries: [
        'The provider executable must be selected explicitly.',
        'Process time and output are bounded, but the process runner is not an OS sandbox.',
      ],
    }],
    report_formats: [
      { id: 'json', status: 'implemented', standard: null },
      { id: 'markdown', status: 'implemented', standard: null },
      { id: 'sarif', status: 'implemented', standard: '2.1.0' },
      { id: 'cyclonedx', status: 'partial', standard: '1.5' },
      { id: 'mermaid', status: 'partial', standard: null },
      { id: 'csv-viewer-export', status: 'partial', standard: null },
    ],
    intelligence: [
      { id: 'artifact-static-analysis', status: 'implemented', boundary: 'Format support is explicitly listed in formats; parser coverage is not full standards validation.' },
      { id: 'project-source-intelligence', status: 'partial', boundary: 'Syntax-pattern inventory, not a compiler or complete dependency resolver.' },
      { id: 'architecture-graph', status: 'partial', boundary: 'Static local-import graph; not a runtime call graph or dead-code proof.' },
      { id: 'dependency-vulnerability-audit', status: 'partial', boundary: 'Opt-in OSV exact-version queries; no reachability proof or full local ecosystem range evaluation.' },
      { id: 'native-binary-analysis', status: 'partial', boundary: 'Bounded PE, ELF, Mach-O and WebAssembly structural parsers; not a complete loader, debugger or decompiler.' },
      { id: 'native-decompilation', status: 'partial', boundary: 'Optional Rizin pdg pseudocode is supported when the separately installed rz-ghidra plugin is available; no plugin is bundled or installed, the dedicated Ghidra workflow and real-version compatibility matrix remain outstanding.' },
      { id: 'javascript-electron-analysis', status: 'partial', boundary: 'Bounded JS/TS lexical import and declaration analysis plus Electron static triage for direct literal webPreferences settings; not a full AST, data-flow, IPC or runtime model.' },
      { id: 'dotnet-analysis', status: 'partial', boundary: 'PE/CLI header, CLR runtime flags, entry-point token and metadata stream inventory are bounded; metadata tables, IL bodies/instructions, PDB and decompilation are not implemented.' },
      { id: 'android-apk-analysis', status: 'partial', boundary: 'Bounded APK ZIP entry analysis with CRC32 validation, binary/plain XML manifest metadata, DEX header/link/data/table validation, class descriptors, Adler32/SHA-1 integrity checks, native ABI inventory and signer-entry inventory are implemented; no method-body/bytecode decoding, resource/intent-filter resolution, cryptographic signing verification or device/runtime observation.' },
      { id: 'android-package-inventory', status: 'partial', boundary: 'Offline bounded APK/AAB ZIP inventory, APK binary-XML manifest metadata, stored unencrypted DEX 035/037/038/039 metadata, multidex/native-library and v1 signature-filename hints; no archive extraction/decompression, AAB protobuf/resources, signature verification or device access.' },
      { id: 'android-device-observation', status: 'planned', boundary: 'No ADB, emulator or Frida device observation provider is shipped.' },
      { id: 'website-structure-analysis', status: 'partial', boundary: 'Bounded offline HTML inventory plus linked/inline JavaScript import and declaration candidates with a depth/file/byte-capped local module graph; no script execution, standards-complete DOM, source-map analysis or live browser observation.' },
      { id: 'browser-observation', status: 'planned', boundary: 'No Playwright/CDP live browser observation provider is shipped.' },
      { id: 'network-har-analysis', status: 'implemented', boundary: 'Offline HAR 1.2 metadata analysis with bounded entries; payloads and header/query values are excluded, and captured traffic is not independently verified.' },
      { id: 'pcap-network-analysis', status: 'partial', boundary: 'Classic PCAP 2.4 and bounded PCAPNG block/interface/packet metadata with supported link-layer endpoint extraction; IPv6 extension traversal, reassembly, checksum validation, application protocols, payload export and live capture are not implemented.' },
      { id: 'firmware-analysis', status: 'partial', boundary: 'Bounded raw CPIO newc/CRC-newc and USTAR/PAX/GNU TAR metadata inventory, plus GZIP member decompression with CRC/ISIZE verification and nested CPIO/TAR parsing, are available; no general filesystem extraction or filesystem parser.' },
      { id: 'evidence-investigation-workflows', status: 'partial', boundary: 'Persistent local event-sourced cases, SHA-256 ledger, workspace-local artifact references, stored analysis reports, finding lifecycle, notes, typed case-local relationships and unsigned portable bundles are implemented; cross-case graph/search, sample object storage, signatures, retention controls, multi-user access control and browser case UI remain unsupported.' },
      { id: 'recorded-behavior-replay', status: 'planned', boundary: 'No normalized behavior trace or deterministic replay engine is shipped.' },
      { id: 'ai-rl-environments', status: 'planned', boundary: 'No Gymnasium-compatible environment adapter or RL training runtime is shipped.' },
      { id: 'evidence-ledger', status: 'implemented', boundary: 'Tamper-evident hash chain, not a digital signature or trusted timestamp.' },
      { id: 'dynamic-analysis', status: 'planned', boundary: 'No target execution or process instrumentation is shipped.' },
      { id: 'ai-agent-workflows', status: 'planned', boundary: 'No autonomous model router or code-editing agent is shipped.' },
    ],
    global_boundaries: [
      'A clean static report is not a safety or malware-free certification.',
      'Untrusted project scripts, builds and tests are not executed by repository analysis.',
      'Planned and partial capabilities must not be described as complete.',
    ],
  };
}
