// JavaScript, src/index.mjs, Node.js 20+, public programmatic ORIX API.
export { inspect_file, INSPECTOR_DEFAULTS } from './core/inspect.mjs';
export { scan_directory } from './analyzer/scan.mjs';
export { scan_project, render_project_markdown } from './project/intelligence.mjs';
export { evaluate_indicators } from './analyzer/indicators.mjs';
export { walk_directory } from './analyzer/walk.mjs';
export { detect_format, list_supported_formats, analyze_known_format, parse_pe, parse_elf, parse_macho, parse_macho_fat, parse_wasm, parse_zip, parse_pdf, parse_png, list_format_capabilities } from './formats/index.mjs';
export { calculate_entropy } from './core/entropy.mjs';
export { extract_strings } from './core/strings.mjs';
export { hash_buffer } from './core/hash.mjs';
export { create_evidence } from './core/evidence.mjs';
export { OrixError, normalize_error } from './core/errors.mjs';
export { DEFAULT_LIMITS, resolve_limits } from './core/limits.mjs';
export { render_json } from './reports/json.mjs';
export { render_inspection_markdown, render_scan_markdown } from './reports/markdown.mjs';
export { render_sarif } from './reports/sarif.mjs';
export { append_ledger, list_ledger, verify_ledger } from './evidence/ledger.mjs';

export { compare_reports } from './analyzer/compare.mjs';
export { render_comparison_markdown } from './reports/comparison.mjs';

export { MCP_PROTOCOL_VERSION, ORIX_MCP_TOOLS, call_orix_tool, handle_mcp_message, start_mcp_server } from './mcp/server.mjs';

export { render_cyclonedx } from './reports/cyclonedx.mjs';

export { read_json_report } from './core/read-report.mjs';

export { create_evidence_ledger, append_evidence_event, verify_evidence_ledger, read_evidence_ledger } from './core/evidence-ledger.mjs';
export { parse_lockfile } from './project/lockfiles.mjs';
export { scan_git_metadata } from './project/git-metadata.mjs';

export { PROVIDER_CONTRACT_VERSION, DEFAULT_PROVIDER_MANIFEST_LIMIT, validate_provider_manifest, parse_provider_manifest_json, read_provider_manifest } from './providers/manifest.mjs';

export { ProviderRegistry } from './providers/registry.mjs';

export { run_static_provider } from './providers/process-runner.mjs';
export { RIZIN_ADAPTER_VERSION, RIZIN_PROVIDER_MANIFEST, analyze_rizin_imports, analyze_rizin_functions, probe_rizin } from './providers/rizin.mjs';

export { build_report_view, filter_report_view, REPORT_VIEW_SEVERITIES } from './reports/view-model.mjs';
export { render_rizin_imports_markdown, render_rizin_functions_markdown } from './reports/rizin.mjs';

export { analyze_project_architecture } from './project/architecture.mjs';
export { render_architecture_markdown, render_architecture_mermaid } from './reports/architecture.mjs';

export { audit_project_dependencies, render_vulnerability_audit_markdown } from './vulnerability/osv.mjs';

export { build_capability_report } from './capabilities/registry.mjs';
export { parse_har, analyze_har_file, render_har_markdown } from './network/har.mjs';
export { parse_dex } from './formats/dex.mjs';
export { analyze_android_package } from './android/package.mjs';
