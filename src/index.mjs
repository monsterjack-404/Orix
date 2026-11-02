// JavaScript, src/index.mjs, Node.js 20+, public programmatic ORIX API.
export { inspect_file, INSPECTOR_DEFAULTS } from './core/inspect.mjs';
export { scan_directory } from './analyzer/scan.mjs';
export { scan_project, render_project_markdown } from './project/intelligence.mjs';
export { evaluate_indicators } from './analyzer/indicators.mjs';
export { walk_directory } from './analyzer/walk.mjs';
export { detect_format, list_supported_formats, analyze_known_format, parse_pe, parse_elf, parse_macho, parse_macho_fat, parse_wasm, parse_zip, parse_pdf, list_format_capabilities } from './formats/index.mjs';
export { calculate_entropy } from './core/entropy.mjs';
export { extract_strings } from './core/strings.mjs';
export { hash_buffer } from './core/hash.mjs';
export { create_evidence } from './core/evidence.mjs';
export { OrixError, normalize_error } from './core/errors.mjs';
export { DEFAULT_LIMITS, resolve_limits } from './core/limits.mjs';
export { render_json } from './reports/json.mjs';
export { render_inspection_markdown, render_scan_markdown } from './reports/markdown.mjs';
