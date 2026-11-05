// JavaScript, src/project/website.mjs, Node.js 20+, bounded offline HTML structure and security triage.
import path from 'node:path';
import { analyze_javascript_source } from './javascript.mjs';

const DEFAULTS = Object.freeze({
  max_pages: 500,
  max_page_bytes: 1024 * 1024,
  max_tags_per_page: 20000,
  max_attributes_per_page: 100000,
  max_refs_per_page: 2000,
  max_findings: 500,
  max_script_files: 500,
  max_script_depth: 8,
  max_script_bytes: 2 * 1024 * 1024,
  max_total_script_bytes: 16 * 1024 * 1024,
  max_script_tokens: 50000,
  max_script_imports: 1000,
  max_script_symbols: 1000,
});

function limits_for(options) {
  const result = {};
  for (const [key, fallback] of Object.entries(DEFAULTS)) {
    const value = options[key] ?? fallback;
    if (!Number.isSafeInteger(value) || value < 1 || value > fallback) {
      throw new TypeError(key + ' must be a positive integer no greater than ' + fallback);
    }
    result[key] = value;
  }
  return result;
}

function line_starts(source) {
  const result = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) result.push(index + 1);
  }
  return result;
}

function line_for(starts, offset) {
  let low = 0;
  let high = starts.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle] <= offset) low = middle + 1;
    else high = middle;
  }
  return low;
}

function is_space(code) {
  return code === 9 || code === 10 || code === 12 || code === 13 || code === 32;
}

function is_name_end(code) {
  return code === 0 || is_space(code) || code === 47 || code === 62 || code === 61;
}

function tokenize_html(source, limits) {
  const tags = [];
  const starts = line_starts(source);
  let cursor = 0;
  let attributes_seen = 0;
  let truncated = false;
  while (cursor < source.length) {
    const opening = source.indexOf('<', cursor);
    if (opening < 0) break;
    cursor = opening + 1;
    if (source.startsWith('!--', cursor)) {
      const end = source.indexOf('-->', cursor + 3);
      if (end < 0) break;
      cursor = end + 3;
      continue;
    }
    if (source[cursor] === '!' || source[cursor] === '?') {
      const end = source.indexOf('>', cursor + 1);
      if (end < 0) break;
      cursor = end + 1;
      continue;
    }
    let closing = false;
    if (source[cursor] === '/') {
      closing = true;
      cursor += 1;
    }
    while (cursor < source.length && is_space(source.charCodeAt(cursor))) cursor += 1;
    const name_start = cursor;
    while (cursor < source.length) {
      const code = source.charCodeAt(cursor);
      if (is_name_end(code)) break;
      cursor += 1;
      if (cursor - name_start > 64) break;
    }
    if (cursor === name_start || cursor - name_start > 64) {
      const end = source.indexOf('>', cursor);
      if (end < 0) break;
      cursor = end + 1;
      continue;
    }
    const name = source.slice(name_start, cursor).toLowerCase();
    const attrs = [];
    if (closing) {
      const end = source.indexOf('>', cursor);
      if (end < 0) break;
      cursor = end + 1;
      tags.push({ name, closing: true, attrs, offset: opening, line: line_for(starts, opening) });
      if (tags.length >= limits.max_tags_per_page) { truncated = true; break; }
      continue;
    }
    let tag_closed = false;
    while (cursor < source.length) {
      while (cursor < source.length && is_space(source.charCodeAt(cursor))) cursor += 1;
      if (source[cursor] === '>') {
        cursor += 1;
        tag_closed = true;
        break;
      }
      if (source[cursor] === '/' && source[cursor + 1] === '>') {
        cursor += 2;
        tag_closed = true;
        break;
      }
      const attr_start = cursor;
      while (cursor < source.length && !is_name_end(source.charCodeAt(cursor))) cursor += 1;
      if (cursor === attr_start) {
        cursor += 1;
        continue;
      }
      const attr_name = source.slice(attr_start, cursor).toLowerCase();
      while (cursor < source.length && is_space(source.charCodeAt(cursor))) cursor += 1;
      let value = '';
      if (source[cursor] === '=') {
        cursor += 1;
        while (cursor < source.length && is_space(source.charCodeAt(cursor))) cursor += 1;
        const quote = source[cursor] === '"' || source[cursor] === "'" ? source[cursor++] : null;
        const value_start = cursor;
        if (quote) {
          while (cursor < source.length && source[cursor] !== quote) cursor += 1;
          value = source.slice(value_start, cursor);
          if (source[cursor] === quote) cursor += 1;
          else truncated = true;
        } else {
          while (cursor < source.length && !is_space(source.charCodeAt(cursor)) && source[cursor] !== '>') cursor += 1;
          value = source.slice(value_start, cursor).replace(/\/$/, (match, offset, whole) => whole.length > 1 && whole.endsWith('/>') ? '' : match);
        }
      }
      attributes_seen += 1;
      if (attributes_seen <= limits.max_attributes_per_page) attrs.push({ name: attr_name, value: value.slice(0, 4096) });
      else {
        truncated = true;
        break;
      }
    }
    const tag_record = { name, closing: false, attrs, offset: opening, line: line_for(starts, opening) };
    tags.push(tag_record);
    if (tags.length >= limits.max_tags_per_page) {
      truncated = true;
      break;
    }
    if (!tag_closed) break;
    if (name === 'script' || name === 'style') {
      const content_start = cursor;
      const close_pattern = new RegExp('</' + name + '(?=[\\s/>])', 'ig');
      close_pattern.lastIndex = cursor;
      const close_match = close_pattern.exec(source);
      if (!close_match) break;
      tag_record.content_start = content_start;
      tag_record.content_end = close_match.index;
      tag_record.content_line = line_for(starts, content_start);
      cursor = close_match.index;
    }
  }
  return { tags, attributes_seen, truncated, line_count: starts.length };
}

function attr(tag, name) {
  return tag.attrs.find(item => item.name === name)?.value ?? null;
}

function url_info(value, page_path, known_paths) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return { kind: 'ignored' };
  const raw = value.trim();
  if (!raw || raw.startsWith('#')) return { kind: 'fragment' };
  if (/^javascript\s*:/i.test(raw)) return { kind: 'javascript' };
  if (/^(?:data|blob):/i.test(raw)) return { kind: 'embedded' };
  let parsed;
  try { parsed = new URL(raw, 'https://orix.invalid/' + page_path.replace(/^\/+/, '')); }
  catch { return { kind: 'invalid' }; }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return { kind: 'other-scheme' };
  if (parsed.origin !== 'https://orix.invalid') return { kind: 'external', origin: parsed.origin, insecure: parsed.protocol === 'http:' };
  let pathname = raw.split(/[?#]/, 1)[0].replace(/\\/g, '/');
  try { pathname = decodeURIComponent(pathname).replace(/\\/g, '/'); } catch { return { kind: 'invalid' }; }
  const combined = pathname.startsWith('/')
    ? pathname.replace(/^\/+/, '')
    : path.posix.join(path.posix.dirname(page_path), pathname || path.posix.basename(page_path));
  const normalized = path.posix.normalize(combined);
  if (normalized === '..' || normalized.startsWith('../')) return { kind: 'path-escape' };
  return { kind: 'local', path: normalized === '.' ? page_path : normalized, exists: known_paths.has(normalized === '.' ? page_path : normalized) };
}

function safe_label(value, maximum = 160) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/[<>]/g, '').slice(0, maximum);
}


function sanitize_module_specifier(value) {
  const raw = String(value ?? '').trim();
  if (/^(?:file|data|blob):/i.test(raw)) return { value: '[' + raw.split(':', 1)[0].toLowerCase() + '-url]', redacted: true };
  if (/^(?:https?:)?\/\//i.test(raw)) {
    try {
      const parsed = new URL(raw.startsWith('//') ? 'https:' + raw : raw);
      return { value: parsed.origin + parsed.pathname, redacted: Boolean(parsed.search || parsed.hash || parsed.username || parsed.password) };
    } catch {
      return { value: '[invalid-external-reference]', redacted: true };
    }
  }
  const value_without_query = raw.split(/[?#]/, 1)[0];
  return { value: value_without_query.slice(0, 2048), redacted: value_without_query !== raw || value_without_query.length > 2048 };
}

function resolve_local_module(specifier, from_path, known_paths) {
  let raw = String(specifier ?? '').split(/[?#]/, 1)[0];
  try { raw = decodeURIComponent(raw); } catch { return { kind: 'invalid-local-reference', path: null }; }
  raw = raw.replace(/\\/g, '/');
  if (!raw.startsWith('./') && !raw.startsWith('../') && !raw.startsWith('/')) return { kind: 'package-or-nonlocal', path: null };
  let candidate = raw.startsWith('/') ? raw.replace(/^\/+/, '') : path.posix.join(path.posix.dirname(from_path), raw);
  candidate = path.posix.normalize(candidate);
  if (candidate === '..' || candidate.startsWith('../')) return { kind: 'path-escape', path: null };
  const candidates = [candidate];
  if (!path.posix.extname(candidate)) {
    for (const extension of ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']) candidates.push(candidate + extension);
    for (const extension of ['index.js', 'index.mjs', 'index.ts', 'index.tsx']) candidates.push(path.posix.join(candidate, extension));
  }
  const resolved = candidates.find(item => known_paths.has(item));
  return resolved ? { kind: 'resolved-local', path: resolved } : { kind: 'unresolved-local', path: null };
}

export function analyze_website_project(raw_files, options = {}) {
  if (!Array.isArray(raw_files)) throw new TypeError('analyze_website_project requires an array of project file records');
  const limits = limits_for(options);
  const known_paths = new Set(raw_files.filter(item => item && typeof item.path === 'string').map(item => item.path));
  const files_by_path = new Map(raw_files.filter(item => item && typeof item.path === 'string').map(item => [item.path, item]));
  const html_files = raw_files.filter(item => item && typeof item.path === 'string' && typeof item.text === 'string' && /\.(?:html?|xhtml)$/i.test(item.path)).sort((a, b) => a.path.localeCompare(b.path));
  const findings = [];
  let findings_truncated = false;
  const pages = [];
  const script_files = [];
  const script_import_graph = [];
  const script_cache = new Map();
  let script_bytes_analyzed = 0;
  let script_imports_seen = 0;
  let script_symbols_seen = 0;
  let script_analysis_truncated = false;
  let truncated_pages = 0;
  let references_seen = 0;
  const add_finding = (page, rule_id, severity, confidence, line, label, evidence = {}) => {
    if (findings.length >= limits.max_findings) { findings_truncated = true; return; }
    findings.push({ rule_id, severity, confidence, file: page, line, label, evidence });
  };
  const analyze_script = (script_source, source_id, line_offset = 0, depth = 0) => {
    if (script_cache.has(source_id)) return script_cache.get(source_id);
    const bytes = Buffer.byteLength(script_source, 'utf8');
    if (depth > limits.max_script_depth || script_files.length >= limits.max_script_files || bytes > limits.max_script_bytes || bytes > limits.max_total_script_bytes - script_bytes_analyzed) {
      script_analysis_truncated = true;
      const reason = depth > limits.max_script_depth ? 'depth-limit' : bytes > limits.max_script_bytes ? 'file-size-limit' : 'analysis-budget-limit';
      const skipped = { source: source_id, status: reason, bytes };
      script_cache.set(source_id, skipped);
      return skipped;
    }
    const result = { source: source_id, status: 'analyzing', bytes, imports: [], symbols: [], coverage: null };
    script_cache.set(source_id, result);
    script_files.push(result);
    script_bytes_analyzed += bytes;
    const parsed = analyze_javascript_source(script_source, {
      max_source_chars: limits.max_script_bytes,
      max_tokens: limits.max_script_tokens,
      max_imports: limits.max_script_imports,
      max_symbols: limits.max_script_symbols,
    });
    const imports = parsed.imports.map(item => {
      const safe = sanitize_module_specifier(item.specifier);
      const resolution = resolve_local_module(item.specifier, source_id.split('#inline-script-')[0], known_paths);
      const line = item.line + line_offset;
      if (resolution.kind === 'path-escape') {
        add_finding(source_id.split('#inline-script-')[0], 'ORIX_WEB_SCRIPT_IMPORT_PATH_ESCAPE', 'medium', 'medium', line, 'JavaScript module import escapes the project root', { source: source_id, specifier: safe.value });
      } else if (resolution.kind === 'unresolved-local') {
        add_finding(source_id.split('#inline-script-')[0], 'ORIX_WEB_UNRESOLVED_LOCAL_IMPORT', 'low', 'medium', line, 'Local JavaScript module reference does not match an inventoried file', { source: source_id, specifier: safe.value });
      }
      const edge = { from: source_id, to: resolution.path, specifier: safe.value, redacted: safe.redacted, kind: item.kind, resolution: resolution.kind, line, confidence: item.confidence };
      script_import_graph.push(edge);
      if (resolution.kind === 'resolved-local') {
        const dependency = files_by_path.get(resolution.path);
        if (dependency && typeof dependency.text === 'string' && /\.(?:[cm]?js|jsx|tsx?|mts|cts)$/i.test(resolution.path)) {
          analyze_script(dependency.text, resolution.path, 0, depth + 1);
        }
      }
      return edge;
    });
    const symbols = parsed.symbols.map(item => ({ ...item, line: item.line + line_offset }));
    script_imports_seen += imports.length;
    script_symbols_seen += symbols.length;
    if (parsed.coverage.token_limit_reached || parsed.coverage.imports_truncated || parsed.coverage.symbols_truncated) script_analysis_truncated = true;
    result.status = 'analyzed';
    result.imports = imports;
    result.symbols = symbols;
    result.coverage = parsed.coverage;
    return result;
  };
  const pages_to_analyze = html_files.slice(0, limits.max_pages);
  if (html_files.length > pages_to_analyze.length) truncated_pages += html_files.length - pages_to_analyze.length;
  for (const item of pages_to_analyze) {
    const source = item.text;
    if (Buffer.byteLength(source, 'utf8') > limits.max_page_bytes) {
      truncated_pages += 1;
      continue;
    }
    const parsed = tokenize_html(source, limits);
    const page = {
      path: item.path,
      title: safe_label(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(source)?.[1]?.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim(), 256),
      language: null,
      scripts: { external: 0, inline: 0, modules: 0, references: [], analysis: [] },
      stylesheets: { count: 0, references: [] },
      links: { internal: 0, external: 0, references: [] },
      forms: [],
      iframes: [],
      images: 0,
      metadata: { charset: null, viewport: null, content_security_policy: false, base_href: null },
      coverage: { tags_seen: parsed.tags.length, attributes_seen: parsed.attributes_seen, line_count: parsed.line_count, truncated: parsed.truncated },
    };
    let refs_for_page = 0;
    const add_reference = (collection, kind, value, line, attribute_name) => {
      if (value === null || value === undefined || value === '') return { kind: 'ignored' };
      if (refs_for_page >= limits.max_refs_per_page) {
        page.coverage.truncated = true;
        return { kind: 'limit' };
      }
      refs_for_page += 1;
      references_seen += 1;
      const info = url_info(value, item.path, known_paths);
      if (info.kind === 'javascript') add_finding(item.path, 'ORIX_WEB_JAVASCRIPT_URL', 'high', 'high', line, 'javascript: URL in ' + attribute_name, { element: kind, attribute: attribute_name });
      if (info.kind === 'path-escape') add_finding(item.path, 'ORIX_WEB_PATH_ESCAPE_REFERENCE', 'medium', 'medium', line, 'Local reference escapes the project root', { element: kind, attribute: attribute_name });
      if (info.kind === 'external' && info.insecure) add_finding(item.path, 'ORIX_WEB_INSECURE_HTTP_REFERENCE', 'medium', 'high', line, 'External resource uses plain HTTP', { element: kind, attribute: attribute_name, origin: info.origin });
      if (collection && info.kind !== 'ignored' && info.kind !== 'fragment') {
        const reference = info.kind === 'external'
          ? { kind: info.kind, origin: info.origin }
          : info.kind === 'local'
            ? { kind: info.kind, path: info.path, exists: info.exists }
            : { kind: info.kind };
        collection.push({ ...reference, line });
      }
      return info;
    };
    for (const tag of parsed.tags) {
      if (tag.closing) continue;
      if (tag.name === 'html') page.language = attr(tag, 'lang');
      if (tag.name === 'meta') {
        const name = (attr(tag, 'name') ?? '').toLowerCase();
        const equiv = (attr(tag, 'http-equiv') ?? '').toLowerCase();
        if (attr(tag, 'charset')) page.metadata.charset = attr(tag, 'charset');
        if (name === 'viewport') page.metadata.viewport = safe_label(attr(tag, 'content'), 256);
        if (equiv === 'content-security-policy') page.metadata.content_security_policy = true;
      }
      if (tag.name === 'base') {
        const base_info = url_info(attr(tag, 'href'), item.path, known_paths);
        page.metadata.base_href = base_info.kind === 'external' ? { kind: 'external', origin: base_info.origin } : base_info.kind === 'local' ? { kind: 'local', path: base_info.path } : { kind: base_info.kind };
      }
      if (tag.name === 'script') {
        const src = attr(tag, 'src');
        const script_type = (attr(tag, 'type') ?? '').toLowerCase().split(';')[0].trim();
        const javascript_type = !script_type || script_type === 'module' || ['text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript'].includes(script_type);
        if (src) {
          page.scripts.external += 1;
          const info = add_reference(page.scripts.references, 'script', src, tag.line, 'src');
          if (info.kind === 'external' && !attr(tag, 'integrity')) add_finding(item.path, 'ORIX_WEB_EXTERNAL_SCRIPT_NO_INTEGRITY', 'low', 'medium', tag.line, 'External script has no integrity attribute', { origin: info.origin });
          if (info.kind === 'local' && info.exists && javascript_type) {
            const script_file = files_by_path.get(info.path);
            if (script_file && typeof script_file.text === 'string') {
              page.scripts.analysis.push(analyze_script(script_file.text, info.path));
            } else page.scripts.analysis.push({ source: info.path, status: 'source-not-available' });
          }
        } else {
          page.scripts.inline += 1;
          if (javascript_type && Number.isSafeInteger(tag.content_start) && Number.isSafeInteger(tag.content_end)) {
            const inline_index = page.scripts.inline;
            const inline_source = source.slice(tag.content_start, tag.content_end);
            page.scripts.analysis.push(analyze_script(inline_source, item.path + '#inline-script-' + inline_index, tag.content_line - 1));
          }
        }
        if (script_type === 'module') page.scripts.modules += 1;
      }
      if (tag.name === 'link' && (attr(tag, 'rel') ?? '').toLowerCase().split(/\s+/).includes('stylesheet')) {
        page.stylesheets.count += 1;
        add_reference(page.stylesheets.references, 'stylesheet', attr(tag, 'href'), tag.line, 'href');
      }
      if (tag.name === 'a') {
        const info = add_reference(page.links.references, 'anchor', attr(tag, 'href'), tag.line, 'href');
        if (info.kind === 'external') page.links.external += 1;
        else if (info.kind === 'local') page.links.internal += 1;
        if ((attr(tag, 'target') ?? '').toLowerCase() === '_blank') {
          const rel = (attr(tag, 'rel') ?? '').toLowerCase().split(/\s+/);
          if (!rel.includes('noopener') && !rel.includes('noreferrer')) add_finding(item.path, 'ORIX_WEB_TARGET_BLANK_NO_REL', 'medium', 'high', tag.line, 'target=_blank link lacks noopener or noreferrer', {});
        }
      }
      if (tag.name === 'form') {
        const action = attr(tag, 'action');
        const method = (attr(tag, 'method') ?? 'get').toLowerCase();
        const info = add_reference(null, 'form', action, tag.line, 'action');
        if (info.kind === 'external' && info.insecure) add_finding(item.path, 'ORIX_WEB_INSECURE_FORM_ACTION', 'high', 'high', tag.line, 'Form submits to an external HTTP endpoint', { origin: info.origin, method });
        if (page.forms.length < limits.max_refs_per_page) page.forms.push({ method: ['get', 'post', 'dialog'].includes(method) ? method : 'other', action: info.kind === 'external' ? { kind: 'external', origin: info.origin } : info.kind === 'local' ? { kind: 'local', path: info.path } : { kind: info.kind } });
      }
      if (tag.name === 'iframe') {
        const info = add_reference(null, 'iframe', attr(tag, 'src'), tag.line, 'src');
        if (attr(tag, 'src') && page.iframes.length < limits.max_refs_per_page) page.iframes.push({ sandboxed: attr(tag, 'sandbox') !== null, reference: info.kind });
      }
      if (tag.name === 'img' || tag.name === 'source') {
        page.images += tag.name === 'img' ? 1 : 0;
        add_reference(null, tag.name, attr(tag, 'src'), tag.line, 'src');
        if (attr(tag, 'srcset')) {
          const first_candidate = attr(tag, 'srcset').split(',')[0].trim().split(/\\s+/)[0];
          add_reference(null, tag.name, first_candidate, tag.line, 'srcset');
        }
      }
      for (const attribute of tag.attrs) {
        if (/^on[a-z]{2,}$/i.test(attribute.name)) add_finding(item.path, 'ORIX_WEB_INLINE_EVENT_HANDLER', 'low', 'high', tag.line, 'Inline event handler attribute is present', { element: tag.name, attribute: attribute.name });
      }
    }
    if (page.coverage.truncated) truncated_pages += 1;
    pages.push(page);
  }
  findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.rule_id.localeCompare(b.rule_id));
  return {
    detected: html_files.length > 0,
    confidence: html_files.length > 0 ? 'html-files-present' : 'not-detected',
    summary: {
      pages_seen: html_files.length,
      pages_analyzed: pages.length,
      script_references: pages.reduce((sum, page) => sum + page.scripts.external, 0),
      script_files_analyzed: script_files.length,
      script_imports: script_imports_seen,
      script_symbols: script_symbols_seen,
      script_analysis_truncated: script_analysis_truncated,
      inline_scripts: pages.reduce((sum, page) => sum + page.scripts.inline, 0),
      stylesheets: pages.reduce((sum, page) => sum + page.stylesheets.count, 0),
      forms: pages.reduce((sum, page) => sum + page.forms.length, 0),
      iframes: pages.reduce((sum, page) => sum + page.iframes.length, 0),
      references_seen,
      findings: findings.length,
      findings_truncated,
    },
    pages,
    script_files,
    script_import_graph,
    findings,
    coverage: {
      complete: truncated_pages === 0 && !findings_truncated && !script_analysis_truncated,
      truncated: truncated_pages > 0 || findings_truncated || script_analysis_truncated,
      truncated_pages,
      script_analysis_truncated,
      script_bytes_analyzed,
      limits,
    },
    limitations: [
      'This is offline lexical HTML analysis, not a standards-complete HTML5 parser or browser DOM.',
      'Scripts, stylesheets, templates and embedded documents are never executed or fetched.',
      'URL references are normalized locally against the source path; base-element browser resolution is recorded but not applied, and no DNS, HTTP, TLS or origin reachability checks are performed.',
      'Security findings are review leads, not exploitability or compliance verdicts.',
      'Linked local JavaScript and inline script bodies receive bounded lexical import/symbol analysis only; source is never executed and browser runtime behavior is not observed.',
    ],
  };
}
