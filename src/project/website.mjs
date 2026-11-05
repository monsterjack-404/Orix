// JavaScript, src/project/website.mjs, Node.js 20+, bounded offline HTML structure and security triage.
import path from 'node:path';

const DEFAULTS = Object.freeze({
  max_pages: 500,
  max_page_bytes: 1024 * 1024,
  max_tags_per_page: 20000,
  max_attributes_per_page: 100000,
  max_refs_per_page: 2000,
  max_findings: 500,
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
    tags.push({ name, closing: false, attrs, offset: opening, line: line_for(starts, opening) });
    if (tags.length >= limits.max_tags_per_page) {
      truncated = true;
      break;
    }
    if (!tag_closed) break;
    if (name === 'script' || name === 'style') {
      const lower = source.toLowerCase();
      const close_at = lower.indexOf('</' + name, cursor);
      if (close_at < 0) break;
      cursor = close_at;
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
  try { pathname = decodeURIComponent(pathname); } catch { return { kind: 'invalid' }; }
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

export function analyze_website_project(raw_files, options = {}) {
  if (!Array.isArray(raw_files)) throw new TypeError('analyze_website_project requires an array of project file records');
  const limits = limits_for(options);
  const known_paths = new Set(raw_files.filter(item => item && typeof item.path === 'string').map(item => item.path));
  const html_files = raw_files.filter(item => item && typeof item.path === 'string' && typeof item.text === 'string' && /\.(?:html?|xhtml)$/i.test(item.path)).sort((a, b) => a.path.localeCompare(b.path));
  const findings = [];
  let findings_truncated = false;
  const pages = [];
  let truncated_pages = 0;
  let references_seen = 0;
  const add_finding = (page, rule_id, severity, confidence, line, label, evidence = {}) => {
    if (findings.length >= limits.max_findings) { findings_truncated = true; return; }
    findings.push({ rule_id, severity, confidence, file: page, line, label, evidence });
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
      scripts: { external: 0, inline: 0, modules: 0, references: [] },
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
        if (src) {
          page.scripts.external += 1;
          const info = add_reference(page.scripts.references, 'script', src, tag.line, 'src');
          if (info.kind === 'external' && !attr(tag, 'integrity')) add_finding(item.path, 'ORIX_WEB_EXTERNAL_SCRIPT_NO_INTEGRITY', 'low', 'medium', tag.line, 'External script has no integrity attribute', { origin: info.origin });
        } else page.scripts.inline += 1;
        if ((attr(tag, 'type') ?? '').toLowerCase() === 'module') page.scripts.modules += 1;
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
        page.forms.push({ method: ['get', 'post', 'dialog'].includes(method) ? method : 'other', action: info.kind === 'external' ? { kind: 'external', origin: info.origin } : info.kind === 'local' ? { kind: 'local', path: info.path } : { kind: info.kind } });
      }
      if (tag.name === 'iframe') {
        const info = add_reference(null, 'iframe', attr(tag, 'src'), tag.line, 'src');
        if (attr(tag, 'src')) page.iframes.push({ sandboxed: attr(tag, 'sandbox') !== null, reference: info.kind });
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
      inline_scripts: pages.reduce((sum, page) => sum + page.scripts.inline, 0),
      stylesheets: pages.reduce((sum, page) => sum + page.stylesheets.count, 0),
      forms: pages.reduce((sum, page) => sum + page.forms.length, 0),
      iframes: pages.reduce((sum, page) => sum + page.iframes.length, 0),
      references_seen,
      findings: findings.length,
      findings_truncated,
    },
    pages,
    findings,
    coverage: {
      complete: truncated_pages === 0 && !findings_truncated,
      truncated: truncated_pages > 0 || findings_truncated,
      truncated_pages,
      limits,
    },
    limitations: [
      'This is offline lexical HTML analysis, not a standards-complete HTML5 parser or browser DOM.',
      'Scripts, stylesheets, templates and embedded documents are never executed or fetched.',
      'URL references are normalized locally; no DNS, HTTP, TLS or origin reachability checks are performed.',
      'Security findings are review leads, not exploitability or compliance verdicts.',
      'JavaScript source analysis remains a separate bounded tokenizer and is not connected to browser runtime behavior.',
    ],
  };
}
