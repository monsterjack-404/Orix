// JavaScript, src/project/javascript.mjs, Node.js 20+, bounded JavaScript/TypeScript lexical analysis.
// This is a tokenizer and shallow declaration recognizer, not a standards-complete AST.

const DEFAULT_MAX_TOKENS = 200000;
const DEFAULT_MAX_SOURCE_CHARS = 8 * 1024 * 1024;
const DEFAULT_MAX_IMPORTS = 2000;
const DEFAULT_MAX_SYMBOLS = 2000;
const REGEX_PREFIX_KEYWORDS = new Set(['return', 'throw', 'case', 'delete', 'void', 'typeof', 'instanceof', 'in', 'of', 'yield', 'await', 'else', 'do']);
const REGEX_PREFIX_PUNCTUATION = new Set(['(', '{', '[', ',', ':', ';', '=', '!', '?', '&', '|', '+', '-', '*', '%', '~', '^', '<', '>']);

function is_space(code) {
  return code === 32 || (code >= 9 && code <= 13) || code === 0x00a0;
}

function is_identifier_start(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
    || code === 95 || code === 36 || code >= 0x80;
}

function is_identifier_part(code) {
  return is_identifier_start(code) || (code >= 48 && code <= 57);
}

function can_start_regex(previous) {
  if (!previous) return true;
  if (previous.type === 'identifier') {
    return REGEX_PREFIX_KEYWORDS.has(previous.value);
  }
  if (previous.type === 'string' || previous.type === 'number' || previous.type === 'template' || previous.type === 'regex') return false;
  return REGEX_PREFIX_PUNCTUATION.has(previous.value);
}

function read_regex(source, start) {
  let cursor = start + 1;
  let in_class = false;
  while (cursor < source.length) {
    const character = source[cursor];
    if (character === '\\') { cursor += 2; continue; }
    if (character === '\n' || character === '\r') return null;
    if (character === '[') in_class = true;
    else if (character === ']') in_class = false;
    else if (character === '/' && !in_class) {
      cursor += 1;
      while (cursor < source.length && is_identifier_part(source.charCodeAt(cursor))) cursor += 1;
      return cursor;
    }
    cursor += 1;
  }
  return null;
}

function read_string(source, start, quote) {
  let cursor = start + 1;
  let value = '';
  let static_value = true;
  while (cursor < source.length) {
    const character = source[cursor];
    if (character === quote) return { end: cursor + 1, value, static_value };
    if (character === '\\') {
      static_value = false;
      cursor += 1;
      if (cursor < source.length && source[cursor] === '\r' && source[cursor + 1] === '\n') cursor += 2;
      else cursor += 1;
      continue;
    }
    if (character === '\n' || character === '\r') return { end: cursor, value, static_value: false };
    value += character;
    cursor += 1;
  }
  return { end: cursor, value, static_value: false };
}

function read_template(source, start) {
  let cursor = start + 1;
  let interpolation = false;
  while (cursor < source.length) {
    const character = source[cursor];
    if (character === '\\') { cursor += 2; continue; }
    if (character === '`') return { end: cursor + 1, interpolation };
    if (character === '$' && source[cursor + 1] === '{') interpolation = true;
    cursor += 1;
  }
  return { end: cursor, interpolation: true };
}

function bounded_option(options, key, fallback, maximum) {
  const value = options[key] ?? fallback;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(key + ' must be an integer between 1 and ' + maximum);
  }
  return value;
}

function tokenize(source, maximum) {
  const tokens = [];
  let cursor = 0;
  let line = 1;
  let truncated = false;
  while (cursor < source.length) {
    if (tokens.length >= maximum) { truncated = true; break; }
    const character = source[cursor];
    const code = source.charCodeAt(cursor);
    if (character === '\n') { line += 1; cursor += 1; continue; }
    if (is_space(code)) { cursor += 1; continue; }
    if (character === '/' && source[cursor + 1] === '/') {
      cursor += 2;
      while (cursor < source.length && source[cursor] !== '\n') cursor += 1;
      continue;
    }
    if (character === '/' && source[cursor + 1] === '*') {
      cursor += 2;
      while (cursor < source.length && !(source[cursor] === '*' && source[cursor + 1] === '/')) {
        if (source[cursor] === '\n') line += 1;
        cursor += 1;
      }
      if (cursor < source.length) cursor += 2;
      continue;
    }
    if (character === '/' && can_start_regex(tokens[tokens.length - 1])) {
      const end = read_regex(source, cursor);
      if (end !== null) {
        tokens.push({ type: 'regex', value: '', line });
        cursor = end;
        continue;
      }
    }
    if (character === "'" || character === '"') {
      const start_line = line;
      const result = read_string(source, cursor, character);
      const raw = source.slice(cursor, result.end);
      for (let index = cursor; index < result.end; index += 1) if (source[index] === '\n') line += 1;
      tokens.push({ type: 'string', value: result.value, static_value: result.static_value, raw, line: start_line });
      cursor = result.end;
      continue;
    }
    if (character === '`') {
      const start_line = line;
      const result = read_template(source, cursor);
      for (let index = cursor; index < result.end; index += 1) if (source[index] === '\n') line += 1;
      tokens.push({ type: 'template', value: '', static_value: false, line: start_line });
      cursor = result.end;
      continue;
    }
    if (is_identifier_start(code)) {
      const start = cursor++;
      while (cursor < source.length && is_identifier_part(source.charCodeAt(cursor))) cursor += 1;
      tokens.push({ type: 'identifier', value: source.slice(start, cursor), line });
      continue;
    }
    if (code >= 48 && code <= 57) {
      const start = cursor++;
      while (cursor < source.length) {
        const next = source.charCodeAt(cursor);
        if (!is_identifier_part(next) && next !== 46) break;
        cursor += 1;
      }
      tokens.push({ type: 'number', value: source.slice(start, cursor), line });
      continue;
    }
    tokens.push({ type: 'punctuation', value: character, line });
    cursor += 1;
  }
  return { tokens, truncated };
}

function add_import(imports, token, kind, from_token, maximum) {
  if (!token || token.type !== 'string' || !token.static_value || !token.value || token.value.length > 2048) return false;
  if (imports.length >= maximum) return true;
  imports.push({ specifier: token.value, kind, line: from_token?.line ?? token.line, confidence: 'static-literal' });
  return false;
}

function collect_imports(tokens, maximum) {
  const imports = [];
  let truncated = false;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type !== 'identifier') continue;
    const previous = tokens[index - 1]?.value;
    const module_require = token.value === 'require' && previous === '.' && tokens[index - 2]?.value === 'module';
    if ((previous === '.' || (previous === '.' && tokens[index - 2]?.value === '?')) && !module_require) continue;
    if (token.value === 'require' && tokens[index + 1]?.value === '(') {
      const argument = tokens[index + 2];
      if (tokens[index + 3]?.value === ')') truncated = add_import(imports, argument, 'require', token, maximum) || truncated;
      continue;
    }
    if (token.value !== 'import' && token.value !== 'export') continue;
    if (token.value === 'import' && tokens[index + 1]?.value === '(') {
      if (tokens[index + 3]?.value === ')' || tokens[index + 3]?.value === ',') truncated = add_import(imports, tokens[index + 2], 'dynamic-import', token, maximum) || truncated;
      continue;
    }
    if (token.value === 'import' && tokens[index + 1]?.type === 'string') {
      truncated = add_import(imports, tokens[index + 1], 'side-effect-import', token, maximum) || truncated;
      continue;
    }
    const start_line = token.line;
    for (let offset = 1; offset <= 100 && index + offset < tokens.length; offset += 1) {
      const current = tokens[index + offset];
      if (current.value === ';') break;
      if (current.value === 'from' && tokens[index + offset + 1]?.type === 'string') {
        truncated = add_import(imports, tokens[index + offset + 1], token.value === 'import' ? 'import' : 're-export', token, maximum) || truncated;
        break;
      }
      if (offset > 1 && current.line > start_line && current.type === 'identifier' &&
          ['const', 'let', 'var', 'function', 'class', 'return', 'export', 'import'].includes(current.value)) break;
    }
  }
  return { imports, truncated };
}

function collect_symbols(tokens, maximum) {
  const symbols = [];
  const seen = new Set();
  let truncated = false;
  const declarations = new Set(['function', 'class', 'interface', 'type', 'enum']);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type !== 'identifier') continue;
    let kind = declarations.has(token.value) ? token.value : null;
    if (!kind && (token.value === 'const' || token.value === 'let' || token.value === 'var')) {
      if (tokens[index - 1]?.value === 'export' || tokens[index - 2]?.value === 'export') kind = 'variable';
    }
    if (!kind) continue;
    let name = tokens[index + 1];
    if (kind === 'function' && name?.value === '*') name = tokens[index + 2];
    if (name?.value === 'default' && kind === 'function') continue;
    if (!name || name.type !== 'identifier' || name.value.length > 256) continue;
    const key = kind + '\0' + name.value + '\0' + token.line;
    if (seen.has(key)) continue;
    seen.add(key);
    if (symbols.length >= maximum) { truncated = true; continue; }
    symbols.push({ name: name.value, kind, line: token.line, confidence: 'declaration-token' });
  }
  return { symbols, truncated };
}

/**
 * Extract static module specifiers and declaration candidates from JS/TS text.
 * Comments and string/template contents are opaque; no source is executed.
 */
export function analyze_javascript_source(source, options = {}) {
  if (typeof source !== 'string') throw new TypeError('JavaScript source must be a string');
  const max_source_chars = bounded_option(options, 'max_source_chars', DEFAULT_MAX_SOURCE_CHARS, 64 * 1024 * 1024);
  if (source.length > max_source_chars) throw new RangeError('JavaScript source exceeds max_source_chars');
  const max_tokens = bounded_option(options, 'max_tokens', DEFAULT_MAX_TOKENS, 500000);
  const max_imports = bounded_option(options, 'max_imports', DEFAULT_MAX_IMPORTS, 10000);
  const max_symbols = bounded_option(options, 'max_symbols', DEFAULT_MAX_SYMBOLS, 10000);
  const scanned = tokenize(source, max_tokens);
  const import_result = collect_imports(scanned.tokens, max_imports);
  const symbol_result = collect_symbols(scanned.tokens, max_symbols);
  return {
    imports: import_result.imports,
    symbols: symbol_result.symbols,
    coverage: {
      tokens: scanned.tokens.length,
      token_limit_reached: scanned.truncated,
      imports_truncated: import_result.truncated,
      symbols_truncated: symbol_result.truncated,
    },
    limitations: [
      'This is bounded lexical and shallow declaration analysis, not a complete ECMAScript or TypeScript AST.',
      'Type resolution, scopes, control flow, data flow, JSX semantics, regular-expression literal bodies and compiler transforms are not analyzed.',
      'Computed module specifiers, non-literal imports, macro-generated code and runtime loading may be missed.',
      'Analysis rejects source text above max_source_chars; token, import and symbol counts are independently capped.',
    ],
  };
}
