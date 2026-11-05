// JavaScript, src/project/electron.mjs, Node.js 20+, bounded Electron configuration triage.
// Findings are static review leads; this module never executes inspected project code.

import { OrixError } from '../core/errors.mjs';

const MAX_FINDINGS = 200;
const MAX_FILES = 50_000;
const MAX_FILE_BYTES = 1_048_576;
const MAX_TOTAL_BYTES = 134_217_728;
const MAX_TOKENS_PER_FILE = 100_000;

function invalid(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

const ELECTRON_PACKAGES = new Set(['electron', 'electron-builder', '@electron-forge/cli', '@electron-forge/core', 'electron-forge']);
const RISK_RULES = [
  { key: 'nodeIntegration', unsafe: true, rule: 'ORIX-ELECTRON-NODE-INTEGRATION', label: 'Node.js integration is enabled in a renderer context', severity: 'high' },
  { key: 'contextIsolation', unsafe: false, rule: 'ORIX-ELECTRON-CONTEXT-ISOLATION', label: 'Context isolation is explicitly disabled', severity: 'high' },
  { key: 'sandbox', unsafe: false, rule: 'ORIX-ELECTRON-SANDBOX-DISABLED', label: 'Renderer sandboxing is explicitly disabled', severity: 'medium' },
  { key: 'webSecurity', unsafe: false, rule: 'ORIX-ELECTRON-WEB-SECURITY-DISABLED', label: 'Web security is explicitly disabled', severity: 'high' },
  { key: 'allowRunningInsecureContent', unsafe: true, rule: 'ORIX-ELECTRON-INSECURE-CONTENT', label: 'Insecure content is explicitly allowed', severity: 'high' },
  { key: 'enableRemoteModule', unsafe: true, rule: 'ORIX-ELECTRON-REMOTE-MODULE', label: 'Deprecated remote module is explicitly enabled', severity: 'medium' },
];

const REGEX_PREFIX_KEYWORDS = new Set(['await', 'case', 'delete', 'do', 'else', 'in', 'instanceof', 'of', 'return', 'throw', 'typeof', 'void', 'yield']);

function is_identifier_start(character) {
  if (!character) return false;
  const code = character.charCodeAt(0);
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36;
}

function is_identifier_part(character) {
  if (!character) return false;
  const code = character.charCodeAt(0);
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90)
    || (code >= 97 && code <= 122) || code === 95 || code === 36;
}

function regex_can_start_after(previous) {
  if (!previous) return true;
  if (previous.type === 'punctuator') return '([{,:;=!?&|+-*%^~<>'.includes(previous.value);
  return previous.type === 'identifier' && REGEX_PREFIX_KEYWORDS.has(previous.value);
}

function tokenize_source(source) {
  const tokens = [];
  let index = 0;
  let line = 1;
  let previous = null;
  let truncated = false;

  function push(type, value, token_line) {
    if (tokens.length >= MAX_TOKENS_PER_FILE) {
      truncated = true;
      return false;
    }
    previous = { type, value };
    tokens.push({ type, value, line: token_line });
    return true;
  }

  while (index < source.length) {
    const character = source[index];
    if (character === '\n') {
      line += 1;
      index += 1;
      continue;
    }
    if (character === ' ' || character === '\t' || character === '\r' || character === '\f' || character === '\v') {
      index += 1;
      continue;
    }

    if (character === '/' && source[index + 1] === '/') {
      index += 2;
      while (index < source.length && source[index] !== '\n') index += 1;
      continue;
    }
    if (character === '/' && source[index + 1] === '*') {
      index += 2;
      while (index < source.length && !(source[index] === '*' && source[index + 1] === '/')) {
        if (source[index] === '\n') line += 1;
        index += 1;
      }
      index = Math.min(source.length, index + 2);
      continue;
    }

    if (character === '\'' || character === '"') {
      const token_line = line;
      const quote = character;
      const start = index + 1;
      index += 1;
      let escaped = false;
      let closed = false;
      while (index < source.length) {
        const current = source[index];
        if (current === '\n') line += 1;
        if (escaped) {
          escaped = false;
          index += 1;
          continue;
        }
        if (current === '\\') {
          escaped = true;
          index += 1;
          continue;
        }
        if (current === quote) {
          closed = true;
          break;
        }
        index += 1;
      }
      const value = closed && !escaped ? source.slice(start, index) : null;
      if (closed) index += 1;
      if (!push('string', value, token_line)) break;
      continue;
    }

    // Template bodies are deliberately opaque, including interpolation expressions.
    if (character.charCodeAt(0) === 96) {
      index += 1;
      let escaped = false;
      while (index < source.length) {
        const current = source[index];
        if (current === '\n') line += 1;
        if (escaped) {
          escaped = false;
          index += 1;
          continue;
        }
        if (current === '\\') {
          escaped = true;
          index += 1;
          continue;
        }
        if (current.charCodeAt(0) === 96) {
          index += 1;
          break;
        }
        index += 1;
      }
      if (!push('opaque', null, line)) break;
      continue;
    }

    if (character === '/' && regex_can_start_after(previous)) {
      index += 1;
      let in_character_class = false;
      let escaped = false;
      while (index < source.length && source[index] !== '\n') {
        const current = source[index];
        if (escaped) {
          escaped = false;
          index += 1;
          continue;
        }
        if (current === '\\') {
          escaped = true;
          index += 1;
          continue;
        }
        if (current === '[') in_character_class = true;
        else if (current === ']') in_character_class = false;
        else if (current === '/' && !in_character_class) {
          index += 1;
          while (is_identifier_part(source[index])) index += 1;
          break;
        }
        index += 1;
      }
      if (!push('opaque', null, line)) break;
      continue;
    }

    if (is_identifier_start(character)) {
      const token_line = line;
      const start = index;
      index += 1;
      while (is_identifier_part(source[index])) index += 1;
      if (!push('identifier', source.slice(start, index), token_line)) break;
      continue;
    }

    if (character >= '0' && character <= '9') {
      const token_line = line;
      const start = index;
      index += 1;
      while (/[A-Za-z0-9_.]/.test(source[index] ?? '')) index += 1;
      if (!push('number', source.slice(start, index), token_line)) break;
      continue;
    }

    const token_line = line;
    index += 1;
    if (!push('punctuator', character, token_line)) break;
  }

  return { tokens, truncated };
}

function has_electron_module_signal(tokens) {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const previous = tokens[index - 1]?.value;
    const qualifier = tokens[index - 2]?.value;
    const next = tokens[index + 1];
    const after = tokens[index + 2];
    const module_require = token.value === 'require'
      && previous === '.' && qualifier === 'module'
      && tokens[index - 3]?.value !== '.' && tokens[index - 3]?.value !== '?';
    const member_call = previous === '.' || (previous === '.' && qualifier === '?');

    // Ignore arbitrary object methods such as service.require() and service.import().
    if (member_call && !module_require) continue;

    // CommonJS require(), module.require(), dynamic import(), and side-effect import.
    if (token.value === 'require' && next?.value === '(' && after?.type === 'string' && after.value === 'electron') return true;
    if (token.value === 'import' && after?.type === 'string' && after.value === 'electron'
      && next?.value === '(') return true;
    if (token.value === 'import' && next?.type === 'string' && next.value === 'electron') return true;
    if (token.value === 'from' && next?.type === 'string' && next.value === 'electron') return true;
  }
  return false;
}

function package_electron_evidence(files) {
  const evidence = [];
  for (const file of files) {
    if (file.path !== 'package.json' || typeof file.text !== 'string') continue;
    try {
      const manifest = JSON.parse(file.text);
      for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        const values = manifest?.[section];
        if (!values || typeof values !== 'object' || Array.isArray(values)) continue;
        for (const name of Object.keys(values)) {
          if (ELECTRON_PACKAGES.has(name) && evidence.length < 100) evidence.push({ path: file.path, section, package: name });
        }
      }
    } catch {
      // The general manifest parser reports malformed package.json separately.
    }
  }
  return evidence;
}

function process_role(file) {
  const value = file.toLowerCase();
  if (/(^|[/.-])(preload)([/.-]|$)/.test(value)) return 'preload-candidate';
  if (/(^|[/.-])(renderer|render)([/.-]|$)/.test(value)) return 'renderer-candidate';
  if (/(^|[/.-])(main|background)([/.-]|$)/.test(value)) return 'main-candidate';
  return null;
}

function inspect_web_preferences(tokens, file_path) {
  const findings = [];
  let found_object = false;

  for (let index = 0; index < tokens.length && findings.length < MAX_FINDINGS; index += 1) {
    const key_token = tokens[index];
    const key_is_web_preferences = (key_token.type === 'identifier' || key_token.type === 'string')
      && key_token.value === 'webPreferences';
    if (!key_is_web_preferences || tokens[index + 1]?.value !== ':' || tokens[index + 2]?.value !== '{') continue;

    found_object = true;
    let brace_depth = 1;
    let bracket_depth = 0;
    let paren_depth = 0;

    for (let cursor = index + 3; cursor < tokens.length && brace_depth > 0 && findings.length < MAX_FINDINGS; cursor += 1) {
      const token = tokens[cursor];

      if (brace_depth === 1 && bracket_depth === 0 && paren_depth === 0
        && (token.type === 'identifier' || token.type === 'string')
        && tokens[cursor + 1]?.value === ':') {
        const rule = RISK_RULES.find(item => item.key === token.value);
        const literal = tokens[cursor + 2];
        if (rule && literal?.type === 'identifier' && (literal.value === 'true' || literal.value === 'false')) {
          const value = literal.value === 'true';
          // Report only the explicitly unsafe boolean value for each rule.
          if (value === rule.unsafe) {
            findings.push({
              rule_id: rule.rule,
              severity: rule.severity,
              confidence: 'heuristic',
              file: file_path,
              line: token.line,
              label: rule.label,
              evidence: rule.key + ': ' + String(value) + ' (literal configuration; review runtime context)',
            });
          }
        }
      }

      if (token.value === '{') brace_depth += 1;
      else if (token.value === '}') brace_depth -= 1;
      else if (token.value === '[') bracket_depth += 1;
      else if (token.value === ']') bracket_depth = Math.max(0, bracket_depth - 1);
      else if (token.value === '(') paren_depth += 1;
      else if (token.value === ')') paren_depth = Math.max(0, paren_depth - 1);
    }
  }

  return { findings, found_object };
}

export function analyze_electron_project(files) {
  if (!Array.isArray(files)) throw new TypeError('Electron project files must be an array');
  if (files.length > MAX_FILES) invalid('ORIX_ELECTRON_FILE_LIMIT', 'Electron project file count exceeds the configured bound', { count: files.length, maximum: MAX_FILES });
  let total_bytes = 0;
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    if (!file || typeof file.path !== 'string') invalid('ORIX_ELECTRON_FILE_ENTRY', 'Electron project file entry requires a string path', { index });
    if (file.path.length > 4096) invalid('ORIX_ELECTRON_PATH_LIMIT', 'Electron project path exceeds the configured bound', { index, maximum: 4096 });
    if (typeof file.text !== 'string') continue;
    const bytes = Buffer.byteLength(file.text, 'utf8');
    if (bytes > MAX_FILE_BYTES) invalid('ORIX_ELECTRON_FILE_SIZE_LIMIT', 'Electron source file exceeds the per-file byte bound', { index, path: file.path, bytes, maximum: MAX_FILE_BYTES });
    total_bytes += bytes;
    if (total_bytes > MAX_TOTAL_BYTES) invalid('ORIX_ELECTRON_TOTAL_SIZE_LIMIT', 'Electron project source bytes exceed the aggregate bound', { total_bytes, maximum: MAX_TOTAL_BYTES });
  }

  const evidence = package_electron_evidence(files);
  const electron_imports = [];
  const roles = new Set();
  const findings = [];
  let analysis_truncated_files = 0;

  for (const file of files) {
    if (typeof file.text !== 'string' || !/\.(?:[cm]?js|jsx|ts|tsx)$/i.test(file.path)) continue;
    const role = process_role(file.path);
    if (role) roles.add(role);

    const { tokens, truncated } = tokenize_source(file.text);
    if (truncated) analysis_truncated_files += 1;

    const has_module_signal = has_electron_module_signal(tokens);
    const web_preferences = inspect_web_preferences(tokens, file.path);
    if ((has_module_signal || web_preferences.found_object) && electron_imports.length < 500) {
      electron_imports.push({ path: file.path, role });
    }
    findings.push(...web_preferences.findings.slice(0, MAX_FINDINGS - findings.length));
    if (findings.length >= MAX_FINDINGS) break;
  }

  const detected = evidence.length > 0 || electron_imports.length > 0;
  return {
    detected,
    confidence: evidence.length > 0 ? 'strong-project-metadata' : detected ? 'heuristic-source-signal' : 'not-detected',
    evidence: evidence.slice(0, 100),
    electron_source_files: electron_imports.slice(0, 500),
    process_roles: [...roles].sort(),
    findings: findings.slice(0, MAX_FINDINGS),
    analysis_truncated_files,
    limitations: [
      'Static literal-pattern triage only; no JavaScript or TypeScript AST, data-flow, or runtime analysis is performed.',
      'Computed values, spreads, helper functions, environment-dependent configuration and dynamically generated windows may be missed.',
      'Only direct literal boolean properties inside a webPreferences object are inspected; property values in nested objects are not interpreted.',
      'Template literal bodies and regex literal bodies are opaque to the bounded tokenizer.',
      'Each source file is limited to 100,000 tokens; files exceeding this bound are only partially inspected.',
      'File names are role candidates, not proof of Electron process boundaries.',
      'Findings are review leads, not proof of exploitability.',
      'No application code, package scripts, browser session or Electron process is executed.',
    ],
  };
}
