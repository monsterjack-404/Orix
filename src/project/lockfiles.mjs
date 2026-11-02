// JavaScript, src/project/lockfiles.mjs, Node.js 20+, bounded npm and Yarn lockfile inventory.

import { OrixError } from '../core/errors.mjs';

const DEFAULT_MAX_PACKAGES = 100000;
const DEFAULT_MAX_EDGES = 500000;
const MAX_NAME = 512;
const MAX_VERSION = 256;

function fail(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function clean_string(value, maximum, field) {
  if (typeof value !== 'string') return null;
  const result = value.trim();
  if (!result || result.length > maximum || /[\u0000-\u001f\u007f]/.test(result)) return null;
  return result;
}

function package_name_from_path(location) {
  const parts = location.split('/');
  let index = -1;
  for (let i = 0; i < parts.length; i += 1) if (parts[i] === 'node_modules') index = i;
  if (index < 0 || index + 1 >= parts.length) return null;
  return parts[index + 1].startsWith('@')
    ? parts[index + 1] + '/' + (parts[index + 2] ?? '')
    : parts[index + 1];
}

function validate_limits(options) {
  const max_packages = options.max_lockfile_packages ?? DEFAULT_MAX_PACKAGES;
  const max_edges = options.max_lockfile_edges ?? DEFAULT_MAX_EDGES;
  if (!Number.isSafeInteger(max_packages) || max_packages < 1 || max_packages > DEFAULT_MAX_PACKAGES) fail('ORIX_LOCKFILE_BAD_LIMIT', 'max_lockfile_packages must be between 1 and 100000', { max_packages });
  if (!Number.isSafeInteger(max_edges) || max_edges < 1 || max_edges > DEFAULT_MAX_EDGES) fail('ORIX_LOCKFILE_BAD_LIMIT', 'max_lockfile_edges must be between 1 and 500000', { max_edges });
  return { max_packages, max_edges };
}

function parse_npm_package_lock(file, text, limits) {
  let document;
  try { document = JSON.parse(text); }
  catch (error) { fail('ORIX_LOCKFILE_INVALID_JSON', 'npm package-lock is not valid JSON', { file, reason: error.message.slice(0, 160) }); }
  const version = Number(document.lockfileVersion ?? 1);
  if (![1, 2, 3].includes(version)) fail('ORIX_LOCKFILE_UNSUPPORTED_VERSION', 'Unsupported npm package-lock version', { file, lockfile_version: document.lockfileVersion });
  const package_map = new Map();
  const packages = [];
  const edges = [];
  const warnings = [];
  const root_dependencies = [];
  const root_edges_placeholder = [];
  if (document.packages && typeof document.packages === 'object' && !Array.isArray(document.packages)) {
    const root_metadata = document.packages[''] ?? {};
    for (const [kind, field] of [['runtime', 'dependencies'], ['development', 'devDependencies'], ['optional', 'optionalDependencies']]) {
      for (const [name, requirement] of Object.entries(root_metadata[field] ?? {})) root_dependencies.push({ name, requirement: String(requirement).slice(0, MAX_VERSION), dependency_type: kind });
    }
    const entries = Object.entries(document.packages).filter(([location]) => location !== '').sort(([a], [b]) => a.localeCompare(b));
    if (entries.length > limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'npm lockfile package count exceeds configured limit', { file, count: entries.length, maximum: limits.max_packages });
    for (const [location, metadata] of entries) {
      if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) continue;
      const name = clean_string(metadata.name, MAX_NAME, 'name') ?? package_name_from_path(location);
      const resolved_version = clean_string(metadata.version, MAX_VERSION, 'version');
      if (!name || !resolved_version) { warnings.push({ code: 'ORIX_LOCKFILE_PACKAGE_IDENTITY', location }); continue; }
      const dependency_type = location.split('/node_modules/').length === 1 ? 'direct-or-hoisted' : 'transitive';
      const item = {
        name,
        version: resolved_version,
        ecosystem: 'npm',
        location,
        dependency_type,
        dev: metadata.dev === true,
        optional: metadata.optional === true,
        peer: metadata.peer === true,
        integrity: clean_string(metadata.integrity, 2048, 'integrity'),
        resolved: clean_string(metadata.resolved, 4096, 'resolved'),
        license: clean_string(metadata.license, 256, 'license'),
        dependencies: metadata.dependencies && typeof metadata.dependencies === 'object' && !Array.isArray(metadata.dependencies)
          ? Object.entries(metadata.dependencies).map(([dependency, requirement]) => ({ name: dependency, requirement: String(requirement).slice(0, MAX_VERSION) }))
          : [],
      };
      package_map.set(location, item);
      packages.push(item);
    }
    const resolve_package = (from_location, dependency_name) => {
      let ancestor = from_location;
      while (ancestor) {
        const candidate = ancestor + '/node_modules/' + dependency_name;
        if (package_map.has(candidate)) return package_map.get(candidate);
        const marker = ancestor.lastIndexOf('/node_modules/');
        if (marker >= 0) ancestor = ancestor.slice(0, marker);
        else if (ancestor.startsWith('node_modules/')) ancestor = '';
        else ancestor = '';
      }
      return package_map.get('node_modules/' + dependency_name) ?? null;
    };
    for (const item of packages) {
      for (const dependency of item.dependencies) {
        const target = resolve_package(item.location, dependency.name);
        if (target) edges.push({ from: item.location, to: target.location, name: dependency.name, requirement: dependency.requirement, resolved_version: target.version });
        else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_EDGE', from: item.location, dependency: dependency.name });
        if (edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'npm lockfile dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
      }
    }
  } else if (document.dependencies && typeof document.dependencies === 'object' && !Array.isArray(document.dependencies)) {
    const visit = (entries, parent = null, depth = 0) => {
      if (depth > 256) fail('ORIX_LOCKFILE_DEPTH_LIMIT', 'npm v1 lockfile nesting exceeds 256 levels', { file });
      for (const [name, metadata] of Object.entries(entries)) {
        if (packages.length >= limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'npm lockfile package count exceeds configured limit', { file, maximum: limits.max_packages });
        if (!metadata || typeof metadata !== 'object') continue;
        const resolved_version = clean_string(metadata.version, MAX_VERSION, 'version');
        if (!resolved_version) { warnings.push({ code: 'ORIX_LOCKFILE_PACKAGE_IDENTITY', name }); continue; }
        const location = parent ? parent + '/node_modules/' + name : 'node_modules/' + name;
        const item = { name, version: resolved_version, ecosystem: 'npm', location, dependency_type: parent ? 'transitive' : 'direct-or-hoisted', dev: metadata.dev === true, optional: metadata.optional === true, peer: false, integrity: clean_string(metadata.integrity, 2048, 'integrity'), resolved: clean_string(metadata.resolved, 4096, 'resolved'), license: null, dependencies: Object.entries(metadata.requires ?? {}).map(([dependency, requirement]) => ({ name: dependency, requirement: String(requirement).slice(0, MAX_VERSION) })) };
        packages.push(item); package_map.set(location, item);
        if (parent) edges.push({ from: parent, to: location, name, requirement: '*', resolved_version });
        visit(metadata.dependencies ?? {}, location, depth + 1);
      }
    };
    visit(document.dependencies);
    for (const [name, metadata] of Object.entries(document.dependencies)) {
      root_dependencies.push({ name, requirement: '*', dependency_type: metadata?.dev ? 'development' : metadata?.optional ? 'optional' : 'runtime' });
      const target = package_map.get('node_modules/' + name);
      if (target) root_edges_placeholder.push({ name, requirement: '*', dependency_type: metadata?.dev ? 'development' : metadata?.optional ? 'optional' : 'runtime', to: target.location, resolved_version: target.version });
    }
    for (const item of packages) {
      for (const dependency of item.dependencies) {
        let ancestor = item.location;
        let target = null;
        while (ancestor) {
          target = package_map.get(ancestor + '/node_modules/' + dependency.name);
          if (target) break;
          const marker = ancestor.lastIndexOf('/node_modules/');
          if (marker >= 0) ancestor = ancestor.slice(0, marker);
          else ancestor = '';
        }
        target ??= package_map.get('node_modules/' + dependency.name);
        if (target) edges.push({ from: item.location, to: target.location, name: dependency.name, requirement: dependency.requirement, resolved_version: target.version });
        if (edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'npm lockfile dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
      }
    }
  } else {
    warnings.push({ code: 'ORIX_LOCKFILE_NO_PACKAGE_TABLE' });
  }
  const root_edges = root_edges_placeholder.length ? root_edges_placeholder : root_dependencies.map(dependency => {
    const target = package_map.get('node_modules/' + dependency.name);
    return target ? { name: dependency.name, requirement: dependency.requirement, dependency_type: dependency.dependency_type, to: target.location, resolved_version: target.version } : null;
  }).filter(Boolean);
  return {
    path: file,
    ecosystem: 'npm',
    format: 'npm-package-lock',
    lockfile_version: version,
    packages,
    edges,
    root_dependencies,
    root_edges,
    warnings,
    complete: warnings.length === 0,
  };
}

function split_yarn_key(value) {
  const result = [];
  let current = '';
  let quote = null;
  let escaped = false;
  for (const character of value) {
    if (escaped) { current += character; escaped = false; continue; }
    if (character === '\\' && quote) { current += character; escaped = true; continue; }
    if ((character === '"' || character === "'") && (!quote || quote === character)) { quote = quote ? null : character; continue; }
    if (character === ',' && !quote) { if (current.trim()) result.push(current.trim()); current = ''; }
    else current += character;
  }
  if (current.trim()) result.push(current.trim());
  return result.map(item => item.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
}

function parse_yarn_lock(file, text, limits) {
  const lines = text.split(/\r?\n/);
  const packages = [];
  const by_selector = new Map();
  let current = null;
  let section = null;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(line) && line.endsWith(':')) {
      const selectors = split_yarn_key(line.slice(0, -1));
      current = { selectors, name: null, version: null, resolved: null, integrity: null, dependencies: [], optional_dependencies: [] };
      packages.push(current);
      for (const selector of selectors) by_selector.set(selector, current);
      section = null;
      if (packages.length > limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'Yarn lockfile package count exceeds configured limit', { file, maximum: limits.max_packages });
      continue;
    }
    if (!current) continue;
    const trimmed = line.trim();
    const field = /^(version|resolved|integrity|name)\s+(.+)$/.exec(trimmed);
    if (field && !trimmed.startsWith('version:')) {
      const value = field[2].replace(/^['"]|['"]$/g, '');
      if (field[1] === 'version') current.version = value;
      else if (field[1] === 'resolved' || field[1] === 'resolution') current.resolved = value;
      else if (field[1] === 'integrity' || field[1] === 'checksum') current.integrity = value;
      else if (field[1] === 'name') current.name = value;
      section = null;
      continue;
    }
    const block = /^(dependencies|optionalDependencies):\s*$/.exec(trimmed);
    if (block) { section = block[1]; continue; }
    if (section && /^\s{4,}/.test(line)) {
      const dependency = /^([^\s]+)\s+(.+)$/.exec(trimmed);
      if (dependency) current[section === 'dependencies' ? 'dependencies' : 'optional_dependencies'].push({ name: dependency[1], requirement: dependency[2].replace(/^['"]|['"]$/g, '') });
      continue;
    }
    section = null;
  }
  const resolve_name = selector => {
    const match = /^(?:@[^/]+\/)?[^@]+@(.+)$/.exec(selector);
    if (!match) return selector.split('@')[0];
    return selector.slice(0, selector.lastIndexOf('@'));
  };
  const resolved = [];
  const edges = [];
  const warnings = [];
  for (let index = 0; index < packages.length; index += 1) {
    const item = packages[index];
    const name = clean_string(item.name, MAX_NAME, 'name') ?? resolve_name(item.selectors[0] ?? '');
    const version = clean_string(item.version, MAX_VERSION, 'version');
    if (!name || !version) continue;
    const record = {
      name, version, ecosystem: 'npm', location: item.selectors.join(', '),
      dependency_type: 'resolved', dev: false, optional: item.optional_dependencies.length > 0,
      peer: false, integrity: clean_string(item.integrity, 2048, 'integrity'),
      resolved: clean_string(item.resolved, 4096, 'resolved'), license: null,
      dependencies: [...item.dependencies, ...item.optional_dependencies],
    };
    resolved.push(record);
    for (const dependency of record.dependencies) {
      const selector = dependency.name + '@' + dependency.requirement;
      const candidate = by_selector.get(selector) ?? by_selector.get(dependency.name + '@npm:' + dependency.requirement);
      if (candidate) edges.push({ from: record.location, to: candidate.selectors.join(', '), name: dependency.name, requirement: dependency.requirement, resolved_version: candidate.version });
      else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_EDGE', from: record.location, dependency: dependency.name });
      if (edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'Yarn lockfile dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  return { path: file, ecosystem: 'npm', format: 'yarn-lock', lockfile_version: null, packages: resolved, edges, warnings, complete: warnings.length === 0 };
}

export function parse_lockfile(file, text, options = {}) {
  if (typeof file !== 'string' || typeof text !== 'string') throw new TypeError('parse_lockfile requires a file path and text');
  const limits = validate_limits(options);
  const base = file.split('/').at(-1);
  if (base === 'package-lock.json') return parse_npm_package_lock(file, text, limits);
  if (base === 'yarn.lock') return parse_yarn_lock(file, text, limits);
  return null;
}
