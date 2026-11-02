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
    const root_dependency_map = new Map();
    for (const [kind, field] of [['runtime', 'dependencies'], ['development', 'devDependencies'], ['optional', 'optionalDependencies']]) {
      for (const [name, requirement] of Object.entries(root_metadata[field] ?? {})) {
        if (!root_dependency_map.has(name)) root_dependency_map.set(name, { name, requirement: String(requirement).slice(0, MAX_VERSION), dependency_type: kind });
      }
    }
    root_dependencies.push(...root_dependency_map.values());
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
  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(line) && line.endsWith(':')) {
      const selectors = split_yarn_key(line.slice(0, -1));
      if (selectors.length === 1 && selectors[0] === '__metadata') {
        current = null;
        section = null;
        continue;
      }
      current = { selectors, name: null, version: null, resolved: null, integrity: null, dependencies: [], optional_dependencies: [] };
      packages.push(current);
      for (const selector of selectors) by_selector.set(selector, current);
      section = null;
      if (packages.length > limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'Yarn lockfile package count exceeds configured limit', { file, maximum: limits.max_packages });
      continue;
    }
    if (!current) continue;
    const trimmed = line.trim();
    const field = /^(version|resolved|integrity|name|resolution|checksum):?\s+(.+)$/.exec(trimmed);
    if (field) {
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
      const dependency = /^("[^"]+"|'[^']+'|[^\s]+)\s+(.+)$/.exec(trimmed);
      if (dependency) {
        const name = dependency[1].replace(/^['"]|['"]$/g, '').replace(/:$/, '');
        const requirement = dependency[2].replace(/^['"]|['"]$/g, '');
        current[section === 'dependencies' ? 'dependencies' : 'optional_dependencies'].push({ name, requirement });
      }
      continue;
    }
    section = null;
  }
  const resolve_name = selector => {
    const separator = selector.lastIndexOf('@');
    return separator > 0 ? selector.slice(0, separator) : selector;
  };
  const resolved = [];
  const edges = [];
  const warnings = [];
  for (const item of packages) {
    const name = clean_string(item.name, MAX_NAME, 'name') ?? resolve_name(item.selectors[0] ?? '');
    const version = clean_string(item.version, MAX_VERSION, 'version');
    if (!name || !version) {
      warnings.push({ code: 'ORIX_LOCKFILE_PACKAGE_IDENTITY', selectors: item.selectors });
      continue;
    }
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
      if (candidate) {
        edges.push({ from: record.location, to: candidate.selectors.join(', '), name: dependency.name, requirement: dependency.requirement, resolved_version: candidate.version });
      } else {
        warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_EDGE', from: record.location, dependency: dependency.name });
      }
      if (edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'Yarn lockfile dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  return { path: file, ecosystem: 'npm', format: 'yarn-lock', lockfile_version: null, packages: resolved, edges, root_dependencies: [], root_edges: [], warnings, complete: warnings.length === 0 };
}

function decode_toml_string(value) {
  const token = value.trim();
  if (token.startsWith('"')) {
    try { return JSON.parse(token); } catch { return null; }
  }
  if (token.startsWith("'") && token.endsWith("'")) return token.slice(1, -1);
  return null;
}

function parse_cargo_dependency(value) {
  const match = /^(.+?)\s+([^\s(]+)(?:\s+\((.+)\))?$/.exec(value.trim());
  if (!match) return null;
  const name = clean_string(match[1], MAX_NAME, 'dependency name');
  const version = clean_string(match[2], MAX_VERSION, 'dependency version');
  const source = clean_string(match[3] ?? '', 4096, 'dependency source');
  return name && version ? { name, version, source } : null;
}

function parse_cargo_lock(file, text, limits) {
  const blocks = [];
  let lockfile_version = null;
  let current = null;
  let reading_dependencies = false;
  const read_dependency_values = value => {
    const matches = value.match(/"(?:\\.|[^"\\])*"|'[^']*'/g) ?? [];
    for (const token of matches) {
      const decoded = decode_toml_string(token);
      if (decoded !== null) current.dependencies.push(decoded);
    }
  };
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*version\s*=/.test(line) && !current) {
      const match = /^\s*version\s*=\s*(\d+)/.exec(line);
      if (match) lockfile_version = Number(match[1]);
      continue;
    }
    if (/^\s*\[\[package\]\]\s*(?:#.*)?$/.test(line)) {
      current = { name: null, version: null, source: null, checksum: null, dependencies: [] };
      blocks.push(current);
      reading_dependencies = false;
      if (blocks.length > limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'Cargo.lock package count exceeds configured limit', { file, maximum: limits.max_packages });
      continue;
    }
    if (!current) continue;
    if (reading_dependencies) {
      read_dependency_values(line);
      if (line.includes(']')) reading_dependencies = false;
      continue;
    }
    const dependencies_match = /^\s*dependencies\s*=\s*\[(.*)$/.exec(line);
    if (dependencies_match) {
      current.dependencies = [];
      read_dependency_values(dependencies_match[1]);
      reading_dependencies = !dependencies_match[1].includes(']');
      continue;
    }
    const field = /^\s*(name|version|source|checksum)\s*=\s*("(?:\\.|[^"\\])*"|'[^']*')/.exec(line);
    if (!field) continue;
    const value = decode_toml_string(field[2]);
    if (field[1] === 'name') current.name = value;
    else if (field[1] === 'version') current.version = value;
    else if (field[1] === 'source') current.source = value;
    else if (field[1] === 'checksum') current.checksum = value;
  }
  const warnings = [];
  if (blocks.length === 0) warnings.push({ code: 'ORIX_LOCKFILE_NO_PACKAGE_TABLE' });
  const package_map = new Map();
  const packages = [];
  const local_packages = [];
  for (const block of blocks) {
    const name = clean_string(block.name, MAX_NAME, 'package name');
    const version = clean_string(block.version, MAX_VERSION, 'package version');
    if (!name || !version) {
      warnings.push({ code: 'ORIX_LOCKFILE_PACKAGE_IDENTITY' });
      continue;
    }
    const location = name + '@' + version + (block.source ? '#' + block.source : '#workspace');
    const item = {
      name, version, ecosystem: 'cargo', location,
      dependency_type: block.source ? 'runtime' : 'workspace',
      dev: false, optional: false, peer: false,
      integrity: clean_string(block.checksum, 2048, 'checksum'),
      resolved: clean_string(block.source, 4096, 'source'),
      license: null,
      dependencies: block.dependencies.map(parse_cargo_dependency).filter(Boolean),
    };
    if (block.source) {
      packages.push(item);
      const key = name + '@' + version;
      const values = package_map.get(key) ?? [];
      values.push(item);
      package_map.set(key, values);
    } else {
      local_packages.push(item);
    }
  }
  const edges = [];
  const root_dependencies = [];
  const root_edges = [];
  const resolve = dependency => {
    const candidates = package_map.get(dependency.name + '@' + dependency.version) ?? [];
    if (dependency.source) return candidates.find(item => item.resolved === dependency.source) ?? null;
    if (candidates.length === 1) return candidates[0];
    if (candidates.length > 1) warnings.push({ code: 'ORIX_LOCKFILE_AMBIGUOUS_DEPENDENCY', name: dependency.name, version: dependency.version });
    return null;
  };
  for (const item of packages) {
    for (const dependency of item.dependencies) {
      const target = resolve(dependency);
      if (target) edges.push({ from: item.location, to: target.location, name: dependency.name, requirement: dependency.version, resolved_version: target.version });
      else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_EDGE', from: item.location, dependency: dependency.name, version: dependency.version });
      if (edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'Cargo.lock dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  for (const item of local_packages) {
    for (const dependency of item.dependencies) {
      root_dependencies.push({ name: dependency.name, requirement: dependency.version, dependency_type: 'runtime' });
      const target = resolve(dependency);
      if (target) root_edges.push({ name: dependency.name, requirement: dependency.version, to: target.location, resolved_version: target.version });
      else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_ROOT_EDGE', package: item.name, dependency: dependency.name, version: dependency.version });
      if (root_edges.length + edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'Cargo.lock total dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  return {
    path: file, ecosystem: 'cargo', format: 'cargo-lock', lockfile_version,
    packages, edges, root_dependencies, root_edges, warnings, complete: warnings.length === 0,
  };
}

function parse_pnpm_scalar(value) {
  const input = value.trim().replace(/,$/, '');
  if (!input) return null;
  if ((input.startsWith('"') && input.endsWith('"')) || (input.startsWith("'") && input.endsWith("'"))) return input.slice(1, -1);
  return input;
}

function parse_pnpm_package_key(value) {
  let key = parse_pnpm_scalar(value) ?? '';
  key = key.replace(/^\//, '');
  let separator = -1;
  if (key.startsWith('@')) separator = key.indexOf('@', key.indexOf('/') + 1);
  else separator = key.indexOf('@');
  let name;
  let raw_version;
  if (separator > 0) {
    name = key.slice(0, separator);
    raw_version = key.slice(separator + 1);
  } else {
    const slash = key.lastIndexOf('/');
    if (slash < 1) return null;
    name = key.slice(0, slash);
    raw_version = key.slice(slash + 1);
  }
  const peer_start = raw_version.indexOf('(');
  const version = peer_start < 0 ? raw_version : raw_version.slice(0, peer_start);
  const peer_suffix = peer_start < 0 ? '' : raw_version.slice(peer_start);
  if (!clean_string(name, MAX_NAME, 'package name') || !clean_string(version, MAX_VERSION, 'package version')) return null;
  return { name, version, peer_suffix };
}

function parse_pnpm_lock(file, text, limits) {
  const lines = text.split(/\r?\n/);
  let lockfile_version = null;
  let section = '';
  let current_record = null;
  let current_importer = null;
  let record_dependency_field = null;
  let record_section = null;
  let importer_dependency_field = null;
  let current_dependency = null;
  let current_dependency_target = null;
  const package_records = [];
  const snapshot_records = [];
  const importer_records = [];
  const top_level_dependencies = [];
  let top_level_dependency_field = null;
  let current_top_level_dependency = null;
  const warnings = [];
  const read_inline_resolution = (record, value) => {
    const integrity = /(?:^|[,{]\s*)integrity:\s*([^,}]+)/.exec(value);
    const tarball = /(?:^|[,{]\s*)tarball:\s*([^,}]+)/.exec(value);
    if (integrity) record.integrity = parse_pnpm_scalar(integrity[1]);
    if (tarball) record.resolved = parse_pnpm_scalar(tarball[1]);
  };
  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const indent = line.length - line.trimStart().length;
    const body = line.trim();
    if (indent === 0) {
      const header = /^([A-Za-z][A-Za-z0-9_-]*):(?:\s*(.*))?$/.exec(body);
      if (!header) continue;
      section = header[1];
      current_record = null;
      current_importer = null;
      record_dependency_field = null;
      record_section = null;
      importer_dependency_field = null;
      current_dependency = null;
      if (section === 'lockfileVersion') lockfile_version = Number(parse_pnpm_scalar(header[2] ?? ''));
      continue;
    }
    if (['dependencies', 'devDependencies', 'optionalDependencies'].includes(section)) {
      if (indent === 2) {
        const dependency = /^(.+?):(?:\s*(.*))?$/.exec(body);
        if (dependency) {
          current_top_level_dependency = { name: parse_pnpm_scalar(dependency[1]), specifier: null, version: parse_pnpm_scalar(dependency[2] ?? ''), dependency_type: section };
          top_level_dependencies.push(current_top_level_dependency);
        }
        continue;
      }
      if (indent >= 4 && current_top_level_dependency) {
        const field = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/.exec(body);
        if (field && ['specifier', 'version'].includes(field[1])) current_top_level_dependency[field[1]] = parse_pnpm_scalar(field[2]);
      }
      continue;
    }
    if (section === 'importers') {
      if (indent === 2 && body.endsWith(':')) {
        current_importer = { path: parse_pnpm_scalar(body.slice(0, -1)), dependencies: [] };
        importer_records.push(current_importer);
        importer_dependency_field = null;
        current_dependency = null;
        continue;
      }
      if (!current_importer) continue;
      if (indent === 4) {
        const field = /^([A-Za-z][A-Za-z0-9_-]*):(?:\s*(.*))?$/.exec(body);
        if (field) {
          importer_dependency_field = ['dependencies', 'devDependencies', 'optionalDependencies'].includes(field[1]) ? field[1] : null;
          current_dependency = null;
        }
        continue;
      }
      if (indent === 6 && importer_dependency_field) {
        const dependency = /^(.+?):(?:\s*(.*))?$/.exec(body);
        if (dependency) {
          current_dependency = { name: parse_pnpm_scalar(dependency[1]), specifier: null, version: parse_pnpm_scalar(dependency[2] ?? '') };
          current_importer.dependencies.push({ ...current_dependency, dependency_type: importer_dependency_field });
        }
        continue;
      }
      if (indent >= 8 && current_dependency && importer_dependency_field) {
        const field = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/.exec(body);
        if (field && ['specifier', 'version'].includes(field[1])) {
          current_dependency[field[1]] = parse_pnpm_scalar(field[2]);
          const target = current_importer.dependencies.at(-1);
          if (target) target[field[1]] = current_dependency[field[1]];
        }
      }
      continue;
    }
    if (section !== 'packages' && section !== 'snapshots') continue;
    const target_records = section === 'packages' ? package_records : snapshot_records;
    if (indent === 2 && body.endsWith(':')) {
      current_record = { key: parse_pnpm_scalar(body.slice(0, -1)), dependencies: [], optional_dependencies: [], integrity: null, resolved: null, dev: false, optional: false, license: null };
      target_records.push(current_record);
      record_dependency_field = null;
      record_section = null;
      current_dependency = null;
      if (target_records.length > limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'pnpm lockfile package count exceeds configured limit', { file, maximum: limits.max_packages });
      continue;
    }
    if (!current_record) continue;
    if (indent === 4) {
      const field = /^([A-Za-z][A-Za-z0-9_-]*):(?:\s*(.*))?$/.exec(body);
      if (!field) continue;
      record_dependency_field = ['dependencies', 'optionalDependencies'].includes(field[1]) ? field[1] : null;
      record_section = field[1] === 'resolution' && !(field[2] ?? '').trim() ? 'resolution' : null;
      current_dependency = null;
      if (field[1] === 'resolution') read_inline_resolution(current_record, field[2] ?? '');
      else if (field[1] === 'dev') current_record.dev = parse_pnpm_scalar(field[2] ?? '') === 'true';
      else if (field[1] === 'optional') current_record.optional = parse_pnpm_scalar(field[2] ?? '') === 'true';
      else if (field[1] === 'license') current_record.license = parse_pnpm_scalar(field[2] ?? '');
      continue;
    }
    if (indent === 6 && record_section === 'resolution') {
      const resolution_field = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/.exec(body);
      if (resolution_field && resolution_field[1] === 'integrity') current_record.integrity = parse_pnpm_scalar(resolution_field[2]);
      if (resolution_field && resolution_field[1] === 'tarball') current_record.resolved = parse_pnpm_scalar(resolution_field[2]);
      continue;
    }
    if (indent === 6 && record_dependency_field) {
      const dependency = /^(.+?):(?:\s*(.*))?$/.exec(body);
      if (dependency) {
        current_dependency = { name: parse_pnpm_scalar(dependency[1]), version: parse_pnpm_scalar(dependency[2] ?? '') };
        current_record[record_dependency_field].push(current_dependency);
      }
      continue;
    }
    if (indent >= 8 && current_dependency && record_dependency_field) {
      const field = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/.exec(body);
      if (field && field[1] === 'version') current_dependency.version = parse_pnpm_scalar(field[2]);
    }
  }
  if (!(lockfile_version === 6 || lockfile_version === 9 || (lockfile_version >= 5 && lockfile_version < 6))) warnings.push({ code: 'ORIX_LOCKFILE_UNSUPPORTED_VERSION', lockfile_version });
  if (package_records.length === 0) warnings.push({ code: 'ORIX_LOCKFILE_NO_PACKAGE_TABLE' });
  const packages = [];
  const by_name_version = new Map();
  const metadata_by_key = new Map();
  for (const record of package_records) {
    const identity = parse_pnpm_package_key(record.key);
    if (!identity) { warnings.push({ code: 'ORIX_LOCKFILE_PACKAGE_IDENTITY', key: record.key }); continue; }
    const snapshot = snapshot_records.find(item => item.key === record.key);
    const dependency_source = snapshot ?? record;
    const item = {
      name: identity.name,
      version: identity.version,
      ecosystem: 'npm',
      location: record.key,
      dependency_type: 'resolved',
      dev: record.dev,
      optional: record.optional,
      peer: Boolean(identity.peer_suffix),
      integrity: clean_string(record.integrity, 2048, 'integrity'),
      resolved: clean_string(record.resolved, 4096, 'resolved'),
      license: clean_string(record.license, 256, 'license'),
      peer_suffix: identity.peer_suffix || null,
      dependencies: [...(dependency_source.dependencies ?? []), ...(dependency_source.optional_dependencies ?? [])].filter(dep => clean_string(dep.name, MAX_NAME, 'dependency name') && clean_string(dep.version, MAX_VERSION, 'dependency version')),
    };
    packages.push(item);
    metadata_by_key.set(record.key, item);
    const key = identity.name + '@' + identity.version;
    const candidates = by_name_version.get(key) ?? [];
    candidates.push(item);
    by_name_version.set(key, candidates);
  }
  const resolve_package = (name, version) => {
    const normalized_version = String(version ?? '').replace(/\(.*/, '');
    const candidates = by_name_version.get(name + '@' + normalized_version) ?? [];
    if (candidates.length === 1) return candidates[0];
    if (candidates.length > 1) {
      const peer_suffix = String(version ?? '').slice(normalized_version.length);
      const exact = candidates.find(item => item.peer_suffix === peer_suffix);
      if (exact) return exact;
      warnings.push({ code: 'ORIX_LOCKFILE_AMBIGUOUS_DEPENDENCY', name, version });
    }
    return null;
  };
  const edges = [];
  for (const item of packages) {
    for (const dependency of item.dependencies) {
      const target = resolve_package(dependency.name, dependency.version);
      if (target) edges.push({ from: item.location, to: target.location, name: dependency.name, requirement: dependency.version, resolved_version: target.version });
      else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_EDGE', from: item.location, dependency: dependency.name, version: dependency.version });
      if (edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'pnpm lockfile dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  const root_dependencies = [];
  const root_edges = [];
  for (const dependency of top_level_dependencies) {
    const requirement = dependency.specifier ?? dependency.version ?? '*';
    root_dependencies.push({ name: dependency.name, requirement, dependency_type: dependency.dependency_type });
    const target = resolve_package(dependency.name, dependency.version);
    if (target) root_edges.push({ name: dependency.name, requirement, dependency_type: dependency.dependency_type, to: target.location, resolved_version: target.version, importer: '.' });
    else if (!String(dependency.version ?? '').startsWith('link:')) warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_ROOT_EDGE', importer: '.', dependency: dependency.name, version: dependency.version });
  }
  for (const importer of importer_records) {
    for (const dependency of importer.dependencies) {
      root_dependencies.push({ name: dependency.name, requirement: dependency.specifier ?? '*', dependency_type: dependency.dependency_type });
      const target = resolve_package(dependency.name, dependency.version);
      if (target) {
        if (dependency.dependency_type === 'devDependencies') target.dev = true;
        if (dependency.dependency_type === 'optionalDependencies') target.optional = true;
        root_edges.push({ name: dependency.name, requirement: dependency.specifier ?? '*', dependency_type: dependency.dependency_type, to: target.location, resolved_version: target.version, importer: importer.path });
      }
      else if (!String(dependency.version ?? '').startsWith('link:')) warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_ROOT_EDGE', importer: importer.path, dependency: dependency.name, version: dependency.version });
      if (edges.length + root_edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'pnpm lockfile total dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  return { path: file, ecosystem: 'pnpm', format: 'pnpm-lock', lockfile_version, packages, edges, root_dependencies, root_edges, warnings, complete: warnings.length === 0 };
}

function parse_composer_lock(file, text, limits, manifests) {
  let document;
  try { document = JSON.parse(text); }
  catch (error) { fail('ORIX_LOCKFILE_INVALID_JSON', 'Composer lockfile is not valid JSON', { file, reason: error.message.slice(0, 160) }); }
  if (!document || typeof document !== 'object' || Array.isArray(document)) fail('ORIX_LOCKFILE_DOCUMENT', 'Composer lockfile root must be an object', { file });
  const runtime = Array.isArray(document.packages) ? document.packages : [];
  const development = Array.isArray(document['packages-dev']) ? document['packages-dev'] : [];
  if (runtime.length + development.length > limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'Composer lockfile package count exceeds configured limit', { file, count: runtime.length + development.length, maximum: limits.max_packages });
  const packages = [];
  const by_name = new Map();
  const warnings = [];
  for (const [entries, dependency_type] of [[runtime, 'runtime'], [development, 'development']]) {
    for (const entry of entries) {
      const name = clean_string(entry?.name, MAX_NAME, 'package name');
      const version = clean_string(entry?.version, MAX_VERSION, 'package version');
      if (!name || !version) { warnings.push({ code: 'ORIX_LOCKFILE_PACKAGE_IDENTITY' }); continue; }
      const source_type = clean_string(entry.source?.type, 64, 'source type');
      const source_reference = clean_string(entry.source?.reference, 256, 'source reference');
      const dist_shasum = clean_string(entry.dist?.shasum, 128, 'dist shasum');
      const item = {
        name, version, ecosystem: 'composer', location: name + '@' + version,
        dependency_type, dev: dependency_type === 'development', optional: false, peer: false,
        integrity: dist_shasum && /^[a-f0-9]{40,128}$/i.test(dist_shasum) ? dist_shasum : null,
        resolved: source_type && source_reference ? source_type + ':' + source_reference : null,
        license: Array.isArray(entry.license) ? entry.license.map(value => clean_string(value, 128, 'license')).filter(Boolean).slice(0, 20) : [],
        dependencies: Object.entries(entry.require && typeof entry.require === 'object' && !Array.isArray(entry.require) ? entry.require : {}).map(([dependency, requirement]) => ({ name: dependency, requirement: String(requirement).slice(0, MAX_VERSION) })),
      };
      packages.push(item);
      const candidates = by_name.get(name) ?? [];
      candidates.push(item);
      by_name.set(name, candidates);
    }
  }
  const edges = [];
  const root_edges = [];
  const resolve = name => {
    const candidates = by_name.get(name) ?? [];
    if (candidates.length === 1) return candidates[0];
    if (candidates.length > 1) warnings.push({ code: 'ORIX_LOCKFILE_AMBIGUOUS_DEPENDENCY', name });
    return null;
  };
  for (const item of packages) {
    for (const dependency of item.dependencies) {
      if (/^(?:php|ext-|lib-)/i.test(dependency.name)) continue;
      const target = resolve(dependency.name);
      if (target) edges.push({ from: item.location, to: target.location, name: dependency.name, requirement: dependency.requirement, resolved_version: target.version });
      else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_EDGE', from: item.location, dependency: dependency.name });
      if (edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'Composer lockfile dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  const manifest = manifests.find(item => item.ecosystem === 'composer');
  const root_dependencies = (manifest?.dependencies ?? []).map(item => ({ name: item.name, requirement: item.version, dependency_type: item.dependency_type === 'require-dev' ? 'development' : 'runtime' }));
  for (const dependency of root_dependencies) {
    const target = resolve(dependency.name);
    if (target) root_edges.push({ name: dependency.name, requirement: dependency.requirement, dependency_type: dependency.dependency_type, to: target.location, resolved_version: target.version });
    else if (!/^(?:php|ext-|lib-)/i.test(dependency.name)) warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_ROOT_EDGE', dependency: dependency.name });
    if (edges.length + root_edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'Composer lockfile total dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
  }
  return { path: file, ecosystem: 'composer', format: 'composer-lock', lockfile_version: null, packages, edges, root_dependencies, root_edges, warnings, complete: warnings.length === 0 };
}

function parse_go_sum(file, text, limits, manifests) {
  const records = new Map();
  const warnings = [];
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const value = line.trim();
    if (!value || value.startsWith('//')) continue;
    const fields = value.split(/\s+/);
    if (fields.length !== 3) {
      warnings.push({ code: 'ORIX_LOCKFILE_GO_SUM_LINE', line: index + 1 });
      continue;
    }
    const name = clean_string(fields[0], MAX_NAME, 'module path');
    const checksum = clean_string(fields[2], 256, 'module checksum');
    const go_mod_only = fields[1].endsWith('/go.mod');
    const version = clean_string(go_mod_only ? fields[1].slice(0, -7) : fields[1], MAX_VERSION, 'module version');
    if (!name || !version || !checksum || !/^h1:[A-Za-z0-9+/=]+$/.test(checksum)) {
      warnings.push({ code: 'ORIX_LOCKFILE_GO_SUM_ENTRY', line: index + 1 });
      continue;
    }
    const key = name + '@' + version;
    const existing = records.get(key);
    if (!existing || (!go_mod_only && existing.checksum_kind === 'go.mod')) {
      records.set(key, {
        name, version, ecosystem: 'go', location: key,
        dependency_type: 'resolved', dev: false, optional: false, peer: false,
        integrity: checksum, checksum_kind: go_mod_only ? 'go.mod' : 'module',
        resolved: null, license: null, dependencies: [],
      });
    } else if (existing.integrity !== checksum && existing.checksum_kind === (go_mod_only ? 'go.mod' : 'module')) {
      warnings.push({ code: 'ORIX_LOCKFILE_GO_SUM_CONFLICT', module: name, version });
    }
    if (records.size > limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'go.sum module count exceeds configured limit', { file, maximum: limits.max_packages });
  }
  const packages = [...records.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  const by_identity = new Map(packages.map(item => [item.name + '@' + item.version, item]));
  const root_dependencies = [];
  const root_edges = [];
  for (const manifest of manifests) {
    if (manifest.ecosystem !== 'go') continue;
    for (const dependency of manifest.dependencies ?? []) {
      root_dependencies.push({ name: dependency.name, requirement: dependency.version, dependency_type: dependency.dependency_type });
      const target = by_identity.get(dependency.name + '@' + dependency.version);
      if (target) root_edges.push({ name: dependency.name, requirement: dependency.version, dependency_type: dependency.dependency_type, to: target.location, resolved_version: target.version });
      else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_ROOT_EDGE', dependency: dependency.name, version: dependency.version, manifest: manifest.path });
      if (root_edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'go.sum root dependency count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  return {
    path: file, ecosystem: 'go', format: 'go-sum', lockfile_version: null,
    packages, edges: [], root_dependencies, root_edges, warnings, complete: warnings.length === 0,
  };
}

function python_package_key(value) {
  return String(value ?? '').toLowerCase().replace(/[-_.]+/g, '-');
}

function parse_poetry_lock(file, text, limits, manifests) {
  const blocks = [];
  let metadata_version = null;
  let current = null;
  let section = '';
  let reading_files = false;
  const parse_array_strings = value => (value.match(/"(?:\\.|[^"\\])*"|'[^']*'/g) ?? []).map(decode_toml_string).filter(Boolean);
  const parse_toml_dependency_version = value => {
    const inline = /\bversion\s*=\s*("(?:\\.|[^"\\])*"|'[^']*')/.exec(value);
    if (inline) return decode_toml_string(inline[1]);
    return decode_toml_string(value) ?? value.trim().replace(/^['"]|['"]$/g, '');
  };
  for (const line of text.split(/\r?\n/)) {
    const header = /^\s*\[\[package\]\]\s*(?:#.*)?$/.exec(line);
    if (header) {
      current = { name: null, version: null, optional: false, groups: [], source: null, files: [], dependencies: [] };
      blocks.push(current);
      section = 'package';
      if (blocks.length > limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'Poetry lockfile package count exceeds configured limit', { file, maximum: limits.max_packages });
      continue;
    }
    const table = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(line);
    if (table) {
      section = table[1];
      reading_files = false;
      continue;
    }
    if (section === 'package' && reading_files) {
      const hash_match = /hash\s*=\s*("(?:\\.|[^"\\])*"|'[^']*')/.exec(line);
      if (hash_match) current?.files.push(decode_toml_string(hash_match[1]));
      if (line.includes(']')) reading_files = false;
      continue;
    }
    const field = /^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*(?:#.*)?$/.exec(line);
    if (!field) continue;
    const key = field[1];
    const value = field[2];
    if (section === 'metadata' && key === 'lock-version') {
      metadata_version = decode_toml_string(value) ?? value;
      continue;
    }
    if (!current) continue;
    if (section === 'package') {
      if (key === 'name') current.name = decode_toml_string(value);
      else if (key === 'version') current.version = decode_toml_string(value);
      else if (key === 'optional') current.optional = value === 'true';
      else if (key === 'groups') current.groups = parse_array_strings(value);
      else if (key === 'files') {
        const hashes = [...value.matchAll(/hash\s*=\s*("(?:\\.|[^"\\])*"|'[^']*')/g)].map(match => decode_toml_string(match[1]));
        current.files.push(...hashes);
        reading_files = value.includes('[') && !value.includes(']');
      }
    } else if (section === 'package.dependencies') {
      const dependency_name = key.replace(/^['"]|['"]$/g, '');
      current.dependencies.push({ name: dependency_name, requirement: parse_toml_dependency_version(value) });
    } else if (section === 'package.source') {
      if (key === 'type') current.source_type = decode_toml_string(value);
      else if (key === 'reference') current.source_reference = decode_toml_string(value);
    }
  }
  const warnings = [];
  const packages = [];
  const by_name = new Map();
  for (const block of blocks) {
    const name = clean_string(block.name, MAX_NAME, 'package name');
    const version = clean_string(block.version, MAX_VERSION, 'package version');
    if (!name || !version) { warnings.push({ code: 'ORIX_LOCKFILE_PACKAGE_IDENTITY' }); continue; }
    const normalized_groups = block.groups.map(value => value.toLowerCase());
    const dev = (normalized_groups.length > 0 && normalized_groups.every(value => value !== 'main')) || block.category === 'dev';
    const item = {
      name, version, ecosystem: 'python', location: name + '@' + version,
      dependency_type: dev ? 'development' : 'runtime', dev, optional: block.optional, peer: false,
      integrity: clean_string(block.files.find(value => /^sha256:[a-f0-9]{64}$/i.test(value))?.slice(7) ?? '', 128, 'file hash'),
      resolved: block.source_type && block.source_reference ? block.source_type + ':' + block.source_reference : null,
      license: null, dependencies: block.dependencies,
    };
    packages.push(item);
    const candidates = by_name.get(python_package_key(name)) ?? [];
    candidates.push(item);
    by_name.set(python_package_key(name), candidates);
  }
  const resolve = name => {
    const candidates = by_name.get(python_package_key(name)) ?? [];
    if (candidates.length === 1) return candidates[0];
    if (candidates.length > 1) warnings.push({ code: 'ORIX_LOCKFILE_AMBIGUOUS_DEPENDENCY', name });
    return null;
  };
  const edges = [];
  for (const item of packages) {
    for (const dependency of item.dependencies) {
      const target = resolve(dependency.name);
      if (target) edges.push({ from: item.location, to: target.location, name: dependency.name, requirement: dependency.requirement, resolved_version: target.version });
      else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_EDGE', from: item.location, dependency: dependency.name });
      if (edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'Poetry lockfile dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
    }
  }
  const manifest = manifests.find(item => item.ecosystem === 'python' && item.path.endsWith('pyproject.toml'));
  const root_dependencies = (manifest?.dependencies ?? []).map(item => ({ name: item.name, requirement: item.version, dependency_type: item.dependency_type === 'dev' ? 'development' : 'runtime' }));
  const root_edges = [];
  for (const dependency of root_dependencies) {
    const target = resolve(dependency.name);
    if (target) root_edges.push({ name: dependency.name, requirement: dependency.requirement, dependency_type: dependency.dependency_type, to: target.location, resolved_version: target.version });
    else warnings.push({ code: 'ORIX_LOCKFILE_UNRESOLVED_ROOT_EDGE', dependency: dependency.name });
  }
  if (edges.length + root_edges.length > limits.max_edges) fail('ORIX_LOCKFILE_EDGE_LIMIT', 'Poetry lockfile total dependency edge count exceeds configured limit', { file, maximum: limits.max_edges });
  return { path: file, ecosystem: 'python', format: 'poetry-lock', lockfile_version: metadata_version, packages, edges, root_dependencies, root_edges, warnings, complete: warnings.length === 0 };
}

function parse_pipfile_lock(file, text, limits, manifests) {
  let document;
  try { document = JSON.parse(text); }
  catch (error) { fail('ORIX_LOCKFILE_INVALID_JSON', 'Pipfile.lock is not valid JSON', { file, reason: error.message.slice(0, 160) }); }
  if (!document || typeof document !== 'object' || Array.isArray(document)) fail('ORIX_LOCKFILE_DOCUMENT', 'Pipfile.lock root must be an object', { file });
  const packages = [];
  const by_name = new Map();
  for (const [section, dependency_type] of [['default', 'runtime'], ['develop', 'development']]) {
    const entries = document[section] && typeof document[section] === 'object' && !Array.isArray(document[section]) ? Object.entries(document[section]) : [];
    for (const [name, metadata] of entries) {
      if (packages.length >= limits.max_packages) fail('ORIX_LOCKFILE_PACKAGE_LIMIT', 'Pipfile.lock package count exceeds configured limit', { file, maximum: limits.max_packages });
      const raw_version = clean_string(metadata?.version, MAX_VERSION, 'package version');
      if (!raw_version) continue;
      const version = raw_version.replace(/^(?:===|==|=)/, '');
      const hashes = Array.isArray(metadata.hashes) ? metadata.hashes.filter(value => typeof value === 'string') : [];
      const integrity = hashes.map(value => /^sha256:([a-f0-9]{64})$/i.exec(value)?.[1]).find(Boolean) ?? null;
      const item = {
        name, version, ecosystem: 'python', location: name + '@' + version,
        dependency_type, dev: dependency_type === 'development', optional: false, peer: false,
        integrity, resolved: null, license: null, dependencies: [],
      };
      packages.push(item);
      const candidates = by_name.get(python_package_key(name)) ?? [];
      candidates.push(item);
      by_name.set(python_package_key(name), candidates);
    }
  }
  const manifest = manifests.find(item => item.ecosystem === 'python' && item.path.endsWith('Pipfile'));
  const root_dependencies = (manifest?.dependencies ?? []).map(item => ({ name: item.name, requirement: item.version, dependency_type: item.dependency_type === 'dev' ? 'development' : 'runtime' }));
  const root_edges = [];
  for (const dependency of root_dependencies) {
    const candidates = by_name.get(python_package_key(dependency.name)) ?? [];
    if (candidates.length === 1) root_edges.push({ name: dependency.name, requirement: dependency.requirement, dependency_type: dependency.dependency_type, to: candidates[0].location, resolved_version: candidates[0].version });
  }
  const warnings = [{ code: 'ORIX_LOCKFILE_DEPENDENCY_EDGES_UNAVAILABLE', detail: 'Pipfile.lock records resolved package versions and hashes but not package-to-package dependency edges.' }];
  if (packages.length === 0) warnings.push({ code: 'ORIX_LOCKFILE_NO_PACKAGE_TABLE' });
  return { path: file, ecosystem: 'python', format: 'pipfile-lock', lockfile_version: document._meta?.pipfile_spec ?? null, packages, edges: [], root_dependencies, root_edges, warnings, complete: false };
}

export function parse_lockfile(file, text, options = {}, manifests = []) {
  if (typeof file !== 'string' || typeof text !== 'string') throw new TypeError('parse_lockfile requires a file path and text');
  const limits = validate_limits(options);
  const base = file.split('/').at(-1);
  if (base === 'package-lock.json') return parse_npm_package_lock(file, text, limits);
  if (base === 'yarn.lock') return parse_yarn_lock(file, text, limits);
  if (base === 'Cargo.lock') return parse_cargo_lock(file, text, limits);
  if (base === 'pnpm-lock.yaml') return parse_pnpm_lock(file, text, limits);
  if (base === 'composer.lock') return parse_composer_lock(file, text, limits, manifests);
  if (base === 'poetry.lock') return parse_poetry_lock(file, text, limits, manifests);
  if (base === 'Pipfile.lock') return parse_pipfile_lock(file, text, limits, manifests);
  if (base === 'go.sum') return parse_go_sum(file, text, limits, manifests);
  return null;
}
