// JavaScript, src/reports/cyclonedx.mjs, Node.js 20+, CycloneDX 1.5 project SBOM export.

import { createHash } from 'node:crypto';

const TYPES = Object.freeze({
  npm: 'npm',
  pnpm: 'npm',
  pip: 'pypi',
  python: 'pypi',
  cargo: 'cargo',
  go: 'golang',
  'go-modules': 'golang',
  composer: 'composer',
  maven: 'maven',
  nuget: 'nuget',
  rubygems: 'gem',
});

function encode_segment(value) {
  return encodeURIComponent(String(value)).replace(/[!'()*]/g, character => '%' + character.charCodeAt(0).toString(16).toUpperCase());
}

function is_pinned_version(value) {
  return typeof value === 'string' && /^v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?$/.test(value);
}

function package_url(dependency) {
  const type = TYPES[dependency.ecosystem];
  if (!type) return null;
  let name = String(dependency.name ?? '').trim();
  if (!name || name.length > 512) return null;
  if (type === 'pypi') name = name.toLowerCase().replaceAll('_', '-');
  let path;
  if (type === 'maven') {
    const separator = name.indexOf(':');
    if (separator < 1 || separator === name.length - 1) return null;
    path = name.slice(0, separator).split('.').map(encode_segment).join('/') + '/' + encode_segment(name.slice(separator + 1));
  } else {
    path = name.split('/').map(encode_segment).join('/');
  }
  const version = is_pinned_version(dependency.version) ? '@' + encode_segment(dependency.version) : '';
  return 'pkg:' + type + '/' + path + version;
}

function uuid_from_hash(value) {
  const bytes = createHash('sha256').update(value).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
}

export function render_cyclonedx(report, options = {}) {
  if (report?.schema_version !== 'orix.project.v1' || !report.project || !Array.isArray(report.dependencies)) {
    throw new TypeError('CycloneDX export requires an ORIX project-intelligence report');
  }
  const lockfile_packages = (report.lockfiles ?? []).flatMap(lockfile => (lockfile.packages ?? []).map(item => ({ ...item, id: lockfile.path + '#' + item.location, manifest: lockfile.path, lockfile_path: lockfile.path, resolved_source: 'lockfile' })));
  const source_dependencies = report.resolved_dependencies?.length ? report.resolved_dependencies : lockfile_packages.length ? lockfile_packages : report.dependencies;
  const components = new Map();
  const package_refs = new Map();
  for (const dependency of source_dependencies) {
    const purl = package_url(dependency);
    if (!purl) continue;
    package_refs.set(dependency.id ?? (dependency.name + '@' + dependency.version), purl);
    const existing = components.get(purl);
    const property_set = new Map((existing?.properties ?? []).map(item => [item.name, item.value]));
    property_set.set('orix:ecosystem', dependency.ecosystem);
    if (dependency.version && dependency.version !== '*') property_set.set('orix:declared-version', dependency.version);
    property_set.set('orix:dependency-type:' + dependency.dependency_type, 'true');
    property_set.set('orix:manifest:' + dependency.manifest, 'true');
    if (dependency.lockfile_path) property_set.set('orix:lockfile', dependency.lockfile_path);
    if (dependency.integrity) property_set.set('orix:integrity', dependency.integrity);
    if (dependency.checksum_kind) property_set.set('orix:checksum-kind', dependency.checksum_kind);
    if (dependency.resolved) property_set.set('orix:resolved-url', dependency.resolved);
    if (dependency.license) property_set.set('orix:declared-license', dependency.license);
    components.set(purl, {
      type: 'library',
      'bom-ref': purl,
      name: dependency.name,
      ...(is_pinned_version(dependency.version) ? { version: dependency.version } : {}),
      purl,
      scope: existing?.scope === 'required' || !(dependency.dev || dependency.optional || ['dev', 'devDependencies', 'require-dev', 'dev-dependencies', 'build-dependencies'].includes(dependency.dependency_type)) ? 'required' : 'optional',
      properties: [...property_set].map(([name, value]) => ({ name, value })).sort((a, b) => a.name.localeCompare(b.name)),
    });
  }
  const manifest = report.manifests.find(item => item.name) ?? {};
  const root_name = manifest.name ?? report.project.name ?? 'unknown-project';
  const root_purl = 'pkg:generic/' + encode_segment(root_name) + (manifest.version ? '@' + encode_segment(manifest.version) : '');
  const ordered = [...components.values()].sort((a, b) => a.purl.localeCompare(b.purl));
  const identity = JSON.stringify({
    root: report.project.root,
    name: root_name,
    version: manifest.version ?? null,
    components: ordered.map(item => item.purl),
    files: (report.files ?? []).map(item => [item.path, item.sha256]).sort((a, b) => a[0].localeCompare(b[0])),
  });
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:' + uuid_from_hash(identity),
    version: 1,
    metadata: {
      timestamp: report.project.scanned_at,
      tools: [{ vendor: 'ORIX', name: 'ORIX', version: options.orix_version ?? '0.5.0' }],
      component: {
        type: 'application',
        'bom-ref': root_purl,
        name: root_name,
        ...(manifest.version ? { version: manifest.version } : {}),
        purl: root_purl,
        properties: [
          { name: 'orix:project-root', value: report.project.root },
          { name: 'orix:inventory-complete', value: String(report.coverage?.complete === true) },
        ],
      },
    },
    components: ordered,
    dependencies: (() => {
      const grouped = new Map();
      const add_edge = (from, to) => { if (!from || !to) return; const values = grouped.get(from) ?? new Set(); values.add(to); grouped.set(from, values); };
      const lockfiles = report.lockfiles ?? [];
      if (lockfiles.some(item => item.packages?.length > 0)) {
        for (const lockfile of lockfiles) {
          const locations = new Map();
          for (const dependency of lockfile.packages ?? []) {
            const purl = package_url(dependency);
            if (purl) locations.set(dependency.location, purl);
          }
          for (const edge of lockfile.edges ?? []) add_edge(locations.get(edge.from), locations.get(edge.to));
          for (const edge of lockfile.root_edges ?? []) add_edge(root_purl, locations.get(edge.to));
        }
        if (!(grouped.get(root_purl)?.size)) {
          const direct_names = new Set((report.dependencies ?? []).map(item => item.name));
          for (const dependency of lockfile_packages) if (direct_names.has(dependency.name)) add_edge(root_purl, package_url(dependency));
        }
      } else {
        const graph_edges = report.dependency_graph?.edges ?? [];
        if (report.resolved_dependencies?.length && graph_edges.length > 0) {
          for (const edge of graph_edges) {
            const from = edge.from === 'root' ? root_purl : package_refs.get(edge.from);
            const to = package_refs.get(edge.to);
            add_edge(from, to);
          }
        } else {
          for (const item of ordered) add_edge(root_purl, item['bom-ref']);
        }
      }
      if (!grouped.has(root_purl)) grouped.set(root_purl, new Set());
      return [...grouped].map(([ref, values]) => ({ ref, dependsOn: [...values].sort() })).sort((a, b) => a.ref.localeCompare(b.ref));
    })(),
    properties: [
      { name: 'orix:dependency-declarations', value: String(report.dependencies.length) },
      { name: 'orix:locked-packages', value: String(report.resolved_dependencies?.length ?? lockfile_packages.length) },
      { name: 'orix:components-emitted', value: String(ordered.length) },
      { name: 'orix:transitive-resolution-performed', value: String((report.resolved_dependencies?.length ?? lockfile_packages.length) > 0) },
    ],
  };
  return JSON.stringify(bom, null, options.compact ? 0 : 2) + '\n';
}
