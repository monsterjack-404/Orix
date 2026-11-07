import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import {
  parse_android_proto_xml,
} from '../src/android/proto-xml.mjs';
import { analyze_android_package, render_android_package_markdown } from '../src/android/package.mjs';
import * as public_api from '../src/index.mjs';
import { parse_android_proto_xml as package_subpath_parser } from '@orix/cli/android/proto-xml';

const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

function varint(value) {
  let current = BigInt(value);
  const bytes = [];
  do {
    let byte = Number(current & 0x7fn);
    current >>= 7n;
    if (current !== 0n) byte |= 0x80;
    bytes.push(byte);
  } while (current !== 0n);
  return Buffer.from(bytes);
}

function field_bytes(field, contents) {
  return Buffer.concat([varint(field * 8 + 2), varint(contents.length), contents]);
}

function field_string(field, value) {
  return field_bytes(field, Buffer.from(value, 'utf8'));
}

function xml_attribute(name, value, namespace_uri = '') {
  return Buffer.concat([
    namespace_uri ? field_string(1, namespace_uri) : Buffer.alloc(0),
    field_string(2, name),
    field_string(3, value),
  ]);
}

function xml_namespace(prefix, uri) {
  return Buffer.concat([field_string(1, prefix), field_string(2, uri)]);
}

function xml_element(name, options = {}) {
  const fields = [];
  for (const item of options.namespaces ?? []) fields.push(field_bytes(1, xml_namespace(item.prefix, item.uri)));
  if (options.namespace_uri) fields.push(field_string(2, options.namespace_uri));
  fields.push(field_string(3, name));
  for (const item of options.attributes ?? []) {
    fields.push(field_bytes(4, xml_attribute(item.name, item.value, item.namespace_uri ?? '')));
  }
  for (const child of options.children ?? []) fields.push(field_bytes(5, xml_node(child)));
  return Buffer.concat(fields);
}

function xml_node(element) {
  return field_bytes(1, element);
}

function proto_manifest() {
  const sdk = xml_element('uses-sdk', {
    attributes: [
      { name: 'minSdkVersion', value: '23', namespace_uri: ANDROID_NS },
      { name: 'targetSdkVersion', value: '35', namespace_uri: ANDROID_NS },
    ],
  });
  const permission = xml_element('uses-permission', {
    attributes: [
      { name: 'name', value: 'android.permission.INTERNET', namespace_uri: ANDROID_NS },
      { name: 'maxSdkVersion', value: '34', namespace_uri: ANDROID_NS },
    ],
  });
  const activity = xml_element('activity', {
    attributes: [
      { name: 'name', value: 'com.example.MainActivity', namespace_uri: ANDROID_NS },
      { name: 'exported', value: 'false', namespace_uri: ANDROID_NS },
      { name: 'permission', value: 'com.example.ACCESS', namespace_uri: ANDROID_NS },
    ],
    children: [xml_element('intent-filter', {
      children: [xml_element('action', {
        attributes: [{ name: 'name', value: 'android.intent.action.MAIN', namespace_uri: ANDROID_NS }],
      })],
    })],
  });
  const application = xml_element('application', {
    attributes: [
      { name: 'debuggable', value: 'true', namespace_uri: ANDROID_NS },
      { name: 'allowBackup', value: 'false', namespace_uri: ANDROID_NS },
      { name: 'label', value: '@string/app_name', namespace_uri: ANDROID_NS },
    ],
    children: [activity],
  });
  const root = xml_element('manifest', {
    namespaces: [{ prefix: 'android', uri: ANDROID_NS }],
    attributes: [
      { name: 'package', value: 'com.example.orix' },
      { name: 'versionCode', value: '42', namespace_uri: ANDROID_NS },
      { name: 'versionName', value: '4.2.0', namespace_uri: ANDROID_NS },
    ],
    children: [sdk, permission, application],
  });
  return xml_node(root);
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function create_zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const contents = Buffer.isBuffer(entry.contents) ? entry.contents : Buffer.from(entry.contents ?? '');
    const method = entry.method ?? 0;
    const compressed = method === 8 ? deflateRawSync(contents) : contents;
    if (method !== 0 && method !== 8) throw new TypeError('Unsupported test ZIP compression method');
    const checksum = crc32(contents);
    const local = Buffer.alloc(30 + name.length + compressed.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(contents.length, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);
    compressed.copy(local, 30 + name.length);
    locals.push(local);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(contents.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);
    centrals.push(central);
    offset += local.length;
  }
  const local_data = Buffer.concat(locals);
  const central_data = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central_data.length, 12);
  eocd.writeUInt32LE(local_data.length, 16);
  return Buffer.concat([local_data, central_data, eocd]);
}

test('AAPT2 protobuf XML decoder extracts bounded AAB manifest metadata', () => {
  const parsed = parse_android_proto_xml(proto_manifest());
  assert.equal(parsed.decoded, true);
  assert.equal(parsed.package_name, 'com.example.orix');
  assert.equal(parsed.version_code, 42);
  assert.equal(parsed.version_name, '4.2.0');
  assert.deepEqual(parsed.sdk, { min_version: 23, target_version: 35, max_version: null });
  assert.deepEqual(parsed.permissions, [{
    name: 'android.permission.INTERNET',
    maxSdkVersion: 34,
  }]);
  assert.equal(parsed.application.debuggable, true);
  assert.equal(parsed.application.allowBackup, false);
  assert.equal(parsed.application.label, '@string/app_name');
  assert.deepEqual(parsed.components, [{
    type: 'activity',
    name: 'com.example.MainActivity',
    exported: false,
    permission: 'com.example.ACCESS',
    process: null,
    authorities: null,
    targetActivity: null,
  }]);
  assert.equal(parsed.counts.elements, 7);
  assert.ok(parsed.counts.attributes >= 10);
});

test('AAB package report decodes stored protobuf module manifests', () => {
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: proto_manifest() },
  ]));
  assert.equal(report.format, 'AAB');
  assert.equal(report.manifests[0].status, 'decoded-proto-xml');
  assert.equal(report.manifests[0].proto_xml, true);
  assert.equal(report.manifests[0].binary_xml, false);
  assert.equal(report.manifests[0].package_name, 'com.example.orix');
  assert.equal(report.manifests[0].components[0].exported, false);
  assert.deepEqual(report.manifests[0].sdk, { min_version: 23, target_version: 35, max_version: null });
  const markdown = render_android_package_markdown(report);
  assert.match(markdown, /SDK: min=23, target=35, max=unspecified/);
  assert.ok(!report.limitations.some(item => item.includes('AAB protobuf manifests') && item.includes('not decoded')));
});

test('AAB package report labels malformed protobuf module manifests without binary-XML fallback', () => {
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: Buffer.from([0x0a, 0xff]) },
  ]));
  assert.equal(report.manifests[0].status, 'malformed-proto-xml');
  assert.equal(report.manifests[0].binary_xml, false);
  assert.equal(report.manifests[0].proto_xml, true);
  assert.equal(report.manifests[0].decoded, false);
  assert.equal(report.manifests[0].error.code, 'ORIX_PROTO_XML_LENGTH_RANGE');
});

test('protobuf XML decoder rejects malformed varints, wire types and invalid UTF-8', () => {
  assert.throws(() => parse_android_proto_xml(Buffer.from([0x0a, 0x80])), error =>
    error.code === 'ORIX_PROTO_XML_VARINT_TRUNCATED');
  assert.throws(() => parse_android_proto_xml(Buffer.from([0x0b])), error =>
    error.code === 'ORIX_PROTO_XML_WIRE_TYPE');
  assert.throws(() => parse_android_proto_xml(Buffer.from([0x0a, 0x03, 0x1a, 0x01, 0xff])), error =>
    error.code === 'ORIX_PROTO_XML_UTF8');
});

test('protobuf XML decoder rejects empty, conflicting and wrong-wire XmlNode fields', () => {
  assert.throws(() => parse_android_proto_xml(Buffer.alloc(0)), error =>
    error.code === 'ORIX_PROTO_XML_EMPTY');
  const conflict = Buffer.concat([field_bytes(1, xml_element('manifest')), field_string(2, 'text')]);
  assert.throws(() => parse_android_proto_xml(conflict), error =>
    error.code === 'ORIX_PROTO_XML_ONEOF');
  assert.throws(() => parse_android_proto_xml(Buffer.from([0x08, 0x01])), error =>
    error.code === 'ORIX_PROTO_XML_WIRE_MISMATCH');
});

test('protobuf XML decoder applies field, node, depth, attribute and byte ceilings', () => {
  const input = proto_manifest();
  assert.throws(() => parse_android_proto_xml(input, { max_fields: 1 }), error =>
    error.code === 'ORIX_PROTO_XML_FIELD_LIMIT');
  assert.throws(() => parse_android_proto_xml(input, { max_nodes: 1 }), error =>
    error.code === 'ORIX_PROTO_XML_NODE_LIMIT');
  assert.throws(() => parse_android_proto_xml(input, { max_attributes: 1 }), error =>
    error.code === 'ORIX_PROTO_XML_ATTRIBUTE_LIMIT');
  assert.throws(() => parse_android_proto_xml(input, { max_file_bytes: 8 }), error =>
    error.code === 'ORIX_PROTO_XML_FILE_LIMIT');
  assert.throws(() => parse_android_proto_xml(input, { max_depth: 1 }), error =>
    error.code === 'ORIX_PROTO_XML_DEPTH_LIMIT');
});

test('protobuf XML decoder skips well-formed unknown fields and refuses invalid option bounds', () => {
  const input = Buffer.concat([proto_manifest(), varint(15 * 8), varint(123)]);
  const parsed = parse_android_proto_xml(input);
  assert.equal(parsed.package_name, 'com.example.orix');
  assert.throws(() => parse_android_proto_xml(proto_manifest(), { max_depth: 0 }), TypeError);
});

test('AAB protobuf XML decoder is exposed through the root API and package subpath', () => {
  assert.equal(public_api.parse_android_proto_xml, parse_android_proto_xml);
  assert.equal(package_subpath_parser, parse_android_proto_xml);
});

test('protobuf XML decoder rejects duplicate namespace prefixes and duplicate expanded attributes', () => {
  const duplicate_namespace = xml_element('manifest', {
    namespaces: [
      { prefix: 'android', uri: ANDROID_NS },
      { prefix: 'android', uri: ANDROID_NS },
    ],
  });
  assert.throws(() => parse_android_proto_xml(xml_node(duplicate_namespace)), error =>
    error.code === 'ORIX_PROTO_XML_DUPLICATE_NAMESPACE');

  const duplicate_attribute = xml_element('manifest', {
    attributes: [
      { name: 'package', value: 'one.example' },
      { name: 'package', value: 'two.example' },
    ],
  });
  assert.throws(() => parse_android_proto_xml(xml_node(duplicate_attribute)), error =>
    error.code === 'ORIX_PROTO_XML_DUPLICATE_ATTRIBUTE');
});

test('protobuf XML decoder enforces per-string, aggregate-string, namespace and element budgets', () => {
  const input = proto_manifest();
  assert.throws(() => parse_android_proto_xml(input, { max_string_bytes: 4 }), error =>
    error.code === 'ORIX_PROTO_XML_STRING_LIMIT');
  assert.throws(() => parse_android_proto_xml(input, { max_total_string_bytes: 8 }), error =>
    error.code === 'ORIX_PROTO_XML_STRING_LIMIT');
  assert.throws(() => parse_android_proto_xml(input, { max_elements: 1 }), error =>
    error.code === 'ORIX_PROTO_XML_ELEMENT_LIMIT');

  const multiple_namespaces = xml_node(xml_element('manifest', {
    namespaces: [
      { prefix: 'android', uri: ANDROID_NS },
      { prefix: 'tools', uri: 'http://schemas.android.com/tools' },
    ],
  }));
  assert.throws(() => parse_android_proto_xml(multiple_namespaces, { max_namespaces: 1 }), error =>
    error.code === 'ORIX_PROTO_XML_NAMESPACE_LIMIT');
});

test('protobuf XML decoder validates wire types of skipped known metadata fields', () => {
  // XmlNode.source is a length-delimited SourcePosition message (field 3).
  const invalid_source_wire = Buffer.concat([proto_manifest(), Buffer.from([0x19, 0, 0, 0, 0, 0, 0, 0, 0])]);
  assert.throws(() => parse_android_proto_xml(invalid_source_wire), error =>
    error.code === 'ORIX_PROTO_XML_WIRE_MISMATCH');

  // XmlAttribute.compiled_item is a length-delimited Item message (field 6).
  const malformed_attribute = Buffer.concat([
    field_string(2, 'package'),
    field_string(3, 'com.example.orix'),
    varint(6 * 8),
    varint(1),
  ]);
  const malformed_element = Buffer.concat([
    field_string(3, 'manifest'),
    field_bytes(4, malformed_attribute),
  ]);
  assert.throws(() => parse_android_proto_xml(xml_node(malformed_element)), error =>
    error.code === 'ORIX_PROTO_XML_WIRE_MISMATCH');
});

test('protobuf XML decoder reports permission and component output truncation explicitly', () => {
  const permissions = [
    'android.permission.INTERNET',
    'android.permission.CAMERA',
  ].map(name => xml_element('uses-permission', {
    attributes: [{ name: 'name', value: name, namespace_uri: ANDROID_NS }],
  }));
  const components = [
    'com.example.First',
    'com.example.Second',
  ].map(name => xml_element('activity', {
    attributes: [{ name: 'name', value: name, namespace_uri: ANDROID_NS }],
  }));
  const manifest = xml_node(xml_element('manifest', {
    children: [
      ...permissions,
      xml_element('application', { children: components }),
    ],
  }));
  const parsed = parse_android_proto_xml(manifest, { max_output_items: 1 });
  assert.deepEqual(parsed.permissions.map(item => item.name), ['android.permission.INTERNET']);
  assert.deepEqual(parsed.components.map(item => item.name), ['com.example.First']);
  assert.equal(parsed.output_truncated, true);
});

test('AAB raw-DEFLATE module manifests decode after bounded inflate and CRC validation', () => {
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: proto_manifest(), method: 8 },
  ]));
  assert.equal(report.format, 'AAB');
  assert.equal(report.manifests[0].status, 'decoded-proto-xml');
  assert.equal(report.manifests[0].package_name, 'com.example.orix');
  assert.deepEqual(report.manifests[0].sdk, { min_version: 23, target_version: 35, max_version: null });
});
