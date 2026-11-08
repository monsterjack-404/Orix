import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_android_resource_table } from '../src/android/resources-table.mjs';

function varint(input) {
  let value = BigInt(input);
  if (value < 0n) value = BigInt.asUintN(64, value);
  const bytes = [];
  do {
    let byte = Number(value & 0x7fn);
    value >>= 7n;
    if (value !== 0n) byte |= 0x80;
    bytes.push(byte);
  } while (value !== 0n);
  return Buffer.from(bytes);
}

function field_varint(field, value) {
  return Buffer.concat([varint(BigInt(field * 8)), varint(value)]);
}

function field_bytes(field, value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  return Buffer.concat([varint(BigInt(field * 8 + 2)), varint(bytes.length), bytes]);
}

function encode_pool_length_u8(value) {
  if (value <= 0x7f) return Buffer.from([value]);
  if (value > 0x7fff) throw new RangeError('UTF-8 pool fixture length is too large');
  return Buffer.from([0x80 | (value >> 8), value & 0xff]);
}

function android_string_pool(strings, encoding = 'utf-8') {
  const utf8 = encoding === 'utf-8';
  const records = [];
  const offsets = [];
  let cursor = 0;
  for (const value of strings) {
    const encoded = Buffer.from(value, utf8 ? 'utf8' : 'utf16le');
    const length = utf8
      ? Buffer.concat([encode_pool_length_u8(value.length), encode_pool_length_u8(encoded.length)])
      : Buffer.from([value.length & 0xff, (value.length >> 8) & 0x7f]);
    const record = Buffer.concat([length, encoded, utf8 ? Buffer.from([0]) : Buffer.from([0, 0])]);
    offsets.push(cursor);
    records.push(record);
    cursor += record.length;
  }
  const table_end = 28 + strings.length * 4;
  const string_data = Buffer.concat(records);
  const header = Buffer.alloc(table_end);
  header.writeUInt16LE(0x0001, 0);
  header.writeUInt16LE(28, 2);
  header.writeUInt32LE(table_end + string_data.length, 4);
  header.writeUInt32LE(strings.length, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(utf8 ? 0x100 : 0, 16);
  header.writeUInt32LE(table_end, 20);
  header.writeUInt32LE(0, 24);
  offsets.forEach((offset, index) => header.writeUInt32LE(offset, 28 + index * 4));
  return Buffer.concat([header, string_data]);
}

function make_reference_value() {
  const dynamic_boolean = field_varint(1, 1);
  const reference = Buffer.concat([
    field_varint(1, 1),
    field_varint(2, 0x7f010002),
    field_bytes(3, '@com.example.app:string/app_name'),
    field_varint(4, 1),
    field_bytes(5, dynamic_boolean),
    field_varint(6, 0x20),
  ]);
  const item = field_bytes(1, reference);
  return field_bytes(2, field_bytes(4, item));
}

function make_resource_table({ unknown_top_level = false, second_config_value = false } = {}) {
  const source_pool_data = android_string_pool(['res/values/strings.xml', 'res/values/public.xml', 'res/values/attrs.xml']);
  const source_pool = field_bytes(1, source_pool_data);
  const configuration = Buffer.concat([
    field_bytes(3, 'en-US'),
    field_varint(18, 420),
    field_varint(24, 35),
    field_bytes(25, 'phone'),
    field_varint(26, 2),
  ]);
  const string_value = field_bytes(1, 'Example application');
  const string_item = field_bytes(2, string_value);
  const value = Buffer.concat([
    field_varint(3, 1),
    field_bytes(4, string_item),
  ]);
  const config_value = Buffer.concat([
    field_bytes(1, configuration),
    field_bytes(2, value),
  ]);
  const alternate_config = Buffer.concat([
    field_bytes(1, field_varint(24, 35)),
    make_reference_value(),
  ]);
  const entry = Buffer.concat([
    field_bytes(1, field_varint(1, 2)),
    field_bytes(2, 'app_name'),
    field_bytes(3, field_varint(1, 2)),
    field_bytes(6, config_value),
    ...(second_config_value ? [field_bytes(6, alternate_config)] : []),
  ]);
  const type = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(2, 'string'),
    field_bytes(3, entry),
  ]);
  const pkg = Buffer.concat([
    field_bytes(1, field_varint(1, 0x7f)),
    field_bytes(2, 'com.example.app'),
    field_bytes(3, type),
  ]);
  const overlayable = Buffer.concat([
    field_bytes(1, 'ThemeResources'),
    field_bytes(3, 'overlay://theme'),
  ]);
  const tool = Buffer.concat([
    field_bytes(1, 'aapt2'),
    field_bytes(2, '8.7-123456'),
  ]);
  const dynamic_ref = Buffer.concat([
    field_bytes(1, field_varint(1, 0x01)),
    field_bytes(2, 'android'),
  ]);
  return Buffer.concat([
    field_bytes(1, source_pool),
    field_bytes(2, pkg),
    field_bytes(3, overlayable),
    field_bytes(4, tool),
    field_bytes(5, dynamic_ref),
    ...(unknown_top_level ? [field_bytes(15, Buffer.from([0xde, 0xad]))] : []),
  ]);
}

test('ResourceTable decodes package/type/entry IDs, names, visibility, config qualifiers and values', () => {
  const report = parse_android_resource_table(make_resource_table());
  assert.equal(report.schema_version, 'orix.android-resource-table.v1');
  assert.equal(report.source_pool_present, true);
  assert.equal(report.source_pool_data_bytes > 28, true);
  assert.equal(report.source_pool_string_count, 3);
  assert.equal(report.source_pool_encoding, 'utf-8');
  assert.equal(report.package_count, 1);
  assert.equal(report.packages_reported, 1);
  const pkg = report.packages[0];
  assert.equal(pkg.id, 0x7f);
  assert.equal(pkg.name, 'com.example.app');
  assert.equal(pkg.type_count, 1);
  const type = pkg.types[0];
  assert.equal(type.id, 1);
  assert.equal(type.name, 'string');
  const entry = type.entries[0];
  assert.equal(entry.id, 2);
  assert.equal(entry.name, 'app_name');
  assert.equal(entry.visibility, 'public');
  assert.equal(entry.resource_id, '0x7f010002');
  assert.equal(entry.config_value_count, 1);
  assert.equal(entry.config_values[0].configuration.locale, 'en-US');
  assert.equal(entry.config_values[0].configuration.density, 420);
  assert.equal(entry.config_values[0].configuration.sdk_version, 35);
  assert.equal(entry.config_values[0].configuration.product, 'phone');
  assert.equal(entry.config_values[0].configuration.grammatical_gender, 2);
  assert.equal(entry.config_values[0].value.kind, 'item');
  assert.equal(entry.config_values[0].value.detail_kind, 'string');
  assert.deepEqual(report.summary.item_kinds, { string: 1 });
  assert.equal(report.summary.entry_count, 1);
  assert.equal(report.coverage.output_truncated, false);
});

test('ResourceTable inventories references, dynamic flags, overlayables and tool fingerprints', () => {
  const report = parse_android_resource_table(make_resource_table({ second_config_value: true }));
  const entry = report.packages[0].types[0].entries[0];
  const reference = entry.config_values[1].value.reference;
  assert.equal(reference.type, 1);
  assert.equal(reference.id, 0x7f010002);
  assert.equal(reference.name, '@com.example.app:string/app_name');
  assert.equal(reference.private, true);
  assert.equal(reference.dynamic, true);
  assert.equal(report.summary.reference_count, 1);
  assert.equal(report.overlayable_count, 1);
  assert.deepEqual(report.overlayables[0], { name: 'ThemeResources', actor: 'overlay://theme' });
  assert.deepEqual(report.tool_fingerprints[0], { tool: 'aapt2', version: '8.7-123456' });
  assert.deepEqual(report.dynamic_ref_tables[0], { package_id: 1, package_name: 'android' });
});

test('ResourceTable counts unknown wire-valid fields without interpreting them', () => {
  const report = parse_android_resource_table(make_resource_table({ unknown_top_level: true }));
  assert.equal(report.coverage.unknown_fields, 1);
});

test('ResourceTable applies output caps without losing structural aggregate counts', () => {
  const report = parse_android_resource_table(make_resource_table({ second_config_value: true }), {
    max_output_items: 0,
  });
  assert.equal(report.packages_reported, 0);
  assert.equal(report.packages_omitted, 1);
  assert.equal(report.summary.package_count, 1);
  assert.equal(report.summary.type_count, 1);
  assert.equal(report.summary.entry_count, 1);
  assert.equal(report.summary.config_value_count, 2);
  assert.equal(report.coverage.output_truncated, true);
  assert.ok(report.coverage.items_omitted > 0);
});

test('ResourceTable rejects malformed protobuf framing, wire types, duplicate singulars and invalid oneofs', () => {
  assert.throws(
    () => parse_android_resource_table(Buffer.from([0x12, 0x80])),
    error => error.code === 'ORIX_RESOURCE_TABLE_VARINT_TRUNCATED',
  );
  assert.throws(
    () => parse_android_resource_table(Buffer.from([0x1b])),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_TYPE',
  );
  assert.throws(
    () => parse_android_resource_table(Buffer.concat([
      field_bytes(2, Buffer.concat([
        field_bytes(1, field_varint(1, 0x7f)),
        field_bytes(1, field_varint(1, 0x7e)),
      ])),
    ])),
    error => error.code === 'ORIX_RESOURCE_TABLE_DUPLICATE_FIELD',
  );
  const invalid_item = Buffer.concat([
    field_bytes(2, field_bytes(1, Buffer.from([0x0a, 0x00]))),
    field_bytes(7, Buffer.from([0x08, 0x01])),
  ]);
  const invalid_value = field_bytes(4, invalid_item);
  const invalid_config = field_bytes(2, invalid_value);
  const invalid_entry = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(6, invalid_config),
  ]);
  const invalid_type = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(3, invalid_entry),
  ]);
  const invalid_package = Buffer.concat([
    field_bytes(1, field_varint(1, 0x7f)),
    field_bytes(3, invalid_type),
  ]);
  assert.throws(
    () => parse_android_resource_table(field_bytes(2, invalid_package)),
    error => error.code === 'ORIX_RESOURCE_TABLE_ONEOF',
  );
});

test('ResourceTable enforces file, field, item, depth and string budgets', () => {
  const table = make_resource_table({ second_config_value: true });
  assert.throws(
    () => parse_android_resource_table(table, { max_file_bytes: table.length - 1 }),
    error => error.code === 'ORIX_RESOURCE_TABLE_FILE_LIMIT',
  );
  assert.throws(
    () => parse_android_resource_table(table, { max_fields: 2 }),
    error => error.code === 'ORIX_RESOURCE_TABLE_FIELD_LIMIT',
  );
  assert.throws(
    () => parse_android_resource_table(table, { max_items: 1 }),
    error => error.code === 'ORIX_RESOURCE_TABLE_STRING_POOL_COUNT',
  );
  assert.throws(
    () => parse_android_resource_table(table, { max_depth: 1 }),
    error => error.code === 'ORIX_RESOURCE_TABLE_DEPTH_LIMIT',
  );
  assert.throws(
    () => parse_android_resource_table(table, { max_string_bytes: 4 }),
    error => error.code === 'ORIX_RESOURCE_TABLE_STRING_LIMIT',
  );
  assert.throws(() => parse_android_resource_table(table, { max_output_items: -1 }), TypeError);
});

test('ResourceTable rejects unknown Reference.type enum values', () => {
  const invalid_reference = field_varint(1, 2);
  const item = field_bytes(1, invalid_reference);
  const value = field_bytes(4, item);
  const config_value = field_bytes(2, value);
  const entry = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(6, config_value),
  ]);
  const type = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(3, entry),
  ]);
  const pkg = Buffer.concat([
    field_bytes(1, field_varint(1, 0x7f)),
    field_bytes(3, type),
  ]);
  assert.throws(
    () => parse_android_resource_table(field_bytes(2, pkg)),
    error => error.code === 'ORIX_RESOURCE_TABLE_REFERENCE_TYPE',
  );
});

test('ResourceTable validates nested string UTF-8 and Primitive oneof structure', () => {
  const invalid_string_item = field_bytes(2, field_bytes(1, Buffer.from([0xff])));
  const invalid_string_value = field_bytes(4, invalid_string_item);
  const invalid_string_config = field_bytes(2, invalid_string_value);
  const invalid_string_entry = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(6, invalid_string_config),
  ]);
  const invalid_string_type = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(3, invalid_string_entry),
  ]);
  const invalid_string_package = Buffer.concat([
    field_bytes(1, field_varint(1, 0x7f)),
    field_bytes(3, invalid_string_type),
  ]);
  assert.throws(
    () => parse_android_resource_table(field_bytes(2, invalid_string_package)),
    error => error.code === 'ORIX_RESOURCE_TABLE_UTF8',
  );

  const invalid_primitive = Buffer.concat([
    field_varint(6, 1),
    field_varint(7, 1),
  ]);
  const invalid_primitive_item = field_bytes(7, invalid_primitive);
  const invalid_primitive_value = field_bytes(4, invalid_primitive_item);
  const invalid_primitive_config = field_bytes(2, invalid_primitive_value);
  const invalid_primitive_entry = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(6, invalid_primitive_config),
  ]);
  const invalid_primitive_type = Buffer.concat([
    field_bytes(1, field_varint(1, 1)),
    field_bytes(3, invalid_primitive_entry),
  ]);
  const invalid_primitive_package = Buffer.concat([
    field_bytes(1, field_varint(1, 0x7f)),
    field_bytes(3, invalid_primitive_type),
  ]);
  assert.throws(
    () => parse_android_resource_table(field_bytes(2, invalid_primitive_package)),
    error => error.code === 'ORIX_RESOURCE_TABLE_ONEOF',
  );
});
