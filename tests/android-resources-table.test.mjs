import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_android_resource_table } from '../src/android/resources-table.mjs';
import * as public_api from '../src/index.mjs';

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

function field_bytes(field, contents) {
  return Buffer.concat([varint(BigInt(field * 8 + 2)), varint(contents.length), contents]);
}

function field_string(field, value) {
  return field_bytes(field, Buffer.from(value, 'utf8'));
}

function id_message(id) {
  return field_varint(1, id);
}

function android_string_pool_with_style(value = 'bold') {
  const encoded = Buffer.from(value, 'utf8');
  const string = Buffer.concat([
    encode_pool_length_u8(value.length),
    encode_pool_length_u8(encoded.length),
    encoded,
    Buffer.from([0]),
  ]);
  const table_end = 36;
  const styles_start = table_end + string.length;
  const styles = Buffer.alloc(24);
  styles.writeUInt32LE(0, 0); // span name string index
  styles.writeUInt32LE(0, 4); // first character
  styles.writeUInt32LE(value.length - 1, 8); // last character
  styles.writeUInt32LE(0xffffffff, 12);
  styles.writeUInt32LE(0xffffffff, 16);
  styles.writeUInt32LE(0xffffffff, 20);
  const header = Buffer.alloc(table_end);
  header.writeUInt16LE(0x0001, 0);
  header.writeUInt16LE(28, 2);
  header.writeUInt32LE(table_end + string.length + styles.length, 4);
  header.writeUInt32LE(1, 8);
  header.writeUInt32LE(1, 12);
  header.writeUInt32LE(0x100, 16);
  header.writeUInt32LE(table_end, 20);
  header.writeUInt32LE(styles_start, 24);
  header.writeUInt32LE(0, 28); // string offset
  header.writeUInt32LE(0, 32); // style offset
  return Buffer.concat([header, string, styles]);
}

function encode_pool_length_u8(value) {
  if (value <= 0x7f) return Buffer.from([value]);
  if (value > 0x7fff) throw new RangeError('UTF-8 pool fixture length is too large');
  return Buffer.from([0x80 | (value >> 8), value & 0xff]);
}

function encode_pool_length_u16(value) {
  if (value <= 0x7fff) {
    const result = Buffer.alloc(2);
    result.writeUInt16LE(value, 0);
    return result;
  }
  if (value > 0x7fffffff) throw new RangeError('UTF-16 pool fixture length is too large');
  const result = Buffer.alloc(4);
  result.writeUInt16LE(0x8000 | Math.floor(value / 0x10000), 0);
  result.writeUInt16LE(value & 0xffff, 2);
  return result;
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
      : encode_pool_length_u16(value.length);
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

function resource_table_fixture({
  entry_metadata = Buffer.alloc(0),
  visibility_metadata = null,
  overlayable_source = null,
  value_contents = null,
  source_pool_first = true,
  include_source_pool = true,
  source_pool_strings = ['res/values/strings.xml', 'res/values/public.xml', 'res/values/attrs.xml'],
  source_pool_encoding = 'utf-8',
} = {}) {
  const source_pool_data = android_string_pool(source_pool_strings, source_pool_encoding);
  const source_pool = field_bytes(1, field_bytes(1, source_pool_data));
  const visibility = visibility_metadata ?? field_varint(1, 2);
  const configuration = Buffer.concat([
    field_string(3, 'en-US'),
    field_varint(18, 320),
    field_varint(24, 35),
  ]);
  const reference = Buffer.concat([
    field_varint(1, 0),
    field_varint(2, 0x7f010001),
    field_string(3, 'string/app_name'),
  ]);
  const item = field_bytes(1, reference);
  const value = value_contents ?? Buffer.concat([
    field_varint(3, 1),
    field_bytes(4, item),
  ]);
  const config_value = Buffer.concat([
    field_bytes(1, configuration),
    field_bytes(2, value),
  ]);
  const entry = Buffer.concat([
    field_bytes(1, id_message(1)),
    field_string(2, 'app_name'),
    field_bytes(3, visibility),
    field_bytes(6, config_value),
    entry_metadata,
  ]);
  const type = Buffer.concat([
    field_bytes(1, id_message(1)),
    field_string(2, 'string'),
    field_bytes(3, entry),
  ]);
  const pkg = Buffer.concat([
    field_bytes(1, id_message(0x7f)),
    field_string(2, 'com.example.app'),
    field_bytes(3, type),
  ]);
  const overlayable = Buffer.concat([
    field_string(1, 'SystemUi'),
    ...(overlayable_source ? [field_bytes(2, overlayable_source)] : []),
    field_string(3, 'overlay://actor'),
  ]);
  const fingerprint = Buffer.concat([
    field_string(1, 'aapt2'),
    field_string(2, '8.4.0'),
  ]);
  const dynamic_ref = Buffer.concat([
    field_bytes(1, id_message(0x7f)),
    field_string(2, 'com.example.app'),
  ]);
  const fields = [
    field_bytes(2, pkg),
    field_bytes(3, overlayable),
    field_bytes(4, fingerprint),
    field_bytes(5, dynamic_ref),
  ];
  if (include_source_pool && source_pool_first) fields.unshift(source_pool);
  else if (include_source_pool) fields.push(source_pool);
  return Buffer.concat(fields);
}

test('ResourceTable parser inventories packages, types, entries, IDs and selected configurations', () => {
  const parsed = parse_android_resource_table(resource_table_fixture());
  assert.equal(parsed.schema_version, 'orix.android-resource-table.v1');
  assert.equal(parsed.source_pool_present, true);
  assert.equal(parsed.source_pool_data_bytes > 28, true);
  assert.equal(parsed.source_pool_string_count, 3);
  assert.equal(parsed.source_pool_style_count, 0);
  assert.equal(parsed.source_pool_encoding, 'utf-8');
  assert.equal(parsed.package_count, 1);
  assert.equal(parsed.packages[0].id, 0x7f);
  assert.equal(parsed.packages[0].name, 'com.example.app');
  assert.equal(parsed.packages[0].type_count, 1);
  assert.equal(parsed.packages[0].types[0].id, 1);
  assert.equal(parsed.packages[0].types[0].name, 'string');
  assert.equal(parsed.packages[0].types[0].entry_count, 1);
  const entry = parsed.packages[0].types[0].entries[0];
  assert.equal(entry.id, 1);
  assert.equal(entry.name, 'app_name');
  assert.equal(entry.visibility, 'public');
  assert.equal(entry.resource_id, '0x7f010001');
  assert.equal(entry.config_value_count, 1);
  assert.deepEqual(entry.config_values[0].configuration, {
    locale: 'en-US',
    density: 320,
    sdk_version: 35,
  });
  assert.equal(entry.config_values[0].value.kind, 'item');
  assert.equal(entry.config_values[0].value.detail_kind, 'reference');
  assert.deepEqual(entry.config_values[0].value.reference, {
    type: 0,
    id: 0x7f010001,
    name: 'string/app_name',
    private: false,
    dynamic: false,
  });
  assert.equal(parsed.summary.type_count, 1);
  assert.equal(parsed.summary.entry_count, 1);
  assert.equal(parsed.summary.config_value_count, 1);
  assert.equal(parsed.summary.item_kinds.reference, 1);
  assert.equal(parsed.overlayables[0].name, 'SystemUi');
  assert.equal(parsed.overlayables[0].actor, 'overlay://actor');
  assert.deepEqual(parsed.tool_fingerprints[0], { tool: 'aapt2', version: '8.4.0' });
  assert.deepEqual(parsed.dynamic_ref_tables[0], { package_id: 0x7f, package_name: 'com.example.app' });
});

test('ResourceTable validates AOSP Source, Visibility, AllowNew, OverlayableItem and StagedId fields', () => {
  const source_position = Buffer.concat([
    field_varint(1, 12),
    field_varint(2, 3),
  ]);
  const source = Buffer.concat([
    field_varint(1, 2),
    field_bytes(2, source_position),
  ]);
  const visibility = Buffer.concat([
    field_varint(1, 2),
    field_bytes(2, source),
    field_string(3, 'declared public'),
    field_varint(4, 1),
  ]);
  const allow_new = Buffer.concat([
    field_bytes(1, source),
    field_string(2, 'compile-time overlay'),
  ]);
  const overlayable_item = Buffer.concat([
    field_bytes(1, source),
    field_string(2, 'overlay item'),
    field_varint(3, 8),
    field_bytes(3, Buffer.from([9, 5])),
    field_varint(4, 0),
  ]);
  const staged_id = Buffer.concat([
    field_bytes(1, source),
    field_varint(2, 0x7f010002),
  ]);
  const metadata = Buffer.concat([
    field_bytes(4, allow_new),
    field_bytes(5, overlayable_item),
    field_bytes(7, staged_id),
  ]);
  const parsed = parse_android_resource_table(resource_table_fixture({
    entry_metadata: metadata,
    visibility_metadata: visibility,
    overlayable_source: source,
  }));
  assert.equal(parsed.packages[0].types[0].entries[0].visibility, 'public');
  assert.equal(parsed.overlayables[0].name, 'SystemUi');

  const invalid_allow_new = field_bytes(4, field_varint(1, 1));
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ entry_metadata: invalid_allow_new })),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_MISMATCH',
    'AllowNew.source must be a Source message, not a varint',
  );

  const invalid_overlayable_item = field_bytes(5, Buffer.from([0x1d, 0, 0, 0, 0]));
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ entry_metadata: invalid_overlayable_item })),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_MISMATCH',
    'OverlayableItem.policy must be a varint enum',
  );

  const malformed_packed_policy = field_bytes(5, field_bytes(3, Buffer.from([0x80])));
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ entry_metadata: malformed_packed_policy })),
    error => error.code === 'ORIX_RESOURCE_TABLE_VARINT_TRUNCATED',
    'Packed OverlayableItem.policy values must be fully terminated inside their field',
  );

  const invalid_staged_id = field_bytes(7, field_bytes(2, field_string(1, 'wrong-wire')));
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ entry_metadata: invalid_staged_id })),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_MISMATCH',
    'StagedId.staged_id must be a uint32 varint',
  );

  const invalid_visibility = field_varint(2, 123);
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ visibility_metadata: invalid_visibility })),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_MISMATCH',
    'Visibility.source must be a Source message',
  );
});

test('ResourceTable validates Value.source with the AOSP Source field schema', () => {
  const validSource = Buffer.concat([
    field_varint(1, 0),
    field_bytes(2, Buffer.concat([field_varint(1, 10), field_varint(2, 2)])),
  ]);
  const validValue = Buffer.concat([
    field_bytes(1, validSource),
    field_bytes(4, field_bytes(1, Buffer.concat([
      field_varint(1, 0),
      field_varint(2, 0x7f010001),
    ]))),
  ]);
  const valid = parse_android_resource_table(resource_table_fixture({ value_contents: validValue }));
  assert.equal(valid.source_paths_resolved, 1);
  assert.equal(valid.source_paths[0].path, 'res/values/strings.xml');

  const invalidSource = field_bytes(1, Buffer.from([1]));
  const invalidValue = Buffer.concat([
    field_bytes(1, invalidSource),
    field_bytes(4, field_bytes(1, Buffer.concat([
      field_varint(1, 0),
      field_varint(2, 0x7f010001),
    ]))),
  ]);
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ value_contents: invalidValue })),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_MISMATCH',
    'Value.source.path_idx must be a uint32 varint and not a length-delimited field',
  );
});

test('ResourceTable validates known nested compound-value protobuf schemas without decoding values', () => {
  const source = field_varint(1, 2);
  const reference = Buffer.concat([
    field_varint(1, 0),
    field_varint(2, 0x7f010001),
  ]);
  const item = field_bytes(1, reference);

  const symbol = Buffer.concat([
    field_bytes(1, source),
    field_string(2, 'symbol'),
    field_bytes(3, reference),
    field_varint(4, 1),
    field_varint(5, 2),
  ]);
  const attribute = Buffer.concat([
    field_varint(1, 3),
    field_varint(2, -2),
    field_varint(3, 99),
    field_bytes(4, symbol),
  ]);
  const style_entry = Buffer.concat([
    field_bytes(1, source),
    field_string(2, 'style entry'),
    field_bytes(3, reference),
    field_bytes(4, item),
  ]);
  const style = Buffer.concat([
    field_bytes(1, reference),
    field_bytes(2, source),
    field_bytes(3, style_entry),
  ]);
  const styleable = field_bytes(1, Buffer.concat([
    field_bytes(1, source),
    field_string(2, 'styleable entry'),
    field_bytes(3, reference),
  ]));
  const array = field_bytes(1, Buffer.concat([
    field_bytes(1, source),
    field_string(2, 'array element'),
    field_bytes(3, item),
  ]));
  const plural = field_bytes(1, Buffer.concat([
    field_bytes(1, source),
    field_string(2, 'plural entry'),
    field_varint(3, 5),
    field_bytes(4, item),
  ]));
  const style_string = Buffer.concat([
    field_string(1, 'styled macro'),
    field_bytes(2, Buffer.concat([
      field_string(1, 'b'),
      field_varint(2, 0),
      field_varint(3, 5),
    ])),
  ]);
  const macro = Buffer.concat([
    field_string(1, 'raw'),
    field_bytes(2, style_string),
    field_bytes(3, Buffer.concat([field_varint(1, 0), field_varint(2, 5)])),
    field_bytes(4, Buffer.concat([
      field_string(1, 'android'),
      field_string(2, 'com.example'),
      field_varint(3, 1),
    ])),
    field_bytes(5, Buffer.concat([field_varint(1, 4), field_varint(2, 8)])),
  ]);

  const variants = [
    [1, attribute, 'attribute'],
    [2, style, 'style'],
    [3, styleable, 'styleable'],
    [4, array, 'array'],
    [5, plural, 'plural'],
    [6, macro, 'macro'],
  ];
  for (const [field, payload, kind] of variants) {
    const compound = field_bytes(field, payload);
    const value = Buffer.concat([field_varint(3, 1), field_bytes(5, compound)]);
    const parsed = parse_android_resource_table(resource_table_fixture({ value_contents: value }));
    assert.equal(parsed.summary.compound_kinds[kind], 1, kind + ' compound value should remain inventoried');
    const expectedReferences = { attribute: 1, style: 3, styleable: 1, array: 1, plural: 1, macro: 0 };
    assert.equal(
      parsed.summary.reference_count,
      expectedReferences[kind],
      kind + ' nested ResourceTable references must be included in the summary count',
    );
  }

  const malformed_attribute = field_bytes(1, field_bytes(1, Buffer.from([1])));
  const malformed_compound = field_bytes(1, malformed_attribute);
  const malformed_value = Buffer.concat([field_varint(3, 1), field_bytes(5, malformed_compound)]);
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ value_contents: malformed_value })),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_MISMATCH',
    'Known Attribute fields must reject a wrong inner protobuf wire type',
  );

  const malformed_macro = field_bytes(6, field_varint(5, 1));
  const malformed_macro_value = Buffer.concat([field_varint(3, 1), field_bytes(5, malformed_macro)]);
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ value_contents: malformed_macro_value })),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_MISMATCH',
    'MacroBody.source must be a SourcePosition message',
  );
});

test('ResourceTable parser exports through the package root and package subpath', async () => {
  assert.equal(public_api.parse_android_resource_table, parse_android_resource_table);
  const exported = await import('@orix/cli/android/resources-table');
  assert.equal(exported.parse_android_resource_table, parse_android_resource_table);
});

test('ResourceTable parser skips and counts unknown wire-valid fields', () => {
  const fixture = Buffer.concat([resource_table_fixture(), field_varint(99, 123)]);
  const parsed = parse_android_resource_table(fixture);
  assert.equal(parsed.coverage.unknown_fields, 1);
  assert.equal(parsed.summary.entry_count, 1);
});

test('ResourceTable parser rejects duplicate singular fields and malformed oneof variants', () => {
  const valid_source_pool = field_bytes(1, android_string_pool(['res/values/strings.xml']));
  const duplicate_source_pool = Buffer.concat([
    field_bytes(1, valid_source_pool),
    field_bytes(1, valid_source_pool),
  ]);
  assert.throws(
    () => parse_android_resource_table(duplicate_source_pool),
    error => error.code === 'ORIX_RESOURCE_TABLE_DUPLICATE_FIELD',
  );

  const invalid_item = Buffer.concat([
    field_bytes(2, field_string(1, 'one')),
    field_bytes(3, field_string(1, 'two')),
  ]);
  const invalid_value = field_bytes(4, invalid_item);
  const invalid_config = field_bytes(2, invalid_value);
  const invalid_entry = field_bytes(6, invalid_config);
  const invalid_type = field_bytes(3, invalid_entry);
  const invalid_package = field_bytes(3, invalid_type);
  const invalid_table = field_bytes(2, invalid_package);
  assert.throws(
    () => parse_android_resource_table(invalid_table),
    error => error.code === 'ORIX_RESOURCE_TABLE_ONEOF',
  );
});

test('ResourceTable parser rejects invalid UTF-8, bad wire types and truncated payloads', () => {
  assert.throws(
    () => parse_android_resource_table(field_bytes(2, field_bytes(2, Buffer.from([0xff])))),
    error => error.code === 'ORIX_RESOURCE_TABLE_UTF8',
  );
  assert.throws(
    () => parse_android_resource_table(Buffer.from([0x0b])),
    error => error.code === 'ORIX_RESOURCE_TABLE_WIRE_TYPE',
  );
  assert.throws(
    () => parse_android_resource_table(Buffer.from([0x0a, 0x05, 0x01])),
    error => error.code === 'ORIX_RESOURCE_TABLE_LENGTH_RANGE',
  );
});

test('ResourceTable parser enforces file, field, item and output limits', () => {
  const fixture = resource_table_fixture();
  assert.throws(
    () => parse_android_resource_table(fixture, { max_file_bytes: fixture.length - 1 }),
    error => error.code === 'ORIX_RESOURCE_TABLE_FILE_LIMIT',
  );
  assert.throws(
    () => parse_android_resource_table(fixture, { max_fields: 1 }),
    error => error.code === 'ORIX_RESOURCE_TABLE_FIELD_LIMIT',
  );
  assert.throws(
    () => parse_android_resource_table(fixture, { max_items: 3 }),
    error => error.code === 'ORIX_RESOURCE_TABLE_ITEM_LIMIT',
  );
  const truncated = parse_android_resource_table(fixture, { max_output_items: 0 });
  assert.equal(truncated.packages_reported, 0);
  assert.equal(truncated.package_count, 1);
  assert.equal(truncated.packages.length, 0);
  assert.equal(truncated.packages_omitted, 1);
  assert.equal(truncated.coverage.output_truncated, true);
  assert.equal(truncated.summary.entry_count, 1);
});

test('ResourceTable parser rejects out-of-range package and assigned type identifiers', () => {
  const bad_package = Buffer.concat([
    field_bytes(1, id_message(256)),
    field_string(2, 'bad.package'),
  ]);
  assert.throws(
    () => parse_android_resource_table(field_bytes(2, bad_package)),
    error => error.code === 'ORIX_RESOURCE_TABLE_ID_RANGE',
  );

  const bad_type = Buffer.concat([
    field_bytes(1, id_message(0)),
    field_string(2, 'invalid'),
  ]);
  const bad_type_package = Buffer.concat([
    field_bytes(1, id_message(0x7f)),
    field_string(2, 'bad.type'),
    field_bytes(3, bad_type),
  ]);
  assert.throws(
    () => parse_android_resource_table(field_bytes(2, bad_type_package)),
    error => error.code === 'ORIX_RESOURCE_TABLE_ID_RANGE' && error.details.minimum === 1,
  );
});

test('ResourceTable source-pool strings resolve Source.path_idx in UTF-8 and UTF-16LE chunks', () => {
  const source = field_varint(1, 2);
  const visibility = Buffer.concat([
    field_varint(1, 2),
    field_bytes(2, source),
  ]);
  const overlay_source = field_varint(1, 2);
  const utf8 = parse_android_resource_table(resource_table_fixture({
    visibility_metadata: visibility,
    overlayable_source: overlay_source,
    source_pool_first: false,
  }));
  assert.equal(utf8.source_pool_encoding, 'utf-8');
  assert.equal(utf8.source_path_references, 2);
  assert.equal(utf8.source_paths_resolved, 2);
  assert.equal(utf8.source_paths_unresolved, 0);
  assert.deepEqual(utf8.source_paths, [{
    index: 2, path: 'res/values/attrs.xml', reference_count: 2,
  }]);

  const utf16 = parse_android_resource_table(resource_table_fixture({
    overlayable_source: overlay_source,
    source_pool_encoding: 'utf-16le',
  }));
  assert.equal(utf16.source_pool_encoding, 'utf-16le');
  assert.equal(utf16.source_paths_resolved, 1);
  assert.equal(utf16.source_paths[0].path, 'res/values/attrs.xml');

  const default_index = parse_android_resource_table(resource_table_fixture({
    overlayable_source: Buffer.alloc(0),
  }));
  assert.equal(default_index.source_path_references, 1);
  assert.equal(default_index.source_paths_resolved, 1);
  assert.deepEqual(default_index.source_paths, [{
    index: 0, path: 'res/values/strings.xml', reference_count: 1,
  }]);
});

test('ResourceTable rejects invalid source path indices and malformed binary string pools', () => {
  const out_of_range_source = field_varint(1, 3);
  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({ overlayable_source: out_of_range_source })),
    error => error.code === 'ORIX_RESOURCE_TABLE_SOURCE_PATH_INDEX',
  );

  assert.throws(
    () => parse_android_resource_table(Buffer.concat([
      field_bytes(1, field_bytes(1, Buffer.from([1, 2, 3, 4]))),
    ])),
    error => error.code === 'ORIX_RESOURCE_TABLE_STRING_POOL_HEADER',
  );

  const bad_terminator_pool = android_string_pool(['res/values/strings.xml']);
  bad_terminator_pool[bad_terminator_pool.length - 1] = 0x41;
  assert.throws(
    () => parse_android_resource_table(field_bytes(1, field_bytes(1, bad_terminator_pool))),
    error => error.code === 'ORIX_RESOURCE_TABLE_STRING_POOL_TERMINATOR',
  );
});

test('ResourceTable reports unresolved source paths when the source pool is absent', () => {
  const source = field_varint(1, 0);
  const parsed = parse_android_resource_table(resource_table_fixture({
    overlayable_source: source,
    include_source_pool: false,
  }));
  assert.equal(parsed.source_path_references, 1);
  assert.equal(parsed.source_paths_resolved, 0);
  assert.equal(parsed.source_paths_unresolved, 1);
});

test('ResourceTable validates binary string-pool style tables and END-terminated spans', () => {
  const styled_pool = android_string_pool_with_style();
  const parsed = parse_android_resource_table(field_bytes(1, field_bytes(1, styled_pool)));
  assert.equal(parsed.source_pool_string_count, 1);
  assert.equal(parsed.source_pool_style_count, 1);
  assert.equal(parsed.source_pool_style_span_count, 1);

  const unterminated = Buffer.from(styled_pool);
  const styles_start = unterminated.readUInt32LE(24);
  unterminated.writeUInt32LE(0, styles_start + 12);
  unterminated.writeUInt32LE(0, styles_start + 16);
  unterminated.writeUInt32LE(3, styles_start + 20);
  assert.throws(
    () => parse_android_resource_table(field_bytes(1, field_bytes(1, unterminated))),
    error => error.code === 'ORIX_RESOURCE_TABLE_STRING_POOL_STYLE_TERMINATOR',
  );

  const out_of_range_span = Buffer.from(styled_pool);
  const out_of_range_styles_start = out_of_range_span.readUInt32LE(24);
  out_of_range_span.writeUInt32LE('bold'.length, out_of_range_styles_start + 8);
  assert.throws(
    () => parse_android_resource_table(field_bytes(1, field_bytes(1, out_of_range_span))),
    error => error.code === 'ORIX_RESOURCE_TABLE_STRING_POOL_STYLE_SPAN_RANGE',
    'A style span last_char must be inside the associated UTF-16 string',
  );
});

test('ResourceTable source-pool UTF-8 lengths support two-byte length prefixes', () => {
  const long_path = 'res/values/' + 'x'.repeat(140) + '.xml';
  const parsed = parse_android_resource_table(resource_table_fixture({
    source_pool_strings: [long_path],
    overlayable_source: Buffer.alloc(0),
  }));
  assert.equal(parsed.source_paths[0].path, long_path);
  assert.equal(parsed.source_paths_resolved, 1);
});

test('ResourceTable validates StyledString span ranges as UTF-16 code-unit indexes', () => {
  const make_value = (text, first_char, last_char) => {
    const span = Buffer.concat([
      field_string(1, 'b'),
      field_varint(2, first_char),
      field_varint(3, last_char),
    ]);
    const styled_string = Buffer.concat([
      field_string(1, text),
      field_bytes(2, span),
    ]);
    const item = field_bytes(4, styled_string);
    return field_bytes(4, item);
  };

  const valid = parse_android_resource_table(resource_table_fixture({
    value_contents: make_value('A😀BC', 1, 2),
  }));
  assert.equal(valid.summary.item_kinds['styled-string'], 1);

  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({
      value_contents: make_value('hello', 1, 5),
    })),
    error => error.code === 'ORIX_RESOURCE_TABLE_STYLED_STRING_SPAN_RANGE' &&
      error.details.text_length === 5,
    'last_char must be inside the UTF-16 string range',
  );

  assert.throws(
    () => parse_android_resource_table(resource_table_fixture({
      value_contents: make_value('hello', 4, 2),
    })),
    error => error.code === 'ORIX_RESOURCE_TABLE_STYLED_STRING_SPAN_RANGE',
    'first_char must not exceed last_char',
  );
});
