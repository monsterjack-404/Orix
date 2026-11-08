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

function resource_table_fixture({ entry_metadata = Buffer.alloc(0), visibility_metadata = null, overlayable_source = null, value_contents = null } = {}) {
  const source_pool = field_bytes(1, Buffer.from([1, 2, 3, 4]));
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
  return Buffer.concat([
    field_bytes(1, source_pool),
    field_bytes(2, pkg),
    field_bytes(3, overlayable),
    field_bytes(4, fingerprint),
    field_bytes(5, dynamic_ref),
  ]);
}

test('ResourceTable parser inventories packages, types, entries, IDs and selected configurations', () => {
  const parsed = parse_android_resource_table(resource_table_fixture());
  assert.equal(parsed.schema_version, 'orix.android-resource-table.v1');
  assert.equal(parsed.source_pool_present, true);
  assert.equal(parsed.source_pool_data_bytes, 4);
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
  const duplicate_source_pool = Buffer.concat([
    field_bytes(1, Buffer.alloc(0)),
    field_bytes(1, Buffer.alloc(0)),
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
    () => parse_android_resource_table(fixture, { max_items: 1 }),
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
