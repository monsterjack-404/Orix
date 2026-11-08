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

function resource_table_fixture() {
  const source_pool = field_bytes(1, Buffer.from([1, 2, 3, 4]));
  const visibility = field_varint(1, 2);
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
  const value = Buffer.concat([
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

test('ResourceTable parser exports through the package root', () => {
  assert.equal(public_api.parse_android_resource_table, parse_android_resource_table);
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
  assert.equal(truncated.packages_reported, undefined);
  assert.equal(truncated.package_count, 1);
  assert.equal(truncated.packages.length, 0);
  assert.equal(truncated.packages_omitted, 1);
  assert.equal(truncated.coverage.output_truncated, true);
  assert.equal(truncated.summary.entry_count, 1);
});

test('ResourceTable parser rejects out-of-range resource identifiers', () => {
  const bad_package = Buffer.concat([
    field_bytes(1, id_message(256)),
    field_string(2, 'bad.package'),
  ]);
  assert.throws(
    () => parse_android_resource_table(field_bytes(2, bad_package)),
    error => error.code === 'ORIX_RESOURCE_TABLE_ID_RANGE',
  );
});
