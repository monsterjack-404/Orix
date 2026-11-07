import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parse_android_resource_table } from '../src/android/resource-table.mjs';

function varint(input) {
  let value = BigInt.asUintN(64, BigInt(input));
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
  return Buffer.concat([varint(BigInt(field * 8 + 2)), varint(value.length), value]);
}

function field_string(field, value) {
  return field_bytes(field, Buffer.from(value, 'utf8'));
}

function message(fields) {
  return Buffer.concat(fields);
}

function create_resource_table() {
  const source = message([
    field_varint(1, 7),
    field_bytes(2, message([field_varint(1, 12), field_varint(2, 3)])),
  ]);
  const visibility = message([
    field_varint(1, 2), // PUBLIC
    field_bytes(2, source),
    field_string(3, 'public string resource'),
    field_varint(4, 1),
  ]);
  const configuration = message([
    field_string(3, 'en-US'),
    field_varint(18, 320),
    field_varint(24, 35),
    field_varint(7, 411),
  ]);
  const string_value = field_bytes(2, message([field_string(1, 'Hello ORIX')]));
  const string_item = message([string_value, field_varint(8, 2), field_varint(9, 1), field_string(10, 'feature_flag')]);
  const value = message([field_string(2, 'hello comment'), field_varint(3, 1), field_bytes(4, string_item)]);
  const variant = message([field_bytes(1, configuration), field_bytes(2, value)]);

  const reference = message([
    field_varint(1, 0), // REFERENCE
    field_varint(2, 0x7f010001),
    field_string(3, '@string/title'),
    field_varint(4, 1),
  ]);
  const reference_item = message([field_bytes(1, reference)]);
  const reference_value = message([field_bytes(4, reference_item)]);
  const reference_variant = message([field_bytes(2, reference_value)]);

  const file_ref = message([field_string(1, 'res/drawable/icon.png'), field_varint(2, 1)]);
  const file_item = message([field_bytes(5, file_ref)]);
  const file_value = message([field_bytes(4, file_item)]);
  const file_variant = message([field_bytes(2, file_value)]);

  const primitive = message([field_varint(8, 1)]);
  const primitive_item = message([field_bytes(7, primitive)]);
  const primitive_value = message([field_bytes(4, primitive_item)]);
  const primitive_variant = message([field_bytes(2, primitive_value)]);

  const array_element = message([field_bytes(3, message([field_bytes(2, message([field_string(1, 'one')]))]))]);
  const array = message([field_bytes(1, array_element)]);
  const compound = message([field_bytes(4, array)]);
  const compound_value = message([field_bytes(5, compound)]);
  const compound_variant = message([field_bytes(2, compound_value)]);

  const entry = message([
    field_bytes(6, variant),
    field_bytes(6, reference_variant),
    field_bytes(6, file_variant),
    field_bytes(6, primitive_variant),
    field_bytes(6, compound_variant),
    field_bytes(8, variant),
    field_string(2, 'title'),
    field_bytes(3, visibility),
    field_bytes(1, message([field_varint(1, 1)])),
  ]);
  const type = message([
    field_bytes(3, entry),
    field_string(2, 'string'),
    field_bytes(1, message([field_varint(1, 1)])),
  ]);
  const pkg = message([
    field_bytes(3, type),
    field_string(2, 'com.example.orix'),
    field_bytes(1, message([field_varint(1, 0x7f)])),
  ]);
  const source_pool = field_bytes(1, Buffer.from([0, 1, 2, 3, 255]));
  const overlayable = message([field_string(1, 'SystemUI'), field_string(3, 'overlay://actor')]);
  const tool = message([field_string(1, 'aapt2'), field_string(2, '8.6.1')]);
  const dynamic = message([field_bytes(1, message([field_varint(1, 1)])), field_string(2, 'android')]);
  return message([
    field_bytes(2, pkg),
    field_bytes(1, source_pool),
    field_bytes(3, overlayable),
    field_bytes(4, tool),
    field_bytes(5, dynamic),
    field_varint(99, 7), // unknown, wire-valid field
  ]);
}

test('ResourceTable parser inventories package/type/entry identity independent of protobuf field order', () => {
  const report = parse_android_resource_table(create_resource_table());
  assert.equal(report.schema_version, 'orix.android-resource-table.v1');
  assert.equal(report.packages.length, 1);
  const pkg = report.packages[0];
  assert.equal(pkg.name, 'com.example.orix');
  assert.equal(pkg.package_id, 0x7f);
  assert.equal(pkg.types[0].name, 'string');
  assert.equal(pkg.types[0].type_id.id, 1);
  const entry = pkg.types[0].entries[0];
  assert.equal(entry.name, 'title');
  assert.equal(entry.entry_id.id, 1);
  assert.equal(entry.resource_id, '0x7f010001');
  assert.equal(entry.visibility.level.name, 'PUBLIC');
  assert.equal(entry.visibility.staged_api, true);
  assert.equal(entry.config_values.length, 5);
  assert.equal(entry.flag_disabled_config_values.length, 1);
});

test('ResourceTable parser decodes config qualifiers and recognized top-level value kinds', () => {
  const report = parse_android_resource_table(create_resource_table());
  const entry = report.packages[0].types[0].entries[0];
  assert.equal(entry.config_values[0].configuration.locale, 'en-US');
  assert.equal(entry.config_values[0].configuration.density, 320);
  assert.equal(entry.config_values[0].configuration.sdk_version, 35);
  assert.equal(entry.config_values[0].configuration.screen_width_dp, 411);
  assert.equal(entry.config_values[0].value.item.kind, 'string');
  assert.equal(entry.config_values[0].value.item.value, 'Hello ORIX');
  assert.equal(entry.config_values[1].value.item.kind, 'reference');
  assert.equal(entry.config_values[1].value.item.value.resource_id, 0x7f010001);
  assert.equal(entry.config_values[1].value.item.value.name, '@string/title');
  assert.equal(entry.config_values[2].value.item.kind, 'file');
  assert.equal(entry.config_values[2].value.item.value.path, 'res/drawable/icon.png');
  assert.equal(entry.config_values[3].value.item.kind, 'primitive');
  assert.deepEqual(entry.config_values[3].value.item.value, { kind: 'boolean', value: true });
  assert.equal(entry.config_values[4].value.kind, 'compound:array');
  assert.equal(report.summary.direct_references, 1);
  assert.deepEqual(report.summary.compound_value_kinds, { array: 1 });
});

test('ResourceTable parser hashes the opaque source pool and inventories overlay/tool/dynamic metadata', () => {
  const report = parse_android_resource_table(create_resource_table());
  const raw = Buffer.from([0, 1, 2, 3, 255]);
  assert.deepEqual(report.source_pool, {
    size_bytes: raw.length,
    sha256: createHash('sha256').update(raw).digest('hex'),
    decoded: false,
  });
  assert.equal(report.overlayables[0].name, 'SystemUI');
  assert.equal(report.overlayables[0].actor, 'overlay://actor');
  assert.equal(report.tool_fingerprints[0].tool, 'aapt2');
  assert.equal(report.tool_fingerprints[0].version, '8.6.1');
  assert.equal(report.dynamic_ref_tables[0].package_id, 1);
  assert.equal(report.dynamic_ref_tables[0].package_name, 'android');
  assert.equal(report.coverage.unknown_fields, 1);
});

test('ResourceTable summary counts full parsed coverage independently of output truncation', () => {
  const report = parse_android_resource_table(create_resource_table(), { max_output_items: 1 });
  assert.equal(report.summary.package_count, 1);
  assert.equal(report.summary.type_count, 1);
  assert.equal(report.summary.entry_count, 1);
  assert.equal(report.summary.variant_count, 5);
  assert.equal(report.summary.disabled_variant_count, 1);
  assert.equal(report.coverage.output_truncated, true);
  assert.ok(report.coverage.items_omitted > 0);
});

test('ResourceTable parser rejects truncated varints, bad UTF-8, conflicting oneofs and malformed fixed-width fields', () => {
  assert.throws(() => parse_android_resource_table(Buffer.from([0x10, 0x80])), error => error.code === 'ORIX_RESOURCE_VARINT_TRUNCATED');
  assert.throws(() => parse_android_resource_table(field_bytes(2, field_bytes(2, Buffer.from([0xff])))), error => error.code === 'ORIX_RESOURCE_UTF8');

  const bad_item = message([
    field_bytes(2, message([field_string(1, 'one')])),
    field_bytes(3, message([field_string(1, 'two')])),
  ]);
  const bad_value = field_bytes(4, bad_item);
  const bad_entry = field_bytes(2, message([field_string(2, 'bad'), field_bytes(4, message([field_bytes(4, message([bad_value]))]))]));
  const bad_type = field_bytes(3, message([field_string(2, 'string'), bad_entry]));
  const bad_pkg = field_bytes(2, message([field_bytes(3, bad_type)]));
  assert.throws(() => parse_android_resource_table(bad_pkg), error => error.code === 'ORIX_RESOURCE_ONEOF_DUPLICATE');

  const bad_fixed = field_bytes(2, Buffer.from([0x0d, 1, 2, 3]));
  assert.throws(() => parse_android_resource_table(bad_fixed), error => error.code === 'ORIX_RESOURCE_FIXED32_RANGE');
});

test('ResourceTable parser enforces file, field, item, depth, string and output budgets', () => {
  const table = create_resource_table();
  assert.throws(() => parse_android_resource_table(table, { max_file_bytes: table.length - 1 }), error => error.code === 'ORIX_RESOURCE_FILE_LIMIT');
  assert.throws(() => parse_android_resource_table(table, { max_fields: 1 }), error => error.code === 'ORIX_RESOURCE_FIELD_LIMIT');
  assert.throws(() => parse_android_resource_table(table, { max_items: 1 }), error => error.code === 'ORIX_RESOURCE_ITEM_LIMIT');
  assert.throws(() => parse_android_resource_table(table, { max_depth: 1 }), error => error.code === 'ORIX_RESOURCE_DEPTH_LIMIT');
  assert.throws(() => parse_android_resource_table(create_resource_table(), { max_string_bytes: 3 }), error => error.code === 'ORIX_RESOURCE_STRING_LIMIT');
});
