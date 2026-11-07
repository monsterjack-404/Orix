import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_android_bundle_config } from '../src/android/bundle-config.mjs';
import * as public_api from '../src/index.mjs';
import { parse_android_bundle_config as package_subpath_parser } from '@orix/cli/android/bundle-config';

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

function field_bytes(field, contents) {
  return Buffer.concat([varint(BigInt(field * 8 + 2)), varint(contents.length), contents]);
}

function field_string(field, value) {
  return field_bytes(field, Buffer.from(value, 'utf8'));
}

function valid_bundle_config() {
  const bundletool = field_string(2, '1.18.0');

  const compression = Buffer.concat([
    field_string(1, 'lib/**/*.so'),
    field_varint(2, 1),
    field_varint(3, 1),
  ]);

  const split_dimension = Buffer.concat([
    field_varint(1, 1), // ABI
    field_varint(2, 1), // negate
    field_bytes(3, Buffer.concat([field_varint(1, 1), field_string(2, '#default')])),
  ]);
  const splits_config = field_bytes(1, split_dimension);
  const native_libraries = Buffer.concat([field_varint(1, 1), field_varint(2, 2)]);
  const dex_files = Buffer.concat([field_varint(1, 1), field_varint(2, 3)]);
  const standalone = Buffer.concat([
    field_bytes(1, split_dimension),
    field_varint(2, 1),
    field_varint(3, 1),
    field_varint(4, 1),
  ]);
  const collapsed_names = Buffer.concat([
    field_varint(1, 1),
    field_bytes(2, Buffer.concat([field_string(1, 'layout'), field_string(2, 'main')])),
    field_varint(3, 1),
    field_string(4, 'string'),
  ]);
  const resource_optimizations = Buffer.concat([field_varint(1, 2), field_bytes(2, collapsed_names)]);
  const optimizations = Buffer.concat([
    field_bytes(1, splits_config),
    field_bytes(2, native_libraries),
    field_bytes(3, dex_files),
    field_bytes(4, standalone),
    field_bytes(5, resource_optimizations),
    field_bytes(6, field_varint(1, 0)),
    field_varint(7, 1),
    field_varint(8, 2),
  ]);

  const resource_ids = Buffer.concat([varint(0x7f020002), varint(0x7f030003)]);
  const master_resources = Buffer.concat([
    field_varint(1, 0x7f010001),
    field_bytes(1, resource_ids), // packed form
    field_string(2, 'drawable/icon'),
    field_string(2, 'string/title'),
  ]);

  const embedded_apk = Buffer.concat([
    field_string(1, 'com.example.system'),
    field_string(2, 'system/app/example.apk'),
  ]);
  const abi_set = Buffer.concat([field_string(1, 'arm64-v8a'), field_string(1, 'x86_64')]);
  const apex_config = Buffer.concat([field_bytes(1, embedded_apk), field_bytes(2, abi_set)]);
  const asset_modules = Buffer.concat([
    field_varint(1, 42), // unpacked int64
    field_bytes(1, Buffer.concat([varint(100), varint(200)])), // packed int64
    field_string(2, 'upload-2026'),
  ]);

  return Buffer.concat([
    field_bytes(1, bundletool),
    field_bytes(2, optimizations),
    field_bytes(3, compression),
    field_bytes(4, master_resources),
    field_bytes(5, apex_config),
    field_bytes(6, field_string(1, 'assets/prebuilt.apk')),
    field_bytes(7, asset_modules),
    field_varint(8, 2), // ASSET_ONLY
    field_bytes(9, field_varint(1, 1)),
    field_varint(15, 123), // forward-compatible unknown field
  ]);
}

test('BundleConfig parser decodes tool, type, compression, split and optimization metadata', () => {
  const report = parse_android_bundle_config(valid_bundle_config());
  assert.equal(report.schema_version, 'orix.android-bundle-config.v1');
  assert.equal(report.bundletool.version, '1.18.0');
  assert.deepEqual(report.type, { value: 2, name: 'ASSET_ONLY', known: true });
  assert.deepEqual(report.compression.uncompressed_globs, ['lib/**/*.so']);
  assert.equal(report.compression.install_time_asset_module_default_compression.name, 'UNCOMPRESSED');
  assert.equal(report.compression.apk_compression_algorithm.name, 'P7ZIP');
  assert.deepEqual(report.optimizations.splits_config.split_dimensions[0].value, { value: 1, name: 'ABI', known: true });
  assert.equal(report.optimizations.splits_config.split_dimensions[0].negate, true);
  assert.equal(report.optimizations.splits_config.split_dimensions[0].suffix_stripping.default_suffix, '#default');
  assert.equal(report.optimizations.uncompress_native_libraries.enabled, true);
  assert.equal(report.optimizations.uncompress_native_libraries.alignment.name, 'PAGE_ALIGNMENT_16K');
  assert.equal(report.optimizations.uncompress_dex_files.target_sdk.name, 'SDK_33');
  assert.equal(report.optimizations.standalone_config.dex_merging_strategy.name, 'NEVER_MERGE');
  assert.equal(report.optimizations.standalone_config.feature_modules_mode.name, 'SEPARATE_FEATURE_MODULES');
  assert.equal(report.optimizations.resource_optimizations.sparse_encoding.name, 'VARIANT_FOR_SDK_32');
  assert.equal(report.optimizations.resource_optimizations.collapsed_resource_names.deduplicate_resource_entries, true);
  assert.deepEqual(report.master_resources.resource_ids, [0x7f010001, 0x7f020002, 0x7f030003]);
  assert.deepEqual(report.master_resources.resource_names, ['drawable/icon', 'string/title']);
  assert.equal(report.apex_config.embedded_apks[0].package_name, 'com.example.system');
  assert.deepEqual(report.apex_config.supported_abi_sets[0].abis, ['arm64-v8a', 'x86_64']);
  assert.equal(report.unsigned_embedded_apk_config[0].path, 'assets/prebuilt.apk');
  assert.deepEqual(report.asset_modules_config.app_versions, [42, 100, 200]);
  assert.equal(report.asset_modules_config.asset_version_tag, 'upload-2026');
  assert.equal(report.locales.inject_locale_config, true);
  assert.equal(report.coverage.unknown_fields, 1);
  assert.equal(report.coverage.output_truncated, false);
});

test('BundleConfig parser accepts an empty proto3 message as default configuration', () => {
  const report = parse_android_bundle_config(Buffer.alloc(0));
  assert.equal(report.type.name, 'REGULAR');
  assert.equal(report.type_present, false);
  assert.equal(report.bundletool, null);
  assert.equal(report.coverage.fields_seen, 0);
  assert.equal(report.coverage.unknown_fields, 0);
});

test('BundleConfig parser preserves unknown enum numbers without inventing names', () => {
  const report = parse_android_bundle_config(Buffer.concat([field_varint(8, 99)]));
  assert.deepEqual(report.type, { value: 99, name: 'UNKNOWN', known: false });
});

test('BundleConfig parser enforces duplicate singular fields and protobuf wire types', () => {
  assert.throws(
    () => parse_android_bundle_config(Buffer.concat([field_varint(8, 0), field_varint(8, 1)])),
    error => error.code === 'ORIX_BUNDLE_CONFIG_DUPLICATE_FIELD',
  );
  const bad_master_resources = field_bytes(4, Buffer.from([0x0d, 1, 2, 3, 4])); // field 1 encoded as fixed32 instead of int32.
  assert.throws(
    () => parse_android_bundle_config(bad_master_resources),
    error => error.code === 'ORIX_BUNDLE_CONFIG_WIRE_MISMATCH',
  );
  const bad_asset_versions = field_bytes(7, Buffer.from([0x0d, 1, 2, 3, 4])); // packed/unpacked int64 accepts only wire 0 or 2.
  assert.throws(
    () => parse_android_bundle_config(bad_asset_versions),
    error => error.code === 'ORIX_BUNDLE_CONFIG_WIRE_MISMATCH',
  );
});

test('BundleConfig parser rejects truncated varints, invalid lengths and malformed UTF-8', () => {
  assert.throws(
    () => parse_android_bundle_config(Buffer.from([0x08, 0x80])),
    error => error.code === 'ORIX_BUNDLE_CONFIG_VARINT_TRUNCATED',
  );
  assert.throws(
    () => parse_android_bundle_config(Buffer.from([0x0a, 0x05, 0x01])),
    error => error.code === 'ORIX_BUNDLE_CONFIG_LENGTH_RANGE',
  );
  assert.throws(
    () => parse_android_bundle_config(field_bytes(1, field_bytes(2, Buffer.from([0xff])))),
    error => error.code === 'ORIX_BUNDLE_CONFIG_UTF8',
  );
  assert.throws(
    () => parse_android_bundle_config(Buffer.from([0x0b])),
    error => error.code === 'ORIX_BUNDLE_CONFIG_WIRE_TYPE',
  );
});

test('BundleConfig parser enforces field, repeated-item, depth, string and file budgets', () => {
  const two_globs = field_bytes(3, Buffer.concat([field_string(1, 'a'), field_string(1, 'b')]));
  assert.throws(() => parse_android_bundle_config(two_globs, { max_items: 1 }), error => error.code === 'ORIX_BUNDLE_CONFIG_ITEM_LIMIT');
  assert.throws(() => parse_android_bundle_config(two_globs, { max_fields: 1 }), error => error.code === 'ORIX_BUNDLE_CONFIG_FIELD_LIMIT');
  assert.throws(() => parse_android_bundle_config(field_bytes(2, field_bytes(1, field_bytes(1, field_varint(1, 1)))), { max_depth: 2 }), error => error.code === 'ORIX_BUNDLE_CONFIG_DEPTH_LIMIT');
  assert.throws(() => parse_android_bundle_config(field_bytes(3, field_string(1, 'long')), { max_string_bytes: 2 }), error => error.code === 'ORIX_BUNDLE_CONFIG_STRING_LIMIT');
  assert.throws(() => parse_android_bundle_config(Buffer.alloc(8), { max_file_bytes: 4 }), error => error.code === 'ORIX_BUNDLE_CONFIG_FILE_LIMIT');
  const truncated = parse_android_bundle_config(two_globs, { max_output_items: 1 });
  assert.deepEqual(truncated.compression.uncompressed_globs, ['a']);
  assert.equal(truncated.coverage.items_omitted, 1);
  assert.equal(truncated.coverage.output_truncated, true);
});

test('BundleConfig parser is exported from the root API and package subpath', () => {
  assert.equal(public_api.parse_android_bundle_config, parse_android_bundle_config);
  assert.equal(package_subpath_parser, parse_android_bundle_config);
});
