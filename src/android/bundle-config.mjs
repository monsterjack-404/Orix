// Bounded decoder for android.bundle.BundleConfig from BundleTool's config.proto.
// Metadata only: this parser does not generate APKs, resolve resources or install bundles.

const ENUMS = {
  bundle_type: { 0: 'REGULAR', 1: 'APEX', 2: 'ASSET_ONLY' },
  asset_compression: { 0: 'UNSPECIFIED', 1: 'UNCOMPRESSED', 2: 'COMPRESSED' },
  apk_compression: { 0: 'DEFAULT_APK_COMPRESSION_ALGORITHM', 1: 'P7ZIP' },
  inject_min_sdk: { 0: 'UNSPECIFIED', 1: 'DISABLED', 2: 'ENABLED' },
  sparse_encoding: { 0: 'UNSPECIFIED', 2: 'VARIANT_FOR_SDK_32', 3: 'DISABLED' },
  page_alignment: { 0: 'PAGE_ALIGNMENT_UNSPECIFIED', 1: 'PAGE_ALIGNMENT_4K', 2: 'PAGE_ALIGNMENT_16K', 3: 'PAGE_ALIGNMENT_64K' },
  uncompressed_dex_target_sdk: { 0: 'UNSPECIFIED', 1: 'SDK_31', 3: 'SDK_33' },
  dex_merging_strategy: { 0: 'MERGE_IF_NEEDED', 1: 'NEVER_MERGE' },
  feature_modules_mode: { 0: 'FUSED_FEATURE_MODULES', 1: 'SEPARATE_FEATURE_MODULES' },
  split_dimension: { 0: 'UNSPECIFIED_VALUE', 1: 'ABI', 2: 'SCREEN_DENSITY', 3: 'LANGUAGE', 4: 'TEXTURE_COMPRESSION_FORMAT', 6: 'DEVICE_TIER', 7: 'COUNTRY_SET', 8: 'AI_MODEL_VERSION', 9: 'DEVICE_GROUP' },
};

function fail(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  throw error;
}

function bounded_integer(name, value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(name + ' must be an integer between ' + minimum + ' and ' + maximum);
  }
  return value;
}

function read_varint(buffer, cursor, end, label) {
  let value = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (cursor >= end) fail('ORIX_BUNDLE_CONFIG_VARINT_TRUNCATED', 'Truncated BundleConfig protobuf varint', { label, offset: cursor });
    const byte = buffer[cursor++];
    if (index === 9 && (byte & 0xfe) !== 0) {
      fail('ORIX_BUNDLE_CONFIG_VARINT_OVERFLOW', 'BundleConfig protobuf varint exceeds 64 bits', { label, offset: cursor - 1 });
    }
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) return { value, next: cursor };
  }
  fail('ORIX_BUNDLE_CONFIG_VARINT_OVERFLOW', 'BundleConfig protobuf varint exceeds ten bytes', { label, offset: cursor });
}

function read_length(buffer, cursor, end, label) {
  const decoded = read_varint(buffer, cursor, end, label + ' length');
  const remaining = BigInt(end - decoded.next);
  if (decoded.value > remaining) {
    fail('ORIX_BUNDLE_CONFIG_LENGTH_RANGE', 'BundleConfig field length exceeds its enclosing message', {
      label, offset: cursor, length: decoded.value.toString(), remaining: end - decoded.next,
    });
  }
  const size = Number(decoded.value);
  return { start: decoded.next, end: decoded.next + size, next: decoded.next + size };
}

function assert_depth(depth, limits, label) {
  if (depth > limits.max_depth) {
    fail('ORIX_BUNDLE_CONFIG_DEPTH_LIMIT', 'BundleConfig protobuf nesting depth exceeds the configured limit', {
      label, depth, max_depth: limits.max_depth,
    });
  }
}

function consume_item(budget, limits) {
  budget.items_seen += 1;
  if (budget.items_seen > limits.max_items) {
    fail('ORIX_BUNDLE_CONFIG_ITEM_LIMIT', 'BundleConfig repeated-item limit exceeded', { max_items: limits.max_items });
  }
}

function add_output(array, value, budget, limits) {
  if (budget.output_items >= limits.max_output_items) {
    budget.items_omitted += 1;
    budget.output_truncated = true;
    return;
  }
  array.push(value);
  budget.output_items += 1;
}

function decode_string(buffer, value, label, budget, limits) {
  const size = value.end - value.start;
  if (size > limits.max_string_bytes || budget.string_bytes > limits.max_total_string_bytes - size) {
    fail('ORIX_BUNDLE_CONFIG_STRING_LIMIT', 'BundleConfig string budget exceeded', {
      label, size, total: budget.string_bytes,
      max_string_bytes: limits.max_string_bytes,
      max_total_string_bytes: limits.max_total_string_bytes,
    });
  }
  budget.string_bytes += size;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(value.start, value.end));
  } catch {
    fail('ORIX_BUNDLE_CONFIG_UTF8', 'BundleConfig string is not valid UTF-8', { label, offset: value.start, size });
  }
}

function walk_fields(buffer, start, end, budget, visitor, label) {
  let cursor = start;
  while (cursor < end) {
    budget.fields_seen += 1;
    if (budget.fields_seen > budget.limits.max_fields) {
      fail('ORIX_BUNDLE_CONFIG_FIELD_LIMIT', 'BundleConfig protobuf field-count limit exceeded', {
        max_fields: budget.limits.max_fields,
      });
    }
    const tag = read_varint(buffer, cursor, end, label + ' tag');
    cursor = tag.next;
    if (tag.value === 0n || tag.value > 0xffffffffn) {
      fail('ORIX_BUNDLE_CONFIG_FIELD_NUMBER', 'BundleConfig protobuf tag is outside the uint32 range', { label, tag: tag.value.toString() });
    }
    const field_number = Number(tag.value >> 3n);
    const wire_type = Number(tag.value & 7n);
    if (field_number < 1 || field_number > 0x1fffffff) {
      fail('ORIX_BUNDLE_CONFIG_FIELD_NUMBER', 'BundleConfig protobuf field number is invalid', { label, field_number });
    }
    let value;
    if (wire_type === 0) {
      const decoded = read_varint(buffer, cursor, end, label + ' field ' + field_number);
      value = decoded.value;
      cursor = decoded.next;
    } else if (wire_type === 1) {
      if (cursor > end - 8) fail('ORIX_BUNDLE_CONFIG_FIXED64_RANGE', 'Truncated BundleConfig fixed64 field', { label, field_number, offset: cursor });
      value = { start: cursor, end: cursor + 8 };
      cursor += 8;
    } else if (wire_type === 2) {
      value = read_length(buffer, cursor, end, label + ' field ' + field_number);
      cursor = value.next;
    } else if (wire_type === 5) {
      if (cursor > end - 4) fail('ORIX_BUNDLE_CONFIG_FIXED32_RANGE', 'Truncated BundleConfig fixed32 field', { label, field_number, offset: cursor });
      value = { start: cursor, end: cursor + 4 };
      cursor += 4;
    } else {
      fail('ORIX_BUNDLE_CONFIG_WIRE_TYPE', 'Unsupported BundleConfig protobuf wire type', { label, field_number, wire_type });
    }
    visitor(field_number, wire_type, value);
  }
  if (cursor !== end) fail('ORIX_BUNDLE_CONFIG_MESSAGE_RANGE', 'BundleConfig message did not end at its declared boundary', { label, cursor, end });
}

function expect_wire(label, field, actual, expected) {
  if (actual !== expected) {
    fail('ORIX_BUNDLE_CONFIG_WIRE_MISMATCH', 'BundleConfig field has an unexpected wire type', { label, field, expected, actual });
  }
}

function singular(seen, field, label) {
  if (seen.has(field)) fail('ORIX_BUNDLE_CONFIG_DUPLICATE_FIELD', 'Duplicate singular BundleConfig field', { label, field });
  seen.add(field);
}

function enum_value(value, mapping, label) {
  const numeric = Number(BigInt.asIntN(32, value));
  return { value: numeric, name: mapping[numeric] ?? 'UNKNOWN', known: Object.hasOwn(mapping, numeric) };
}

function decode_bool(value) {
  return value !== 0n;
}

function decode_int64(value) {
  const signed = BigInt.asIntN(64, value);
  const number = Number(signed);
  return Number.isSafeInteger(number) ? number : signed.toString();
}

function parse_bundletool(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Bundletool');
  const result = { version: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 2) {
      expect_wire('Bundletool', field, wire, 2);
      singular(seen, field, 'Bundletool');
      result.version = decode_string(buffer, value, 'Bundletool.version', budget, limits);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Bundletool');
  return result;
}

function parse_suffix_stripping(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'SuffixStripping');
  const result = { enabled: false, default_suffix: '' };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('SuffixStripping', field, wire, 0);
      singular(seen, field, 'SuffixStripping');
      result.enabled = decode_bool(value);
    } else if (field === 2) {
      expect_wire('SuffixStripping', field, wire, 2);
      singular(seen, field, 'SuffixStripping');
      result.default_suffix = decode_string(buffer, value, 'SuffixStripping.default_suffix', budget, limits);
    } else budget.unknown_fields += 1;
  }, 'SuffixStripping');
  return result;
}

function parse_split_dimension(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'SplitDimension');
  const result = { value: { value: 0, name: 'UNSPECIFIED_VALUE', known: true }, negate: false, suffix_stripping: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('SplitDimension', field, wire, 0);
      singular(seen, field, 'SplitDimension');
      result.value = enum_value(value, ENUMS.split_dimension, 'SplitDimension.value');
    } else if (field === 2) {
      expect_wire('SplitDimension', field, wire, 0);
      singular(seen, field, 'SplitDimension');
      result.negate = decode_bool(value);
    } else if (field === 3) {
      expect_wire('SplitDimension', field, wire, 2);
      singular(seen, field, 'SplitDimension');
      result.suffix_stripping = parse_suffix_stripping(buffer, value.start, value.end, budget, limits, depth + 1);
    } else budget.unknown_fields += 1;
  }, 'SplitDimension');
  return result;
}

function parse_splits_config(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'SplitsConfig');
  const result = { split_dimensions: [] };
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('SplitsConfig', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.split_dimensions, parse_split_dimension(buffer, value.start, value.end, budget, limits, depth + 1), budget, limits);
    } else budget.unknown_fields += 1;
  }, 'SplitsConfig');
  return result;
}

function parse_uncompress_native_libraries(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'UncompressNativeLibraries');
  const result = { enabled: false, alignment: enum_value(0n, ENUMS.page_alignment, 'PageAlignment') };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('UncompressNativeLibraries', field, wire, 0);
      singular(seen, field, 'UncompressNativeLibraries');
      result.enabled = decode_bool(value);
    } else if (field === 2) {
      expect_wire('UncompressNativeLibraries', field, wire, 0);
      singular(seen, field, 'UncompressNativeLibraries');
      result.alignment = enum_value(value, ENUMS.page_alignment, 'PageAlignment');
    } else budget.unknown_fields += 1;
  }, 'UncompressNativeLibraries');
  return result;
}

function parse_uncompress_dex_files(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'UncompressDexFiles');
  const result = { enabled: false, target_sdk: enum_value(0n, ENUMS.uncompressed_dex_target_sdk, 'UncompressedDexTargetSdk') };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('UncompressDexFiles', field, wire, 0);
      singular(seen, field, 'UncompressDexFiles');
      result.enabled = decode_bool(value);
    } else if (field === 2) {
      expect_wire('UncompressDexFiles', field, wire, 0);
      singular(seen, field, 'UncompressDexFiles');
      result.target_sdk = enum_value(value, ENUMS.uncompressed_dex_target_sdk, 'UncompressedDexTargetSdk');
    } else budget.unknown_fields += 1;
  }, 'UncompressDexFiles');
  return result;
}

function parse_resource_type_name(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'ResourceTypeAndName');
  const result = { type: '', name: '' };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 || field === 2) {
      expect_wire('ResourceTypeAndName', field, wire, 2);
      singular(seen, field, 'ResourceTypeAndName');
      result[field === 1 ? 'type' : 'name'] = decode_string(buffer, value, 'ResourceTypeAndName.' + field, budget, limits);
    } else budget.unknown_fields += 1;
  }, 'ResourceTypeAndName');
  return result;
}

function parse_collapsed_resource_names(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'CollapsedResourceNames');
  const result = { collapse_resource_names: false, no_collapse_resources: [], no_collapse_resource_types: [], deduplicate_resource_entries: false };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 || field === 3) {
      expect_wire('CollapsedResourceNames', field, wire, 0);
      singular(seen, field, 'CollapsedResourceNames');
      result[field === 1 ? 'collapse_resource_names' : 'deduplicate_resource_entries'] = decode_bool(value);
    } else if (field === 2) {
      expect_wire('CollapsedResourceNames', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.no_collapse_resources, parse_resource_type_name(buffer, value.start, value.end, budget, limits, depth + 1), budget, limits);
    } else if (field === 4) {
      expect_wire('CollapsedResourceNames', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.no_collapse_resource_types, decode_string(buffer, value, 'CollapsedResourceNames.no_collapse_resource_types', budget, limits), budget, limits);
    } else budget.unknown_fields += 1;
  }, 'CollapsedResourceNames');
  return result;
}

function parse_resource_optimizations(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'ResourceOptimizations');
  const result = { sparse_encoding: enum_value(0n, ENUMS.sparse_encoding, 'SparseEncoding'), collapsed_resource_names: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('ResourceOptimizations', field, wire, 0);
      singular(seen, field, 'ResourceOptimizations');
      result.sparse_encoding = enum_value(value, ENUMS.sparse_encoding, 'SparseEncoding');
    } else if (field === 2) {
      expect_wire('ResourceOptimizations', field, wire, 2);
      singular(seen, field, 'ResourceOptimizations');
      result.collapsed_resource_names = parse_collapsed_resource_names(buffer, value.start, value.end, budget, limits, depth + 1);
    } else budget.unknown_fields += 1;
  }, 'ResourceOptimizations');
  return result;
}

function parse_standalone_config(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'StandaloneConfig');
  const result = { split_dimensions: [], strip_64_bit_libraries: false, dex_merging_strategy: enum_value(0n, ENUMS.dex_merging_strategy, 'DexMergingStrategy'), feature_modules_mode: enum_value(0n, ENUMS.feature_modules_mode, 'FeatureModulesMode') };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('StandaloneConfig', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.split_dimensions, parse_split_dimension(buffer, value.start, value.end, budget, limits, depth + 1), budget, limits);
    } else if (field === 2 || field === 3 || field === 4) {
      expect_wire('StandaloneConfig', field, wire, 0);
      singular(seen, field, 'StandaloneConfig');
      if (field === 2) result.strip_64_bit_libraries = decode_bool(value);
      if (field === 3) result.dex_merging_strategy = enum_value(value, ENUMS.dex_merging_strategy, 'DexMergingStrategy');
      if (field === 4) result.feature_modules_mode = enum_value(value, ENUMS.feature_modules_mode, 'FeatureModulesMode');
    } else budget.unknown_fields += 1;
  }, 'StandaloneConfig');
  return result;
}

function parse_store_archive(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'StoreArchive');
  const result = { enabled: true };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('StoreArchive', field, wire, 0);
      singular(seen, field, 'StoreArchive');
      result.enabled = decode_bool(value);
    } else budget.unknown_fields += 1;
  }, 'StoreArchive');
  return result;
}

function parse_optimizations(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Optimizations');
  const result = {
    splits_config: null,
    uncompress_native_libraries: null,
    uncompress_dex_files: null,
    standalone_config: null,
    resource_optimizations: null,
    store_archive: null,
    inject_min_sdk_deprecated: null,
    inject_min_sdk_setting: enum_value(0n, ENUMS.inject_min_sdk, 'InjectMinSdkSetting'),
  };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field >= 1 && field <= 6) {
      expect_wire('Optimizations', field, wire, 2);
      singular(seen, field, 'Optimizations');
      if (field === 1) result.splits_config = parse_splits_config(buffer, value.start, value.end, budget, limits, depth + 1);
      if (field === 2) result.uncompress_native_libraries = parse_uncompress_native_libraries(buffer, value.start, value.end, budget, limits, depth + 1);
      if (field === 3) result.uncompress_dex_files = parse_uncompress_dex_files(buffer, value.start, value.end, budget, limits, depth + 1);
      if (field === 4) result.standalone_config = parse_standalone_config(buffer, value.start, value.end, budget, limits, depth + 1);
      if (field === 5) result.resource_optimizations = parse_resource_optimizations(buffer, value.start, value.end, budget, limits, depth + 1);
      if (field === 6) result.store_archive = parse_store_archive(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 7) {
      expect_wire('Optimizations', field, wire, 0);
      singular(seen, field, 'Optimizations');
      result.inject_min_sdk_deprecated = decode_bool(value);
    } else if (field === 8) {
      expect_wire('Optimizations', field, wire, 0);
      singular(seen, field, 'Optimizations');
      result.inject_min_sdk_setting = enum_value(value, ENUMS.inject_min_sdk, 'InjectMinSdkSetting');
    } else budget.unknown_fields += 1;
  }, 'Optimizations');
  return result;
}

function parse_compression(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Compression');
  const result = {
    uncompressed_globs: [],
    install_time_asset_module_default_compression: enum_value(0n, ENUMS.asset_compression, 'AssetModuleCompression'),
    apk_compression_algorithm: enum_value(0n, ENUMS.apk_compression, 'ApkCompressionAlgorithm'),
  };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Compression', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.uncompressed_globs, decode_string(buffer, value, 'Compression.uncompressed_glob', budget, limits), budget, limits);
    } else if (field === 2 || field === 3) {
      expect_wire('Compression', field, wire, 0);
      singular(seen, field, 'Compression');
      if (field === 2) result.install_time_asset_module_default_compression = enum_value(value, ENUMS.asset_compression, 'AssetModuleCompression');
      if (field === 3) result.apk_compression_algorithm = enum_value(value, ENUMS.apk_compression, 'ApkCompressionAlgorithm');
    } else budget.unknown_fields += 1;
  }, 'Compression');
  return result;
}

function signed_int32(value) {
  return Number(BigInt.asIntN(32, value));
}

function parse_packed_varints(buffer, value, label, callback) {
  let cursor = value.start;
  while (cursor < value.end) {
    const decoded = read_varint(buffer, cursor, value.end, label);
    cursor = decoded.next;
    callback(decoded.value);
  }
  if (cursor !== value.end) fail('ORIX_BUNDLE_CONFIG_PACKED_RANGE', 'Packed BundleConfig field did not end at its declared boundary', { label, cursor, end: value.end });
}

function parse_master_resources(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'MasterResources');
  const result = { resource_ids: [], resource_names: [] };
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 && wire === 0) {
      consume_item(budget, limits);
      add_output(result.resource_ids, signed_int32(value), budget, limits);
    } else if (field === 1 && wire === 2) {
      parse_packed_varints(buffer, value, 'MasterResources.resource_ids', item => {
        consume_item(budget, limits);
        add_output(result.resource_ids, signed_int32(item), budget, limits);
      });
    } else if (field === 2) {
      expect_wire('MasterResources', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.resource_names, decode_string(buffer, value, 'MasterResources.resource_names', budget, limits), budget, limits);
    } else budget.unknown_fields += 1;
  }, 'MasterResources');
  return result;
}

function parse_apex_embedded_apk(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'ApexEmbeddedApkConfig');
  const result = { package_name: '', path: '' };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 || field === 2) {
      expect_wire('ApexEmbeddedApkConfig', field, wire, 2);
      singular(seen, field, 'ApexEmbeddedApkConfig');
      result[field === 1 ? 'package_name' : 'path'] = decode_string(buffer, value, 'ApexEmbeddedApkConfig.' + field, budget, limits);
    } else budget.unknown_fields += 1;
  }, 'ApexEmbeddedApkConfig');
  return result;
}

function parse_supported_abi_set(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'SupportedAbiSet');
  const result = { abis: [] };
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('SupportedAbiSet', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.abis, decode_string(buffer, value, 'SupportedAbiSet.abi', budget, limits), budget, limits);
    } else budget.unknown_fields += 1;
  }, 'SupportedAbiSet');
  return result;
}

function parse_apex_config(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'ApexConfig');
  const result = { embedded_apks: [], supported_abi_sets: [] };
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('ApexConfig', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.embedded_apks, parse_apex_embedded_apk(buffer, value.start, value.end, budget, limits, depth + 1), budget, limits);
    } else if (field === 2) {
      expect_wire('ApexConfig', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.supported_abi_sets, parse_supported_abi_set(buffer, value.start, value.end, budget, limits, depth + 1), budget, limits);
    } else budget.unknown_fields += 1;
  }, 'ApexConfig');
  return result;
}

function parse_unsigned_embedded_apk(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'UnsignedEmbeddedApkConfig');
  const result = { path: '' };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('UnsignedEmbeddedApkConfig', field, wire, 2);
      singular(seen, field, 'UnsignedEmbeddedApkConfig');
      result.path = decode_string(buffer, value, 'UnsignedEmbeddedApkConfig.path', budget, limits);
    } else budget.unknown_fields += 1;
  }, 'UnsignedEmbeddedApkConfig');
  return result;
}

function parse_asset_modules_config(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'AssetModulesConfig');
  const result = { app_versions: [], asset_version_tag: '' };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 && wire === 0) {
      consume_item(budget, limits);
      add_output(result.app_versions, decode_int64(value), budget, limits);
    } else if (field === 1 && wire === 2) {
      parse_packed_varints(buffer, value, 'AssetModulesConfig.app_version', item => {
        consume_item(budget, limits);
        add_output(result.app_versions, decode_int64(item), budget, limits);
      });
    } else if (field === 2) {
      expect_wire('AssetModulesConfig', field, wire, 2);
      singular(seen, field, 'AssetModulesConfig');
      result.asset_version_tag = decode_string(buffer, value, 'AssetModulesConfig.asset_version_tag', budget, limits);
    } else budget.unknown_fields += 1;
  }, 'AssetModulesConfig');
  return result;
}

function parse_locales(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Locales');
  const result = { inject_locale_config: false };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Locales', field, wire, 0);
      singular(seen, field, 'Locales');
      result.inject_locale_config = decode_bool(value);
    } else budget.unknown_fields += 1;
  }, 'Locales');
  return result;
}

/**
 * Decode the bounded metadata subset of android.bundle.BundleConfig.
 * Unknown protobuf fields are skipped only after validating their wire framing.
 */
export function parse_android_bundle_config(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('Android BundleConfig input must be a Buffer');
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Android BundleConfig options must be an object');
  const limits = {
    max_file_bytes: options.max_file_bytes ?? 4 * 1024 * 1024,
    max_fields: options.max_fields ?? 100_000,
    max_items: options.max_items ?? 20_000,
    max_depth: options.max_depth ?? 32,
    max_string_bytes: options.max_string_bytes ?? 64 * 1024,
    max_total_string_bytes: options.max_total_string_bytes ?? 2 * 1024 * 1024,
    max_output_items: options.max_output_items ?? 5_000,
  };
  bounded_integer('max_file_bytes', limits.max_file_bytes, 1, 64 * 1024 * 1024);
  bounded_integer('max_fields', limits.max_fields, 1, 1_000_000);
  bounded_integer('max_items', limits.max_items, 1, 100_000);
  bounded_integer('max_depth', limits.max_depth, 1, 64);
  bounded_integer('max_string_bytes', limits.max_string_bytes, 1, 1024 * 1024);
  bounded_integer('max_total_string_bytes', limits.max_total_string_bytes, 1, 8 * 1024 * 1024);
  bounded_integer('max_output_items', limits.max_output_items, 1, 50_000);
  if (buffer.length === 0) fail('ORIX_BUNDLE_CONFIG_EMPTY', 'BundleConfig protobuf input is empty');
  if (buffer.length > limits.max_file_bytes) fail('ORIX_BUNDLE_CONFIG_FILE_LIMIT', 'BundleConfig protobuf input exceeds the configured file-size limit', {
    actual: buffer.length, max_file_bytes: limits.max_file_bytes,
  });

  const budget = { limits, fields_seen: 0, items_seen: 0, output_items: 0, items_omitted: 0, string_bytes: 0, unknown_fields: 0, output_truncated: false };
  const result = {
    schema_version: 'orix.android-bundle-config.v1',
    bundletool: null,
    type: enum_value(0n, ENUMS.bundle_type, 'BundleType'),
    type_present: false,
    compression: null,
    optimizations: null,
    master_resources: null,
    apex_config: null,
    unsigned_embedded_apk_config: [],
    asset_modules_config: null,
    locales: null,
    coverage: null,
    notes: [
      'BundleConfig fields, compression and recognized optimization metadata are decoded from BundleTool config.proto.',
      'Unknown fields are skipped after bounded protobuf wire validation and counted; unrecognized enum values are preserved numerically.',
      'This is metadata inspection only. It does not generate APKs, interpret module splits as installability proof or execute application code.',
    ],
  };
  const seen = new Set();
  walk_fields(buffer, 0, buffer.length, budget, (field, wire, value) => {
    if (field === 1 || field === 2 || field === 3 || field === 4 || field === 5 || field === 7 || field === 9) {
      expect_wire('BundleConfig', field, wire, 2);
      singular(seen, field, 'BundleConfig');
      if (field === 1) result.bundletool = parse_bundletool(buffer, value.start, value.end, budget, limits, 1);
      if (field === 2) result.optimizations = parse_optimizations(buffer, value.start, value.end, budget, limits, 1);
      if (field === 3) result.compression = parse_compression(buffer, value.start, value.end, budget, limits, 1);
      if (field === 4) result.master_resources = parse_master_resources(buffer, value.start, value.end, budget, limits, 1);
      if (field === 5) result.apex_config = parse_apex_config(buffer, value.start, value.end, budget, limits, 1);
      if (field === 7) result.asset_modules_config = parse_asset_modules_config(buffer, value.start, value.end, budget, limits, 1);
      if (field === 9) result.locales = parse_locales(buffer, value.start, value.end, budget, limits, 1);
    } else if (field === 6) {
      expect_wire('BundleConfig', field, wire, 2);
      consume_item(budget, limits);
      add_output(result.unsigned_embedded_apk_config, parse_unsigned_embedded_apk(buffer, value.start, value.end, budget, limits, 1), budget, limits);
    } else if (field === 8) {
      expect_wire('BundleConfig', field, wire, 0);
      singular(seen, field, 'BundleConfig');
      result.type = enum_value(value, ENUMS.bundle_type, 'BundleType');
      result.type_present = true;
    } else budget.unknown_fields += 1;
  }, 'BundleConfig');

  result.coverage = {
    fields_seen: budget.fields_seen,
    items_seen: budget.items_seen,
    items_reported: budget.output_items,
    items_omitted: budget.items_omitted,
    unknown_fields: budget.unknown_fields,
    string_bytes: budget.string_bytes,
    output_truncated: budget.output_truncated,
  };
  return result;
}
