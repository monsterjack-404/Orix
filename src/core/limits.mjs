// JavaScript, src/core/limits.mjs, Node.js 20+, centralized resource ceilings.

export const DEFAULT_LIMITS = Object.freeze({
  max_file_bytes: 128 * 1024 * 1024,
  max_read_bytes: 16 * 1024 * 1024,
  max_strings: 2_000,
  max_string_length: 512,
  min_string_length: 5,
  max_scan_files: 10_000,
  max_scan_directories: 10_000,
  max_scan_entries: 100_000,
  max_scan_depth: 24,
  max_scan_concurrency: 4,
  max_hex_preview_bytes: 96,
  max_sections: 4_096,
  max_wasm_sections: 4_096,
});

export function bounded_integer(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

export function resolve_limits(overrides = {}) {
  const limits = { ...DEFAULT_LIMITS, ...overrides };
  if (Object.hasOwn(overrides, 'max_file_bytes') && !Object.hasOwn(overrides, 'max_read_bytes')) {
    limits.max_read_bytes = Math.min(DEFAULT_LIMITS.max_read_bytes, limits.max_file_bytes);
  }
  const bounds = {
    max_file_bytes: [1, 2 * 1024 * 1024 * 1024],
    max_read_bytes: [1, 512 * 1024 * 1024],
    max_strings: [0, 100_000],
    max_string_length: [1, 16_384],
    min_string_length: [1, 4_096],
    max_scan_files: [1, 1_000_000],
    max_scan_directories: [1, 1_000_000],
    max_scan_entries: [1, 10_000_000],
    max_scan_depth: [0, 256],
    max_scan_concurrency: [1, 32],
    max_hex_preview_bytes: [0, 4_096],
    max_sections: [1, 65_535],
    max_wasm_sections: [1, 65_535],
  };
  for (const [key, [minimum, maximum]] of Object.entries(bounds)) {
    bounded_integer(limits[key], key, minimum, maximum);
  }
  if (limits.min_string_length > limits.max_string_length) {
    throw new TypeError('min_string_length cannot exceed max_string_length');
  }
  if (limits.max_read_bytes > limits.max_file_bytes) {
    throw new TypeError('max_read_bytes cannot exceed max_file_bytes');
  }
  return Object.freeze(limits);
}
