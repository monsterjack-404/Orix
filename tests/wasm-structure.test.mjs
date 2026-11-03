// JavaScript, tests/wasm-structure.test.mjs, Node.js 20+, WebAssembly structural indexing regressions.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_wasm } from '../src/formats/wasm.mjs';

const HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

function encode_u32(value) {
  const bytes = [];
  let rest = value >>> 0;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return Buffer.from(bytes);
}

function section(id, payload) {
  return Buffer.concat([Buffer.from([id]), encode_u32(payload.length), payload]);
}

function module_with(...sections) {
  return Buffer.concat([HEADER, ...sections]);
}

test('WebAssembly parser indexes function types, imports, exports and code body ranges', () => {
  const type = section(1, Buffer.from([1, 0x60, 0, 0]));
  const imports = section(2, Buffer.from([1, 1, 0x6d, 1, 0x66, 0, 0]));
  const functions = section(3, Buffer.from([1, 0]));
  const exports = section(7, Buffer.from([1, 1, 0x66, 0, 1]));
  const start = section(8, Buffer.from([1]));
  const code = section(10, Buffer.from([1, 2, 0, 0x0b]));
  const result = parse_wasm(module_with(type, imports, functions, exports, start, code));

  assert.deepEqual(result.types, [{ params: [], results: [] }]);
  assert.deepEqual(result.imports, [{ module: 'm', name: 'f', kind: 'function', type_index: 0 }]);
  assert.deepEqual(result.exports, [{ name: 'f', kind: 'function', index: 1 }]);
  assert.equal(result.start_function_index, 1);
  assert.deepEqual(result.code_bodies, [{ offset: 40, size: 2 }]);
  assert.deepEqual(result.counts, {
    types: 1, imports: 1, imported_functions: 1,
    defined_functions: 1, exports: 1, code_bodies: 1,
  });
  assert.equal(result.sections.find(item => item.id === 10).vector_count, 1);
});

test('WebAssembly parser preserves custom section names and allows repeated custom sections', () => {
  const custom = section(0, Buffer.from([4, 0x6e, 0x61, 0x6d, 0x65]));
  const repeated = section(0, Buffer.from([3, 0x64, 0x65, 0x62]));
  const result = parse_wasm(module_with(custom, repeated));
  assert.deepEqual(result.sections.map(item => item.custom_name), ['name', 'deb']);
});

test('WebAssembly parser rejects malformed UTF-8 in custom, import and export names', () => {
  const bad_custom = section(0, Buffer.from([1, 0xff]));
  assert.throws(() => parse_wasm(module_with(bad_custom)), error => error.code === 'ORIX_WASM_BAD_UTF8');

  const bad_import = section(2, Buffer.from([1, 1, 0xff, 0]));
  assert.throws(() => parse_wasm(module_with(bad_import)), error => error.code === 'ORIX_WASM_BAD_UTF8');

  const bad_export = section(7, Buffer.from([1, 1, 0xff, 0, 0]));
  assert.throws(() => parse_wasm(module_with(bad_export)), error => error.code === 'ORIX_WASM_BAD_UTF8');
});

test('WebAssembly parser enforces unique standard sections and known section identifiers', () => {
  const empty_vector = section(1, Buffer.from([0]));
  assert.throws(
    () => parse_wasm(module_with(empty_vector, empty_vector)),
    error => error.code === 'ORIX_WASM_DUPLICATE_SECTION',
  );
  assert.throws(
    () => parse_wasm(module_with(section(14, Buffer.from([0])))),
    error => error.code === 'ORIX_WASM_UNKNOWN_SECTION',
  );
});

test('WebAssembly parser bounds vector counts and names before allocating arrays', () => {
  const types = section(1, Buffer.from([2]));
  assert.throws(
    () => parse_wasm(module_with(types), { max_vector_entries: 1 }),
    error => error.code === 'ORIX_WASM_VECTOR_LIMIT',
  );
  const custom = section(0, Buffer.from([3, 0x61, 0x62, 0x63]));
  assert.throws(
    () => parse_wasm(module_with(custom), { max_name_bytes: 2 }),
    error => error.code === 'ORIX_WASM_NAME_LIMIT',
  );
});

test('WebAssembly parser validates type indices, export indices and the function/code pairing', () => {
  const bad_type = section(2, Buffer.from([1, 1, 0x6d, 1, 0x66, 0, 0]));
  assert.throws(
    () => parse_wasm(module_with(bad_type)),
    error => error.code === 'ORIX_WASM_TYPE_INDEX_OUT_OF_RANGE',
  );

  const functions = section(3, Buffer.from([1, 0]));
  const bad_export = section(7, Buffer.from([1, 1, 0x66, 0, 2]));
  assert.throws(
    () => parse_wasm(module_with(section(1, Buffer.from([1, 0x60, 0, 0])), functions, bad_export)),
    error => error.code === 'ORIX_WASM_EXPORT_INDEX_OUT_OF_RANGE',
  );

  assert.throws(
    () => parse_wasm(module_with(section(1, Buffer.from([1, 0x60, 0, 0])), functions)),
    error => error.code === 'ORIX_WASM_FUNCTION_CODE_MISMATCH',
  );
  assert.throws(
    () => parse_wasm(module_with(section(10, Buffer.from([1, 2, 0, 0x0b])))),
    error => error.code === 'ORIX_WASM_FUNCTION_CODE_MISMATCH',
  );
});

test('WebAssembly parser never reads an import field through the next section boundary', () => {
  const truncated_global_import = section(2, Buffer.from([1, 0, 0, 3, 0x7f]));
  const next_custom_section = section(0, Buffer.from([1, 0x78]));
  assert.throws(
    () => parse_wasm(module_with(truncated_global_import, next_custom_section)),
    error => error.code === 'ORIX_WASM_TRUNCATED_SECTION',
  );
});

test('WebAssembly parser validates bounded code-body framing and options', () => {
  const malformed_code = section(10, Buffer.from([1, 5, 0]));
  assert.throws(
    () => parse_wasm(module_with(section(3, Buffer.from([1, 0])), malformed_code)),
    error => error.code === 'ORIX_WASM_BAD_CODE_BODY',
  );
  assert.throws(() => parse_wasm(HEADER, { max_sections: 0 }), /max_sections/);
  assert.throws(() => parse_wasm(HEADER, { max_vector_entries: 0 }), /max_vector_entries/);
  assert.throws(() => parse_wasm(HEADER, { max_name_bytes: 0 }), /max_name_bytes/);
  assert.throws(() => parse_wasm(new Uint8Array(HEADER)), /Buffer/);
});


test('WebAssembly parser indexes table, shared-memory, global and tag imports', () => {
  const types = section(1, Buffer.from([1, 0x60, 0, 0]));
  const imports = section(2, Buffer.from([
    4,
    1, 0x6d, 1, 0x74, 1, 0x70, 1, 1, 2,
    1, 0x6d, 3, 0x6d, 0x65, 0x6d, 2, 3, 1, 2,
    1, 0x6d, 1, 0x67, 3, 0x7f, 1,
    1, 0x6d, 3, 0x74, 0x61, 0x67, 4, 0, 0,
  ]));
  const result = parse_wasm(module_with(types, imports));
  assert.deepEqual(result.imports.map(item => item.kind), ['table', 'memory', 'global', 'tag']);
  assert.deepEqual(result.imports[0].limits, { minimum: 1, maximum: 2, shared: false });
  assert.deepEqual(result.imports[1].limits, { minimum: 1, maximum: 2, shared: true });
  assert.equal(result.imports[2].value_type, 'i32');
  assert.equal(result.imports[2].mutable, true);
  assert.equal(result.imports[3].type_index, 0);
});

test('WebAssembly parser rejects invalid import limits, reference types and mutability', () => {
  const bad_table_type = section(2, Buffer.from([1, 0, 0, 1, 0x7f, 0, 1]));
  assert.throws(() => parse_wasm(module_with(bad_table_type)), error => error.code === 'ORIX_WASM_UNSUPPORTED_VALUE_TYPE');

  const shared_without_maximum = section(2, Buffer.from([1, 0, 0, 2, 3, 1]));
  assert.throws(() => parse_wasm(module_with(shared_without_maximum)), error => error.code === 'ORIX_WASM_INVALID_LIMITS');

  const maximum_below_minimum = section(2, Buffer.from([1, 0, 0, 2, 1, 5, 4]));
  assert.throws(() => parse_wasm(module_with(maximum_below_minimum)), error => error.code === 'ORIX_WASM_INVALID_LIMITS');

  const invalid_mutability = section(2, Buffer.from([1, 0, 0, 3, 0x7f, 2]));
  assert.throws(() => parse_wasm(module_with(invalid_mutability)), error => error.code === 'ORIX_WASM_BAD_MUTABILITY');
});

test('WebAssembly parser rejects duplicate export names and invalid start indices', () => {
  const duplicate_exports = section(7, Buffer.from([
    2, 1, 0x78, 0, 0, 1, 0x78, 0, 0,
  ]));
  assert.throws(
    () => parse_wasm(module_with(duplicate_exports)),
    error => error.code === 'ORIX_WASM_DUPLICATE_EXPORT',
  );

  const invalid_start = section(8, Buffer.from([0]));
  assert.throws(
    () => parse_wasm(module_with(invalid_start)),
    error => error.code === 'ORIX_WASM_START_INDEX_OUT_OF_RANGE',
  );
});

test('WebAssembly parser reports section and vector offsets without decoding guest instructions', () => {
  const type = section(1, Buffer.from([1, 0x60, 1, 0x7f, 1, 0x7e]));
  const functions = section(3, Buffer.from([1, 0]));
  const code = section(10, Buffer.from([1, 4, 0, 0x41, 0x00, 0x0b]));
  const result = parse_wasm(module_with(type, functions, code));
  assert.deepEqual(result.types, [{ params: ['i32'], results: ['i64'] }]);
  assert.equal(result.code_bodies[0].size, 4);
  assert.ok(result.notes.some(note => /instruction streams/.test(note)));
});
