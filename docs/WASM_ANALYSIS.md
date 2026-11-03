# WebAssembly Structural Analysis

ORIX parses WebAssembly binary version 1 as a bounded structure index. It does not execute a module, instantiate imports, run guest code, contact a host, or decompile instructions.

## Indexed structures

The parser validates and exposes:

- Module magic and binary version.
- Standard section framing, bounded section counts and duplicate standard-section detection.
- Strict UTF-8 decoding for custom-section names, import module/field names and export names.
- Function types, parameter types and result types.
- Function, table, memory, global and tag import descriptors.
- Defined-function type indices.
- Export names, kinds and index values, including duplicate export-name rejection.
- The optional start-function index.
- Code-section function-body byte ranges, including bounds checks and function/code count consistency.
- Standard `name` custom-section module names and function-name maps, including duplicate subsection/index and out-of-range function-index rejection.
- Function and tag references to the parsed type index space.

The sections array keeps each section's ID, name, file offset, payload offset and payload size. For sections that are not yet decoded, vector_count reports the bounded leading vector count when one is available. code_bodies contains byte offsets and lengths only; it does not imply that function instructions have been validated.

## Resource ceilings

parse_wasm(buffer, options) accepts a Node.js Buffer. Defaults are:

| Option | Default | Maximum |
|---|---:|---:|
| max_sections | 4,096 | 65,535 |
| max_vector_entries | 100,000 | 1,000,000 |
| max_name_bytes | 4,096 | 1,048,576 |

Invalid option values throw TypeError. Malformed or truncated binary structures throw typed OrixError values with stable ORIX_WASM_* codes. The parser does not allocate arrays larger than the configured vector limit, and every decoded name is checked against its byte ceiling before decoding.

## Programmatic use

~~~js
import { parse_wasm } from '@orix/cli';

const result = parse_wasm(buffer, {
  max_sections: 4096,
  max_vector_entries: 100000,
  max_name_bytes: 4096,
});

console.log(result.types);
console.log(result.imports);
console.log(result.exports);
console.log(result.module_name);
console.log(result.function_names);
console.log(result.code_bodies);
~~~

The report includes counts.types, counts.imports, counts.imported_functions, counts.defined_functions, counts.exports and counts.code_bodies.

## Explicit limitations

This parser is a structural indexer, not a complete WebAssembly validator. It currently does not decode or semantically validate:

- Function instruction opcodes, control-flow blocks, branch targets or stack typing.
- Local declarations inside code bodies.
- Global constant expressions.
- Full table, memory, global, element, data, data-count or tag section contents; these sections currently expose bounded vector counts only.
- Typed-reference proposals, memory64, extended constant expressions, component-model binaries or future section extensions.
- Debug/source maps, DWARF, decompilation or runtime behavior.

The parser rejects unsupported value types and memory-limit flags rather than guessing their meaning. An accepted structure means that the indexed fields passed ORIX's checks; it is not a standards-conformance certificate. An artifact that is only partially analyzed remains subject to the inspection report's file and coverage limits.

## Regression coverage

tests/wasm-structure.test.mjs covers successful type/import/export/code indexing, module/function name custom sections, custom section names, malformed UTF-8, duplicate and unknown sections, resource ceilings, invalid type/export references, function/code count mismatches, section-boundary reads and truncated code bodies.
