# Format Support Matrix

ORIX distinguishes **signature recognition** from **structural parsing**. Recognition answers which known leading-byte pattern matched. Parsing answers which structures were decoded and validated. Neither step proves that the file is safe, complete, authentic or semantically valid.

## Recognition and parser coverage

| Format | Signature recognized | Structural parser | Implemented coverage | Not implemented yet |
|---|---:|---:|---|---|
| PE / COFF | Yes (`MZ`) | Yes | PE32/PE32+ headers, file-backed RVA mapping, imports/delay imports/exports, base-relocation blocks and entries, forwarded exports, bounded resource trees and WIN_CERTIFICATE framing | Relocation application, CLR metadata, Authenticode hash and certificate trust verification |
| ELF | Yes | Yes | ELF32/ELF64 headers, endianness, section names, PT_LOAD and other program headers, PT_INTERP, PT_DYNAMIC tags, GNU build IDs, SHT_SYMTAB/SHT_DYNSYM symbols, SHT_REL/SHT_RELA relocation records, GNU Verneed/Verdef records, VERSYM-to-dynsym version mapping, GNU hash bloom filters, buckets and bounded chain records | Extended numbering, relocation application, symbol lookup through GNU hash, DWARF and architecture-specific relocation-name catalogs |
| Thin Mach-O | Yes | Yes | 32/64-bit header, CPU metadata, bounded load commands, LC_SEGMENT/LC_SEGMENT_64 sections and LC_CODE_SIGNATURE superblob/CodeDirectory metadata | Chained fixups, cryptographic trust verification, Objective-C metadata and other command payloads |
| Universal Mach-O | Yes | Yes | 32/64-bit fat architecture tables, bounded non-overlapping slices and per-slice thin Mach-O parsing | Architecture-specific semantic analysis beyond supported thin commands |
| WebAssembly | Yes | Yes | Versioned sections, custom section names, function types, imports (function/table/memory/global), exports, function declarations, start function, code-body framing and module/function names | Full spec validation, instruction decoding/decompilation, complete element/data/global semantics and execution |
| ZIP | Yes | Yes | EOCD and ZIP64 EOCD/locator, 64-bit central-directory metadata, ZIP64 per-entry sizes/offsets, extra-field bounds, path/symlink flags and local data ranges | Multi-disk, decompression, CRC verification and streaming extraction |
| PDF | Yes | Yes | PDF 1.x header, classic xref tables, trailer metadata, incremental /Prev chain, indirect-object framing, encryption and active-content marker triage | Xref-stream entry decoding, object streams, filters/decompression, page-tree semantics, embedded-file extraction and signature verification |
| PNG | Yes | No | Eight-byte PNG signature | Chunk validation, decompression and metadata |
| JPEG | Yes | No | JPEG SOI marker | Marker/segment parsing and image decoding |
| SQLite | Yes | No | Sixteen-byte database signature | Page layout, schema, WAL and freelist parsing |
| GZIP | Yes | No | GZIP magic | Header flags, decompression and trailer validation |

## Parser behavior

### PE/COFF

The parser supports PE32 and PE32+ optional-header layouts. It retains raw machine identifiers, reports known architecture names, identifies selected DLL characteristics and checks each section's raw byte range against the supplied buffer. File-backed RVAs are mapped through headers or section raw data; virtual zero-fill regions are not treated as file bytes. The import directory is decoded into DLL names and name/ordinal thunks. The delay-import directory is decoded from RVA-based or safely convertible VA-based descriptors, including name/ordinal thunks and descriptor termination state. The base-relocation directory is decoded into bounded blocks and raw relocation records, including HIGHLOW, HIGHADJ and DIR64 metadata; target file ranges are reported when mappable, but relocations are never applied. The export directory is decoded into names, ordinals, RVAs and forwarder strings. The resource directory is traversed as a bounded tree with depth, entry and UTF-16 name limits; resource data is reported by RVA and file range without extraction. The security directory is treated as a file offset and WIN_CERTIFICATE record framing is decoded. Descriptor, thunk, export, resource and certificate work is bounded. Base relocation application, CLR metadata, Authenticode digest verification and certificate-chain trust are not implemented.

The registry initially treats the `MZ` prefix as a PE candidate. A DOS executable without a PE signature is therefore detected as candidate `PE` but correctly rejected by the PE parser.

### ELF

The parser validates class and byte order before selecting ELF32 or ELF64 layouts. It decodes bounded program-header tables and reports segment permissions, virtual and physical addresses, file/memory sizes and file-range validity. PT_INTERP strings, PT_DYNAMIC tags, DT_NEEDED library names, DT_SONAME, DT_RPATH and DT_RUNPATH strings are resolved through file-backed PT_LOAD mappings when the dynamic string table is valid. GNU build IDs in PT_NOTE are extracted when their ranges are valid. SHT_SYMTAB and SHT_DYNSYM entries are decoded with linked string-table names; SHT_REL and SHT_RELA records retain target section, symbol index, relocation type and explicit addend where present. All count-driven tables have configurable limits. Section names are resolved only when the section-name table is valid. Large 64-bit offsets that cannot be represented as safe JavaScript numbers are not silently rounded. The parser resolves GNU version requirements and definitions onto linked dynamic symbols through bounded Verneed, Verdef and VERSYM records. GNU hash bloom filters, bucket arrays and terminal-bit chain records are decoded with aggregate traversal limits. Duplicate bucket heads share cached chain results to prevent repeated work. It does not apply relocations, resolve symbol lookups against hash results, interpret architecture-specific relocation names or decode DWARF.

### Mach-O

Thin Mach-O parsing validates magic, byte order, header size and each load command. LC_SEGMENT and LC_SEGMENT_64 decode segment ranges, protections and section records with count and file-range checks. LC_SYMTAB decodes bounded 32-bit/64-bit nlist records, symbol types, external/private/debug flags, values and NUL-terminated names from the declared string table. LC_DYSYMTAB validates local/external/undefined symbol groups, table-of-contents/module/reference/relocation ranges and resolves bounded indirect-symbol entries to names or local/absolute markers. LC_CODE_SIGNATURE reports bounded embedded-signature superblob slots and CodeDirectory metadata; it does not verify hashes, CMS signatures, certificates or trust. Symbol counts and string-table bytes are capped, and invalid indexes or unterminated names are rejected. Universal Mach-O parsing decodes FAT/FAT64 architecture tables, rejects out-of-file and overlapping slices, and runs the thin parser against each bounded slice. Chained fixups, Objective-C metadata and other load-command payloads remain unsupported.

### ZIP

The parser locates the end-of-central-directory record in the permitted trailing window. ZIP64 locators and end records are decoded with safe-integer checks; per-entry ZIP64 extra fields resolve 64-bit sizes and local-header offsets. Central-directory bounds are constrained to the appropriate EOCD record. It reports entry names, compression methods, encryption flags, size ratios, local-header/data range status and suspicious absolute or parent-traversal paths. It never extracts or decompresses content. Multi-disk archives remain unsupported; CRC values are reported but not recomputed.

### WebAssembly

The parser validates the eight-byte preamble, reads section identifiers and bounded unsigned LEB128 payload lengths, and resolves custom-section names within their own section boundary. It does not parse code instructions or assert module validity according to the full WebAssembly validation algorithm.

## Adding a parser

A parser is ready for registration only after it has:

1. A direct Buffer API with no filesystem side effects.
2. Signature and version checks that reject unsupported variants.
3. Bounds-checked field reads and offset arithmetic.
4. A configured ceiling for every count-driven structure.
5. A valid minimal fixture and malformed/truncated fixtures.
6. Tests for endianness and bitness variants supported by the implementation.
7. A deterministic mutation/truncation corpus that checks malformed inputs produce typed parser errors.
8. Explicit notes for structures not decoded.
9. A documented distinction between raw offsets, virtual addresses, RVAs and indices.

Do not use file extensions as a substitute for signature recognition. Extensions may be useful contextual metadata, but they are user-controlled labels.


## Indicator integration

Format parsers return structural facts only. A separate analyzer evaluates selected parsed fields without changing parser output. For PE, it reviews section permission combinations and raw-file ranges. For ZIP, it inspects entry path and symlink metadata. The static indicator catalogue is maintained in [`INDICATORS.md`](INDICATORS.md); those findings are triage leads and do not extend the parser's semantic coverage.


### PDF

The PDF parser validates the version header, locates the final bounded `startxref` / `%%EOF` pair, indexes classic cross-reference subsections and trailer metadata, follows bounded incremental-update `/Prev` links, and scans bounded indirect-object framing. It reports encryption and lexical markers for JavaScript, embedded files, file specifications, open/additional actions and launch actions. It does not execute JavaScript, decompress streams, extract attachments, decode xref-stream entries or object streams, validate page-tree semantics, or verify digital signatures. Marker matches are triage hints, not proof of reachability or execution.
