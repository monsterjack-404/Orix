# Format Support Matrix

ORIX distinguishes **signature recognition**, **structural parsing**, **semantic validation** and **trust verification**. These are separate levels of capability. A recognized signature is only a candidate. A parser result means only that the implemented structures passed ORIX's bounded checks; it is not a complete standards-conformance, safety or authenticity certificate.

## Recognition and parser coverage

| Format | Signature recognized | Structural parser | Implemented coverage | Not implemented yet |
|---|---:|---:|---|---|
| PE / COFF (PE) | Yes (MZ candidate) | Yes | PE32/PE32+ headers, file-backed RVA mapping, sections, imports and delay imports, exports/forwarders, bounded resources, WIN_CERTIFICATE framing and base-relocation records | Relocation application, CLR metadata, Authenticode digest verification and certificate-chain trust |
| ELF | Yes | Yes | ELF32/ELF64, program and section headers, PT_INTERP/PT_DYNAMIC, build IDs, symbol tables, REL/RELA, GNU versions and GNU hash bloom/bucket/chain tables | Extended numbering, relocation application, DWARF, architecture-specific relocation names and full dynamic symbol resolution |
| Thin Mach-O | Yes | Yes | 32/64-bit headers, load commands, segments/sections, LC_SYMTAB, LC_DYSYMTAB and CodeDirectory metadata | Chained fixups, Objective-C metadata, CMS/hash/certificate verification and other unsupported command payloads |
| Universal Mach-O | Yes | Yes | FAT/FAT64 architecture tables, bounded non-overlapping slices and per-slice thin parsing | Complete architecture-specific semantic analysis |
| WebAssembly | Yes | Yes | Version, bounded section framing/order, strict UTF-8 names, types, imports, exports, function/type indices, start function, code-body ranges and standard name-section maps | Instruction decoding, stack/type validation, control-flow analysis, global initializers, full table/memory/data/element semantics, DWARF and decompilation |
| ZIP | Yes | Yes | EOCD, ZIP64 EOCD/locator, central directory, ZIP64 per-entry sizes/offsets, path/symlink flags, local data ranges and encryption metadata | Multi-disk archives, bounded decompression/extraction and CRC verification |
| PDF | Yes | Yes | PDF 1.x header, classic xref tables, trailer metadata, incremental /Prev chain, indirect-object framing, encryption and active-content lexical triage | Xref-stream entries, object streams, filters/decompression, page-tree semantics, attachment extraction and digital-signature verification |
| PNG | Yes | Yes | Signature, IHDR fields, chunk boundaries/order, PLTE-before-tRNS ordering, bit-depth-bounded grayscale/truecolor tRNS samples, IDAT sequence, IEND and bounded CRC validation | IDAT inflation, scanline/pixel decoding, color management and full ancillary-chunk semantics |
| JPEG | Yes | No | JPEG SOI marker | Marker/segment parser and metadata |
| SQLite | Yes | No | Sixteen-byte database signature | Page layout, schema, WAL and freelist parsing |
| GZIP | Yes | No | GZIP magic | Header flags, bounded decompression and trailer validation |

The registry recognizes PE from the MZ prefix as a candidate. A DOS executable without a PE signature is therefore reported as a PE candidate and rejected by the PE parser. This is intentional candidate recognition, not proof of PE structure.

## Parser behavior and boundaries

### PE / COFF

The parser supports PE32 and PE32+ optional-header layouts. It retains raw machine identifiers, reports known architecture names, identifies selected DLL characteristics and checks section raw-byte ranges against the supplied buffer. File-backed RVAs are mapped through headers or section raw data; virtual zero-fill regions are not treated as file bytes.

The import directory is decoded into DLL names and name/ordinal thunks. Delay imports support RVA-based and safely convertible VA-based descriptors, including name/ordinal thunks and termination state. Base-relocation blocks and records include HIGHLOW, HIGHADJ and DIR64 metadata; relocations are not applied. Exports include names, ordinals, RVAs and forwarder strings. Resource directories are traversed with depth, entry and UTF-16 name limits. Resource data is reported by RVA and file range without extraction. The security directory is treated as a file offset and WIN_CERTIFICATE framing is decoded.

Certificate framing is not Authenticode verification. The parser does not calculate the Authenticode digest, validate CMS signatures, construct certificate chains or apply a trust policy.

### ELF

The parser validates class and byte order before selecting ELF32 or ELF64 layouts. It decodes bounded program-header tables, segment permissions and ranges, PT_INTERP, PT_DYNAMIC tags, DT_NEEDED, DT_SONAME, DT_RPATH and DT_RUNPATH through valid file-backed PT_LOAD mappings. GNU build IDs are extracted from bounded PT_NOTE records.

SHT_SYMTAB/SHT_DYNSYM symbols and SHT_REL/SHT_RELA relocation records are decoded with linked string tables and explicit addends where present. GNU Verneed/Verdef records and VERSYM mappings are resolved onto linked dynamic symbols. GNU hash bloom filters, bucket arrays and terminal-bit chains are decoded under aggregate traversal limits; duplicate bucket heads share cached chain results. The parser does not apply relocations, resolve full runtime symbol binding, decode DWARF or provide a complete architecture-specific relocation name catalog.

### Mach-O

Thin Mach-O parsing validates magic, byte order, header size and load-command boundaries. LC_SEGMENT and LC_SEGMENT_64 decode segment ranges, protections and section records. LC_SYMTAB decodes bounded 32-bit/64-bit nlist symbols and names. LC_DYSYMTAB validates symbol groups and resolves bounded indirect-symbol entries. LC_CODE_SIGNATURE reports bounded superblob slots and CodeDirectory metadata only.

Universal Mach-O parses FAT/FAT64 architecture tables, rejects overlapping or out-of-file slices and invokes the thin parser per slice. Neither CodeDirectory metadata nor an embedded certificate implies cryptographic trust. Chained fixups, Objective-C metadata and other unsupported load-command payloads remain outside current coverage.

### WebAssembly

The parser validates the versioned preamble and standard section ordering, bounded unsigned LEB128 payload lengths, section boundaries, UTF-8 names, function types, imports, exports, type/function references, start-function indices, code-body framing and standard name custom-section maps. It reports code-body byte ranges but does not decode guest instructions or prove full module validity. See [WASM Analysis](WASM_ANALYSIS.md) for exact fields, ceilings and exclusions.

### PNG

The parser indexes PNG chunks without inflating or decoding image pixels. It validates the eight-byte signature, first/unique IHDR placement, non-zero dimensions, legal bit-depth/color-type combinations, supported compression/filter/interlace method values, chunk type letters and reserved bit, chunk boundaries, PLTE-before-tRNS ordering when both are present, grayscale/truecolor tRNS sample ranges against IHDR bit depth, indexed-color tRNS palette bounds, consecutive IDAT chunks, required IEND placement and CRC values within a configurable work budget. It reports unknown critical chunks and CRCs skipped after the budget is exhausted. Chunk offsets and lengths are retained for independent inspection. It does not inflate IDAT, decode scanlines, validate pixel filters, apply color profiles or claim that an image is fully renderable.

### ZIP

The parser locates the end-of-central-directory record within a bounded trailing window. ZIP64 locators, end records and per-entry extra fields are decoded with safe-integer and central-directory checks. It reports names, compression methods, encryption flags, size ratios, local-header/data range status and suspicious paths. It does not extract, decompress, decrypt or recompute CRC values. Do not treat archive metadata as proof of what an extracting application will do.

### PDF

The parser validates the version header, locates a bounded final startxref/EOF pair, indexes classic cross-reference subsections and trailer metadata, follows bounded incremental-update /Prev links and scans bounded indirect-object framing. It reports encryption and lexical markers for JavaScript, embedded files, file specifications, open/additional actions and launch actions. It does not execute JavaScript, decompress streams, extract attachments, decode xref-stream entries or object streams, validate page-tree semantics or verify digital signatures. Marker matches do not prove that the content is reachable or executed.

## Parser implementation contract

A parser is ready for registration only after it has:

1. A direct Buffer API with no filesystem, network or process side effects.
2. Signature, version, class and byte-order checks that reject unsupported variants explicitly.
3. Bounds-checked reads and overflow-safe offset arithmetic.
4. A ceiling for every count-driven structure, string, recursion path and aggregate work loop.
5. Valid minimal fixtures and malformed/truncated fixtures.
6. Tests for each supported bitness, endianness and architecture family.
7. Mutation/truncation tests that produce bounded, typed outcomes.
8. Explicit unsupported-structure notes and coverage metadata.
9. A documented distinction between file offsets, virtual addresses, RVAs, indices and lengths.
10. Independent differential checks where a trusted tool can serve as an oracle.

File extensions are user-controlled labels and must never substitute for signature or structural validation.

## Indicator integration

Format parsers return structural facts. The separate indicator engine evaluates selected facts without mutating parser output. The current PDF, PE, ZIP, entropy, acquisition-stability and parser-rejection rules are documented in [INDICATORS.md](INDICATORS.md). These are triage leads, not malware classifications or proofs of runtime behavior.

## Future format selection

New formats should be prioritized by user demand, ecosystem impact, available authoritative specifications, fixture quality, independent validation tools and safe parser boundaries. Candidate areas include Android APK/DEX, additional executable formats, container/image metadata and common database formats. Recognition may be added before parsing only when the CLI and reports clearly label it signature-only.