# Format Support Matrix

ORIX distinguishes **signature recognition** from **structural parsing**. Recognition answers which known leading-byte pattern matched. Parsing answers which structures were decoded and validated. Neither step proves that the file is safe, complete, authentic or semantically valid.

## Recognition and parser coverage

| Format | Signature recognized | Structural parser | Implemented coverage | Not implemented yet |
|---|---:|---:|---|---|
| PE / COFF | Yes (`MZ`) | Yes | PE pointer, signature, COFF, PE32/PE32+, selected optional fields, data directories, section records, file-backed RVA mapping, import descriptors/thunks, named and ordinal exports, forwarded-export markers | Delay imports, relocations, resources, certificate validation, CLR metadata |
| ELF | Yes | Yes | ELF32/ELF64 headers, endianness, section names, PT_LOAD and other program headers, PT_INTERP, PT_DYNAMIC tags, GNU build IDs, SHT_SYMTAB/SHT_DYNSYM symbols and SHT_REL/SHT_RELA relocation records | Extended numbering, relocation application, GNU symbol-version resolution, DWARF and architecture-specific relocation-name catalogs |
| Thin Mach-O | Yes | Yes | 32/64-bit header, CPU metadata, bounded load commands, LC_SEGMENT/LC_SEGMENT_64 sections and LC_CODE_SIGNATURE superblob/CodeDirectory metadata | Chained fixups, cryptographic trust verification, Objective-C metadata and other command payloads |
| Universal Mach-O | Yes | Yes | 32/64-bit fat architecture tables, bounded non-overlapping slices and per-slice thin Mach-O parsing | Architecture-specific semantic analysis beyond supported thin commands |
| WebAssembly | Yes | Yes | Version, section boundaries and custom section names | Type validation, instruction decoding, imports/exports semantics and decompilation |
| ZIP | Yes | Yes | End-of-central-directory discovery, bounded central-directory entries, method/flag metadata, unsafe path and symlink markers, local-header range checks | ZIP64, multi-disk, decompression, CRC verification and archive-bomb analysis |
| PDF | Yes | No | `%PDF-` prefix | Cross-reference parsing, object graph, incremental updates, embedded files and JavaScript inspection |
| PNG | Yes | No | Eight-byte PNG signature | Chunk validation, decompression and metadata |
| JPEG | Yes | No | JPEG SOI marker | Marker/segment parsing and image decoding |
| SQLite | Yes | No | Sixteen-byte database signature | Page layout, schema, WAL and freelist parsing |
| GZIP | Yes | No | GZIP magic | Header flags, decompression and trailer validation |

## Parser behavior

### PE/COFF

The parser supports PE32 and PE32+ optional-header layouts. It retains raw machine identifiers, reports known architecture names, identifies selected DLL characteristics and checks each section's raw byte range against the supplied buffer. File-backed RVAs are mapped through headers or section raw data; virtual zero-fill regions are not treated as file bytes. The import directory is decoded into DLL names and name/ordinal thunks. The export directory is decoded into names, ordinals, RVAs and forwarder strings. Descriptor, thunk, export and string work is bounded. The security directory is identified as a file-offset directory and is not dereferenced as an RVA. Delay imports, relocation application, resource trees, CLR metadata and certificate trust validation remain unsupported.

The registry initially treats the `MZ` prefix as a PE candidate. A DOS executable without a PE signature is therefore detected as candidate `PE` but correctly rejected by the PE parser.

### ELF

The parser validates class and byte order before selecting ELF32 or ELF64 layouts. It decodes bounded program-header tables and reports segment permissions, virtual and physical addresses, file/memory sizes and file-range validity. PT_INTERP strings, PT_DYNAMIC tags and GNU build IDs in PT_NOTE are extracted when their ranges are valid. SHT_SYMTAB and SHT_DYNSYM entries are decoded with linked string-table names; SHT_REL and SHT_RELA records retain target section, symbol index, relocation type and explicit addend where present. All count-driven tables have configurable limits. Section names are resolved only when the section-name table is valid. Large 64-bit offsets that cannot be represented as safe JavaScript numbers are not silently rounded. The parser does not apply relocations, resolve GNU symbol versions, interpret architecture-specific relocation names or decode DWARF.

### Mach-O

Thin Mach-O parsing validates magic, byte order, header size and each load command. LC_SEGMENT and LC_SEGMENT_64 decode segment ranges, protections and section records with count and file-range checks. LC_CODE_SIGNATURE reports bounded embedded-signature superblob slots and CodeDirectory metadata; it does not verify hashes, CMS signatures, certificates or trust. Universal Mach-O parsing decodes FAT/FAT64 architecture tables, rejects out-of-file and overlapping slices, and runs the thin parser against each bounded slice. Chained fixups, Objective-C metadata and other load-command payloads remain unsupported.

### ZIP

The parser locates the end-of-central-directory record in the permitted trailing window, validates single-disk metadata and reads each central-directory record within its declared range. It reports entry names, compression methods, encryption flags, size ratios, local-header range status and suspicious absolute or parent-traversal paths. It never extracts or decompresses content. ZIP64 sentinel values and multi-disk archives are rejected explicitly.

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
7. Explicit notes for structures not decoded.
8. A documented distinction between raw offsets, virtual addresses, RVAs and indices.

Do not use file extensions as a substitute for signature recognition. Extensions may be useful contextual metadata, but they are user-controlled labels.


## Indicator integration

Format parsers return structural facts only. A separate analyzer evaluates selected parsed fields without changing parser output. For PE, it reviews section permission combinations and raw-file ranges. For ZIP, it inspects entry path and symlink metadata. The static indicator catalogue is maintained in [`INDICATORS.md`](INDICATORS.md); those findings are triage leads and do not extend the parser's semantic coverage.
