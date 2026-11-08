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
| PCAP | Yes | Yes | Classic PCAP 2.4 global/packet framing, four endian/timestamp magic variants, bounded packet and byte budgets, Ethernet/VLAN, BSD DLT_NULL, Linux cooked, legacy/current raw-IP, best-effort IPv4/IPv6 endpoints and immediate TCP/UDP ports | IPv6 extension traversal, IP reassembly, checksum validation, application protocols, payload export and replay |
| UBIFS | Yes (little-endian node magic `31 18 10 06`) | Yes | Common node header and CRC for 4096-byte superblock and 512-byte master nodes; filesystem geometry, layout counts, root-index/journal/LPT pointers, space counters, flags, compression, UUID and authentication metadata inventory | Duplicate-master recovery selection, index/journal/LPT/orphan traversal, HMAC/hash verification, inode/directory/data decoding and extraction |
| UBI | Yes (`UBI#`) | Yes | EC/VID headers, CRC checks, explicit-geometry PEB scan and opt-in layout-volume table decoding with record CRCs, names, volume types, reservations, flags and duplicate-copy comparison | Fastmap semantics, PEB attach/recovery selection, volume payload CRC validation and volume payload decoding |
| cramfs | Yes (`45 3d cd 28` / `28 cd 3d 45`) | Yes | Superblock and root inode, endian detection, signature, declared filesystem size, flags, root-directory mode and root data-offset bounds | Compressed block decoding, directory traversal, file inode analysis, extraction and reconstruction |
| SquashFS | Yes (`hsqs` / `sqsh`) | Yes | SquashFS v4.0 superblock, endian detection, block geometry, compression ID/flags, declared filesystem size and bounded ID/xattr/inode/directory/fragment/export table offsets | Metadata block decompression, inode/directory traversal, fragment and xattr decoding, file extraction and filesystem reconstruction |
| PCAPNG | Yes | Yes | Section headers and byte order, block-length/trailer validation, interface descriptions/options, enhanced/obsolete/simple packet metadata, timestamp resolution/offset, name-resolution record counts, interface statistics and decryption-secret block inventory without secret contents | IPv6 extension traversal, IP reassembly, checksum validation, application protocols, payload export and replay |
| ZIP | Yes | Yes | EOCD, ZIP64 EOCD/locator, central directory, ZIP64 per-entry sizes/offsets, path/symlink flags, local data ranges and encryption metadata | Multi-disk archives, bounded decompression/extraction and CRC verification |
| DEX | Yes | Yes | DEX 035/037/038/039/040 header/map, bounded Modified UTF-8 strings, string/type/prototype/field/method identifiers, class-data indexes, code_item register/instruction/try/catch boundaries, Adler-32 and SHA-1 recomputation | Instruction decoding, control-flow analysis, annotation/debug-program decoding, decompilation, publisher authentication |
| Android APK (ZIP subtype) | Yes (validated ZIP + AndroidManifest.xml) | Yes | Bounded ZIP inventory, stored/raw-DEFLATE manifest and DEX entry inspection with CRC32 checks, binary-XML manifest metadata, multidex/native paths, semantic DEX string/type/prototype/field/method/class-data/code-item inventory, Adler-32/SHA-1 recomputation, v1 filename hints and APK Signing Block pair/ID inventory (v2/v3/v3.1) | DEX opcode/control-flow decoding, resource/intent-filter resolution, cryptographic APK signature and certificate-chain verification, runtime behavior |
| Android App Bundle (AAB) | ZIP layout, AAPT2 protobuf manifest, BundleConfig.pb and resources.pb | Partial metadata inventory | Bounded per-module path counts; AAPT2 XmlNode manifest fields, permissions and components; bounded BundleConfig tool version/type, compression, split and optimization metadata; bounded resources.pb package/type/entry/resource-ID/visibility/configuration/value-kind inventory with protobuf field/item/depth/string/output and per-entry/aggregate byte budgets | Full reference resolution, complete compound values, compiled resource-file decoding, dependency and split/install relationships, installability verdicts, cryptographic signature verification |
| PDF | Yes | Yes | PDF 1.x header, classic xref tables, trailer metadata, incremental /Prev chain, indirect-object framing, encryption and active-content lexical triage | Xref-stream entries, object streams, filters/decompression, page-tree semantics, attachment extraction and digital-signature verification |
| PNG | Yes | Yes | Signature, IHDR fields, chunk boundaries/order, PLTE-before-tRNS ordering, bit-depth-bounded grayscale/truecolor tRNS samples, IDAT sequence, IEND and bounded CRC validation | IDAT inflation, scanline/pixel decoding, color management and full ancillary-chunk semantics |
| JPEG | Yes | No | JPEG SOI marker | Marker/segment parser and metadata |
| SQLite | Yes | No | Sixteen-byte database signature | Page layout, schema, WAL and freelist parsing |
| GZIP | Yes | Yes | Bounded DEFLATE members, optional header fields/FHCRC, CRC32 and ISIZE verification, concatenated members and nested CPIO newc/TAR parsing | Other compression methods, arbitrary nested-format recursion, extraction and trailing-data recovery |
| CPIO newc | Yes | Yes | 070701 and 070702 headers, bounded entry/name/data ranges, file types, path safety, duplicate inventory, trailer detection and CRC-newc byte-sum verification | Extraction, concatenated archives, filesystem semantics and symlink/hardlink resolution |
| TAR | Yes | Yes | Header checksums, octal/base-256 fields, bounded file ranges, path safety, PAX records, GNU long names/links and end markers | Legacy V7-only headers, sparse maps, ACLs/xattrs, extraction and filesystem reconstruction |

The registry recognizes PE from the MZ prefix as a candidate. A DOS executable without a PE signature is therefore reported as a PE candidate and rejected by the PE parser. This is intentional candidate recognition, not proof of PE structure.

## Parser behavior and boundaries

### PE / COFF

The parser supports PE32 and PE32+ optional-header layouts. It retains raw machine identifiers, reports known architecture names, identifies selected DLL characteristics and checks section raw-byte ranges against the supplied buffer. File-backed RVAs are mapped through headers or section raw data; virtual zero-fill regions are not treated as file bytes.

The import directory is decoded into DLL names and name/ordinal thunks. Delay imports support RVA-based and safely convertible VA-based descriptors, including name/ordinal thunks and termination state. Base-relocation blocks and records include HIGHLOW, HIGHADJ and DIR64 metadata; relocations are not applied. Exports include names, ordinals, RVAs and forwarder strings. Resource directories are traversed with depth, entry and UTF-16 name limits. Resource data is reported by RVA and file range without extraction. The security directory is treated as a file offset and WIN_CERTIFICATE framing is decoded.

The CLR runtime directory is inspected as a bounded IMAGE_COR20_HEADER and BSJB metadata root. ORIX reports runtime version, metadata version, stream names/ranges, selected CLR flags and entry-point token. Stream ranges must remain inside the declared metadata root. This is a CLR assembly indicator and metadata-layout inventory only: metadata tables, signatures, method bodies, IL instructions, resources and PDB symbols are not decoded, and no decompilation or execution occurs.

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

### PCAPNG

The parser reads Section Header Blocks with per-section byte order, validates block lengths and trailing-length copies, resets interface indexes at section boundaries, and indexes Interface Description, Enhanced Packet, obsolete Packet, Simple Packet, Name Resolution, Interface Statistics and Decryption Secrets blocks under input, block, interface, packet, option and secret-metadata ceilings. Interface timestamp resolution and offsets are retained; packet payload bytes and decryption secret contents are never returned. Supported link-layer frames reuse the bounded classic-PCAP network metadata decoder for IPv4/IPv6 endpoints and immediate TCP/UDP ports. Name-resolution values are counted but not retained. Unknown blocks are length-validated and inventoried without interpreting their payloads. IPv6 extension traversal, reassembly, checksum validation, application protocols, payload export and replay remain unsupported.

### GZIP

The parser reads bounded RFC 1952 members using raw DEFLATE, validates optional extra/name/comment framing, reserved flags, optional header CRC16, trailer CRC32 and ISIZE, and supports concatenated members. Decompressed output is capped per member and across the stream, hashed with SHA-256 and not written to disk. If the combined output begins with CPIO newc/CRC-newc, the bounded CPIO parser is applied; other nested signatures are identified only. Trailing bytes after the last complete member are reported and make the stream incomplete.

### UBIFS

The parsers recognize the little-endian UBIFS node magic. The superblock parser validates one 4096-byte superblock node: common-header fields, node type, group type, node length, CRC-32 over bytes 8 through the declared node end, reserved padding, key format, filesystem flags, minimum I/O size, LEB geometry/counts, journal/LPT/orphan layout counts, fanout, format version, compression identifier, UUID and authentication metadata presence. An explicit aligned offset can select a superblock node inside a supplied buffer. HMACs and hashes are only inventoried, not verified. Master-node records are decoded by a separate bounded parser; duplicate-master selection, index trees, journal, LPT, orphan records, inode/directory/data nodes and file payloads are not traversed.

The master-node parser validates one fixed 512-byte master node, decodes committed root-index and journal/LPT references, commit/sequence ordering, space counters and optional cross-checks against caller-supplied superblock geometry. It inventories root-index/LPT hashes and HMAC presence without verifying them. It does not select between the duplicate master nodes stored on flash or perform recovery.

### UBI

The parser validates the 64-byte UBI erase-counter (EC) header and, when present at its declared offset, the 64-byte volume-identifier (VID) header. It checks big-endian fields, supported header version, EC/VID header CRCs, volume type and geometry offsets. Multi-PEB inventory is performed only when the caller supplies an explicit physical eraseblock size; no geometry is guessed. The parser does not decode layout-volume table records, fastmap payloads, additional UBIFS nodes or volume data.

### cramfs

The parser validates the cramfs superblock and embedded root inode in either byte order. It checks the fixed signature, declared image size, filesystem flags, block count plausibility, root directory mode and root data offset. It does not traverse directory entries, decode other inodes, decompress blocks, or extract files.

### SquashFS

The parser validates the 96-byte SquashFS v4.0 superblock in little- or big-endian form, checks block-size/log consistency, inode and ID-count constraints, declared filesystem size and top-level metadata-table offsets. Known compression IDs and feature flags are inventoried; unknown compression IDs remain explicitly unknown. The parser does not decompress metadata blocks, decode inode or directory records, inspect file payloads, or extract files. Table offsets are range-checked but are not interpreted as proof of a valid filesystem.

### TAR (USTAR-compatible)

The parser validates 512-byte USTAR-compatible headers and unsigned or signed header checksums, accepts octal and positive base-256 numeric fields, bounds declared entry sizes and aggregate data, and inventories path/type/ownership/mode/link metadata without reading or extracting file payloads. POSIX PAX local/global records and GNU long-name/long-link extension headers are interpreted under strict metadata and record ceilings. Absolute paths, drive-prefixed names and parent-directory segments are marked unsafe; duplicate paths are reported. A complete archive requires two consecutive zero end blocks. Legacy V7-only headers, GNU sparse maps, ACLs/xattrs, filesystem reconstruction and extraction are not implemented.

### CPIO newc

The parser supports raw `070701` newc and `070702` CRC-newc streams. It validates the fixed 110-byte header, hexadecimal fields, NUL-terminated names (non-UTF-8 names are retained as unsafe inventory records), four-byte alignment, declared file ranges, entry/name/aggregate byte ceilings and the trailer marker. CRC-newc entries are verified using the format byte-sum. Absolute paths, drive-prefixed names, backslash paths and parent-directory segments are marked unsafe; duplicate names are reported. The parser never extracts or executes entries. Trailing bytes after the first trailer are reported, not interpreted as a second archive.

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

New formats should be prioritized by user demand, ecosystem impact, available authoritative specifications, fixture quality, independent validation tools and safe parser boundaries. Candidate areas include deeper SquashFS metadata decoding, cramfs directory/block decoding, deeper UBIFS index/journal/LPT decoding and UBI volume-table decoding, additional executable formats, container/image metadata and common database formats. Recognition may be added before parsing only when the CLI and reports clearly label it signature-only.

### Android APK and DEX

APK analysis is selected only after the ZIP central directory has been structurally parsed and an exact `AndroidManifest.xml` entry is present. The parser reads only that manifest and `classes*.dex` entries, under per-entry and aggregate decompression ceilings. It supports stored and raw-DEFLATE entries; verifies decompressed entry CRC32 plus local-header name, flags, method and (when no data descriptor is present) CRC/size metadata; and rejects unsupported compression methods, encrypted entries, unsafe paths, symlinks, invalid local ranges and size mismatches.

The standalone `analyze_android_package` inventory does not extract entries to the filesystem. It expands selected stored and raw-DEFLATE manifest/DEX/BundleConfig/resources.pb entries in memory only, after checking local/central names, general-purpose flags, compression method, declared sizes and CRC32. Per-entry and aggregate output ceilings (`max_manifest_bytes`, `max_manifest_total_bytes`, `max_dex_entry_bytes`, `max_dex_total_bytes`, `max_bundle_config_bytes`) bound decompression; encrypted, malformed, unsafe and unsupported-compression entries are not parsed. Duplicate paths remain ambiguous and are not analyzed. The DEX parser validates versions 035/037/038/039/040, fixed-table bounds/non-overlap, map metadata, Modified UTF-8 strings, identifier/prototype references, class-data member indexes, method ownership and bounded `code_item`/try-handler structures; it recomputes DEX Adler-32 and SHA-1 fields. APK Signing Block framing, pair lengths, known v2/v3/v3.1 IDs, unknown IDs and duplicates are inventoried, but signatures, content digests, certificates and publisher identity are not verified. AAB reports decode each bounded module manifest using the AAPT2 Resources.XmlNode protobuf message and expose package/version, min/target/max SDK levels, permissions, application attributes and components. The decoder validates protobuf wire framing, UTF-8, oneof structure and field/node/depth/string budgets. BundleConfig.pb metadata is decoded by a bounded `android.bundle.BundleConfig` parser, including BundleTool version, bundle type, compression globs, master-resource hints, optimization/split settings, APEX/asset-module settings and locale configuration. AAPT2 `resources.pb` is now decoded into bounded package, type, entry, resource-ID, visibility, configuration qualifier and item/compound value-kind inventories. The parser skips and counts unknown wire-valid fields and applies per-entry/aggregate byte, protobuf field, repeated-item, depth, per-string, aggregate-string and output ceilings. It does not resolve references, fully decode compound values, decode compiled resource files or infer module/split installability. The CLI command is `orix android <app.apk|app.aab>`; the API and workspace-confined MCP tool expose the same bounded report. No inspected application code is executed.
