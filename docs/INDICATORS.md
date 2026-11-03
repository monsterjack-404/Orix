# ORIX Static Indicator Catalogue

This catalogue documents the rule identifiers emitted by the local static indicator engine. Rules are deterministic functions over information already acquired by the inspector. They do not execute inspected files, resolve remote reputation, infer author intent or decide whether an artifact is malware.

## Output contract

Each finding has:

| Field | Meaning |
|---|---|
| `rule_id` | Stable identifier suitable for filtering and automation |
| `title` | Short human-readable rule name |
| `severity` | Triage priority: `critical`, `high`, `medium`, `low` or `info` |
| `confidence` | `observed`, `derived` or `heuristic` |
| `summary` | Contextual explanation, including important false-positive boundaries |
| `evidence` | Bounded source facts that caused the rule to match |

The current implementation emits no `critical` rules. A severity label is not a probability score. It does not estimate the likelihood that a file is malicious.

## Implemented rules

### `ORIX-FILE-STABILITY-001`

**Severity:** high. **Confidence:** observed.

The file size or modification metadata changed between the opened-file state and the post-read state. The report may contain a complete SHA-256 for the bytes read while its parsed prefix corresponds to a changing source. Preserve a stable copy and repeat the analysis before relying on the result.

### `ORIX-PARSER-STRUCTURE-001`

**Severity:** medium. **Confidence:** observed.

The signature registry selected a parser, but that parser rejected the supplied bytes with a typed error. Truncation, unsupported variants, corrupted files and false-positive signatures can all cause this result. Parser rejection is not proof of malicious modification.

### `ORIX-PE-WRITABLE-EXECUTABLE-001`

**Severity:** high. **Confidence:** derived.

A parsed PE section has both `write` and `execute` characteristics. This combination can be intentional in specialized software, runtime trampolines or packers. Review the section context and actual page protections before interpreting it.

### `ORIX-PE-SECTION-RANGE-001`

**Severity:** high. **Confidence:** observed.

A PE section declares a raw file range that does not fit inside the supplied analyzed bytes. The finding can result from corruption, truncation, an unsupported overlay layout or a malformed header. The current parser does not map virtual addresses to loaded memory.

### `ORIX-ZIP-UNSAFE-ENTRY-001`

**Severity:** high. **Confidence:** observed.

A ZIP central-directory entry uses an absolute path, a parent-traversal path component, or a Unix symbolic-link marker. This matters when another application extracts the archive without safe path normalization. ORIX reports metadata only and does not extract the entry.

### `ORIX-ZIP-ENCRYPTED-ENTRY-001`

**Severity:** info. **Confidence:** observed.

One or more ZIP entries are marked encrypted. The current parser does not decrypt content or validate the plaintext.

### `ORIX-ENTROPY-HIGH-001`

**Severity:** low. **Confidence:** heuristic.

The analyzed sample is at least 1,024 bytes and has Shannon entropy of at least 7.2 bits per byte. Compression, encrypted content, random test data and some media formats can naturally meet this threshold. Entropy alone is not a malware signal.

### `ORIX-STRINGS-PROCESS-MEMORY-001`

**Severity:** medium. **Confidence:** heuristic.

Bounded extracted strings exactly match selected API names associated with cross-process memory access or process creation. The names may occur in documentation, debug symbols, test fixtures or unused resources; they do not prove that the APIs are imported or called.

### `ORIX-STRINGS-CREDENTIAL-ACCESS-001`

**Severity:** medium. **Confidence:** heuristic.

Bounded extracted strings exactly match selected API names associated with credential enumeration or process-dump workflows. Context, symbol resolution and call-site analysis are outside the current release.

### `ORIX-PDF-ACTIVE-CONTENT-001`

**Severity:** medium. **Confidence:** observed.

The bounded PDF lexical scan found one or more JavaScript or action-related dictionary names: JavaScript, open actions, additional actions or launch actions. These are lexical markers, not a full PDF object-graph reachability analysis. They do not prove that an action is reachable, permitted by a viewer or executed.

### `ORIX-PDF-EMBEDDED-CONTENT-001`

**Severity:** info. **Confidence:** observed.

The bounded PDF lexical scan found embedded-file or file-specification markers. ORIX currently does not extract or inspect attachment contents through this parser. The marker does not prove an attachment is reachable or successfully extractable.

### `ORIX-PDF-ENCRYPTED-001`

**Severity:** info. **Confidence:** observed.

The parsed PDF metadata reports an encryption dictionary/reference. ORIX does not decrypt the document or validate plaintext content. Encryption metadata is not itself a malware signal.

## Ordering and limits

Findings are ordered by severity (`critical`, `high`, `medium`, `low`, `info`) and then by `rule_id`. Supporting string and archive-entry evidence is capped at 100 records per finding. The global file read, string extraction, parser count and directory scan ceilings continue to apply.

## Using findings responsibly

Use findings to prioritize a manual review. Correlate them with hashes, parser output, vendor documentation, build provenance and independent tooling. Do not block, quarantine or execute software solely because one heuristic rule matched. Do not treat an empty indicator list as a safety certification.
