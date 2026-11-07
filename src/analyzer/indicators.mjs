// JavaScript, src/analyzer/indicators.mjs, Node.js 20+, deterministic static indicator rules.

const API_GROUPS = [
  {
    rule_id: 'ORIX-STRINGS-PROCESS-MEMORY-001',
    title: 'Process-memory manipulation API names observed',
    severity: 'medium',
    names: ['VirtualAllocEx', 'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread', 'NtWriteVirtualMemory', 'QueueUserAPC'],
    explanation: 'Strings contain names commonly associated with cross-process memory operations. Static strings do not prove that the APIs are imported or called.',
  },
  {
    rule_id: 'ORIX-STRINGS-CREDENTIAL-ACCESS-001',
    title: 'Credential-access related API names observed',
    severity: 'medium',
    names: ['CredReadW', 'CredEnumerateW', 'LsaEnumerateLogonSessions', 'MiniDumpWriteDump'],
    explanation: 'Strings contain names associated with credential or process-dump workflows. Context and call-site analysis are required before drawing conclusions.',
  },
];

const SEVERITY_ORDER = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });

function make_indicator(rule_id, title, severity, confidence, summary, evidence = []) {
  return Object.freeze({
    rule_id,
    title,
    severity,
    confidence,
    summary,
    evidence: evidence.map(item => Object.freeze({ ...item })),
  });
}

function find_api_strings(strings, names) {
  const wanted = new Set(names.map(name => name.toLowerCase()));
  return strings.filter(item => wanted.has(item.value.toLowerCase()));
}

/**
 * Evaluate explainable, bounded rules over parser output and already-extracted
 * metrics. This function never executes a file and never assigns a malware verdict.
 */
export function evaluate_indicators({ format, parser_status, parsed, parser_error, entropy, strings = [], stable_during_read = true }) {
  const indicators = [];

  if (parser_status === 'rejected' && parser_error) {
    indicators.push(make_indicator(
      'ORIX-PARSER-STRUCTURE-001',
      'Recognized structure failed parser validation',
      'medium',
      'observed',
      `The ${format} parser rejected the supplied structure: ${parser_error.code}.`,
      [{ source: 'parser', code: parser_error.code, details: parser_error.details ?? null }],
    ));
  }

  if (!stable_during_read) {
    indicators.push(make_indicator(
      'ORIX-FILE-STABILITY-001',
      'Artifact metadata changed during acquisition',
      'high',
      'observed',
      'File size or modification metadata changed during the read; the resulting report may combine observations from different file states.',
      [{ source: 'file-metadata', field: 'stable_during_read', value: false }],
    ));
  }

  if (entropy && entropy.sample_size >= 1_024 && entropy.bits_per_byte >= 7.2) {
    indicators.push(make_indicator(
      'ORIX-ENTROPY-HIGH-001',
      'High-entropy byte sample',
      'low',
      'heuristic',
      `The analyzed sample has ${entropy.bits_per_byte} bits per byte of Shannon entropy. Compression, encryption and packed data can all produce this pattern.`,
      [{ source: 'entropy', sample_size: entropy.sample_size, bits_per_byte: entropy.bits_per_byte }],
    ));
  }

  if (format === 'PE' && parsed) {
    for (const section of parsed.sections ?? []) {
      const flags = new Set(section.characteristics ?? []);
      if (flags.has('write') && flags.has('execute')) {
        indicators.push(make_indicator(
          'ORIX-PE-WRITABLE-EXECUTABLE-001',
          'Writable and executable PE section',
          'high',
          'derived',
          `PE section ${section.name || `#${section.index}`} is marked both writable and executable. This can be intentional, but it deserves manual review.`,
          [{ source: 'pe-section', section_index: section.index, section_name: section.name, raw_offset: section.raw_offset, raw_size: section.raw_size }],
        ));
      }
      if (section.raw_range_valid === false) {
        indicators.push(make_indicator(
          'ORIX-PE-SECTION-RANGE-001',
          'PE section raw data lies outside the supplied file bytes',
          'high',
          'observed',
          `PE section ${section.name || `#${section.index}`} declares a raw range that is not fully present in the analyzed bytes.`,
          [{ source: 'pe-section', section_index: section.index, raw_offset: section.raw_offset, raw_size: section.raw_size }],
        ));
      }
    }
  }

  if (format === 'ZIP' && parsed) {
    const unsafe = (parsed.entries ?? []).filter(entry => entry.unsafe_path || entry.is_symlink);
    if (unsafe.length) {
      indicators.push(make_indicator(
        'ORIX-ZIP-UNSAFE-ENTRY-001',
        'ZIP contains unsafe path or symbolic-link entries',
        'high',
        'observed',
        `${unsafe.length} archive entr${unsafe.length === 1 ? 'y has' : 'ies have'} an absolute/parent-traversal path or symbolic-link marker. ORIX does not extract these entries.`,
        unsafe.slice(0, 100).map(entry => ({ source: 'zip-central-directory', entry_index: entry.index, name: entry.name, unsafe_path: entry.unsafe_path, is_symlink: entry.is_symlink })),
      ));
    }
    const encrypted = (parsed.entries ?? []).filter(entry => entry.encrypted);
    if (encrypted.length) {
      indicators.push(make_indicator(
        'ORIX-ZIP-ENCRYPTED-ENTRY-001',
        'Encrypted ZIP entries present',
        'info',
        'observed',
        `${encrypted.length} archive entr${encrypted.length === 1 ? 'y is' : 'ies are'} marked as encrypted; content was not decrypted or extracted.`,
        encrypted.slice(0, 100).map(entry => ({ source: 'zip-central-directory', entry_index: entry.index, name: entry.name, encrypted: true })),
      ));
    }
  }


  if (format === 'PDF' && parsed) {
    const active = parsed.active_content ?? {};
    const active_keys = ['javascript', 'open_actions', 'additional_actions', 'launch_actions'].filter(key => active[key]);
    if (active_keys.length) {
      indicators.push(make_indicator(
        'ORIX-PDF-ACTIVE-CONTENT-001',
        'PDF contains active-content action markers',
        'medium',
        'observed',
        'PDF dictionaries contain JavaScript or action-related names. These lexical markers do not prove that the content is reachable or will execute.',
        active_keys.map(key => ({ source: 'pdf-name-marker', marker: key, present: true })),
      ));
    }
    const attachment_keys = ['embedded_files', 'file_specifications'].filter(key => active[key]);
    if (attachment_keys.length) {
      indicators.push(make_indicator(
        'ORIX-PDF-EMBEDDED-CONTENT-001',
        'PDF contains embedded-file markers',
        'info',
        'observed',
        'PDF dictionaries contain embedded-file or file-specification names. ORIX does not extract attachments.',
        attachment_keys.map(key => ({ source: 'pdf-name-marker', marker: key, present: true })),
      ));
    }
    if (parsed.encrypted) {
      indicators.push(make_indicator(
        'ORIX-PDF-ENCRYPTED-001',
        'PDF encryption dictionary observed',
        'info',
        'observed',
        'The PDF trailer or scanned dictionary contains an encryption reference. ORIX does not decrypt document contents.',
        [{ source: 'pdf-trailer', encrypted: true }],
      ));
    }
  }

  for (const group of API_GROUPS) {
    const matches = find_api_strings(strings, group.names);
    if (matches.length) {
      indicators.push(make_indicator(
        group.rule_id,
        group.title,
        group.severity,
        'heuristic',
        group.explanation,
        matches.slice(0, 100).map(item => ({ source: 'extracted-string', value: item.value, encoding: item.encoding, offset: item.offset, length: item.length })),
      ));
    }
  }

  return indicators.sort((left, right) => SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity] || left.rule_id.localeCompare(right.rule_id));
}
