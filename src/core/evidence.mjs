// JavaScript, src/core/evidence.mjs, Node.js 20+, provenance-first finding records.

let evidence_counter = 0;

export function create_evidence({ kind, summary, source, offset = null, length = null, confidence = 'observed', details = {} }) {
  if (!kind || !summary || !source) throw new TypeError('Evidence requires kind, summary, and source');
  if (!['observed', 'derived', 'heuristic'].includes(confidence)) throw new TypeError('Invalid evidence confidence');
  if (offset !== null && (!Number.isSafeInteger(offset) || offset < 0)) throw new TypeError('Evidence offset must be a non-negative safe integer');
  if (length !== null && (!Number.isSafeInteger(length) || length < 0)) throw new TypeError('Evidence length must be a non-negative safe integer');
  evidence_counter += 1;
  return Object.freeze({
    id: `ev-${evidence_counter.toString(36).padStart(6, '0')}`,
    kind,
    summary,
    source,
    offset,
    length,
    confidence,
    details: structuredClone(details),
  });
}

export function reset_evidence_sequence_for_tests() {
  evidence_counter = 0;
}
