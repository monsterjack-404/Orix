// JavaScript, tests/fuzz-smoke.test.mjs, Node.js 20+, deterministic bounded parser mutation smoke test.

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze_known_format } from '../src/formats/index.mjs';

function create_generator(seed) {
  let state = seed >>> 0;
  return function next() {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}

const SIGNATURES = [
  buffer => buffer.set([0x4d,0x5a]),
  buffer => buffer.set([0x7f,0x45,0x4c,0x46]),
  buffer => buffer.set([0xcf,0xfa,0xed,0xfe]),
  buffer => buffer.set([0x64,0x65,0x78,0x0a,0x30,0x33,0x35,0x00]),
  buffer => buffer.set([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00]),
  buffer => buffer.set([0x50,0x4b,0x03,0x04]),
  buffer => buffer.set([137,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]),
];

test('signature-directed parser mutations remain bounded and return structured outcomes', () => {
  const random = create_generator(0x4f524958);
  const outcomes = new Map();
  for (let index = 0; index < 500; index += 1) {
    const length = 8 + (random() % 249);
    const buffer = Buffer.allocUnsafe(length);
    for (let offset = 0; offset < length; offset += 1) buffer[offset] = random() & 0xff;
    SIGNATURES[index % SIGNATURES.length](buffer);
    if (buffer.length > 5 && buffer.subarray(0, 4).toString('hex') === '7f454c46') {
      buffer[4] = (random() & 1) + 1;
      buffer[5] = (random() & 1) + 1;
    }
    const report = analyze_known_format(buffer, { max_sections: 64, max_commands: 64, max_wasm_sections: 64 });
    assert.ok(['parsed','rejected','not-supported'].includes(report.parser_status));
    assert.ok(report.detection.format);
    assert.doesNotThrow(() => JSON.stringify(report));
    const key = `${report.detection.format}:${report.parser_status}`;
    outcomes.set(key, (outcomes.get(key) ?? 0) + 1);
  }
  assert.ok(outcomes.size >= 5, `expected multiple parser outcomes, observed ${[...outcomes.keys()].join(', ')}`);
});
