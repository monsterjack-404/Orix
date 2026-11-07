import test from 'node:test';
import assert from 'node:assert/strict';
import { is_supported_bubblewrap_version } from '../src/providers/linux-isolation.mjs';

test('Linux provider isolation requires the Bubblewrap release that fixes CVE-2026-87766', () => {
  for (const version of ['bubblewrap 0.8.0', 'bubblewrap 0.9.0', 'bubblewrap 0.11.2']) {
    assert.equal(is_supported_bubblewrap_version(version), false, version + ' must be rejected');
  }

  for (const version of ['bubblewrap 0.12.0', 'bubblewrap 0.12.1', 'bubblewrap 0.13.0', 'bubblewrap 0.13.1', 'bubblewrap 1.0.0']) {
    assert.equal(is_supported_bubblewrap_version(version), true, version + ' must be accepted');
  }
});

test('Bubblewrap version parsing requires one complete, unambiguous version line', () => {
  for (const output of [
    'banner\nbubblewrap 0.13.1',
    'bubblewrap 0.13.1\nbanner',
    'bubblewrap 999999999999999999999999.0.0',
    'bubblewrap 0.13.1 extra',
  ]) {
    assert.equal(is_supported_bubblewrap_version(output), false, JSON.stringify(output));
  }

  assert.equal(is_supported_bubblewrap_version('bubblewrap 0.13.1\n'), true);
});

test('Linux provider isolation rejects malformed and prerelease Bubblewrap version output', () => {
  for (const output of [
    '',
    'bwrap 0.13.1',
    'bubblewrap unknown',
    'bubblewrap 0.12',
    'bubblewrap 0.12.0-rc1',
    'bubblewrap 0.12.0+vendor',
    null,
    0.13,
  ]) {
    assert.equal(is_supported_bubblewrap_version(output), false, String(output));
  }
});
