'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');

const { filetime } = loadSrc({ only: /02-filetime/ }).reg;

test('FILETIME 0 → null date, "(no timestamp)" text', () => {
  assert.strictEqual(filetime.filetimeToDate(0n), null);
  assert.strictEqual(filetime.formatFiletime(0n), '(no timestamp)');
});

test('Unix epoch maps to 1970-01-01T00:00:00Z', () => {
  const epoch = (11644473600000n * 10000n);
  assert.strictEqual(filetime.filetimeToMs(epoch), 0n);
  const d = filetime.filetimeToDate(epoch);
  assert.strictEqual(d.toISOString(), '1970-01-01T00:00:00.000Z');
});

test('known FILETIME renders UTC string (regrip time.pl parity)', () => {
  // 0x01D0C7A57F5A6C00 → 2015-07-26 13:18:01.390 UTC
  const ft = 0x01d0c7a57f5a6c00n;
  assert.strictEqual(filetime.formatFiletime(ft), '2015-07-26 13:18:01.390 UTC');
});

test('sub-ms ticks survive (BigInt, not float)', () => {
  const base = 0x01d0c7a57f5a6c00n;
  // 10 ticks = 1ms: integer division must still advance whole milliseconds
  assert.strictEqual(filetime.filetimeToMs(base + 10000n) - filetime.filetimeToMs(base), 1n);
  // Fewer than 10 ticks cannot cross a ms boundary by accident
  for (const t of [1n, 5n, 9n]) {
    const ms = filetime.filetimeToMs(base + t);
    assert.ok(ms === 1437916681390n || ms === 1437916681391n, `tick ${t} jumped: ${ms}`);
  }
});

test('far-future corrupt stamps clamp to null', () => {
  assert.strictEqual(filetime.filetimeToDate(0xffffffffffffffffn), null);
});

test('non-BigInt inputs rejected; negative maps before epoch (not an error)', () => {
  assert.throws(() => filetime.filetimeToDate(42), TypeError);
  assert.throws(() => filetime.filetimeToMs('x'), TypeError);
  // -1 tick = 100ns before 1601-01-01: representable, just very old
  const d = filetime.filetimeToDate(1n);
  assert.strictEqual(d.getUTCFullYear(), 1601);
});
