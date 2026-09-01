'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');

const { decodeUtf16LE, formatGuid } = loadSrc({ only: /03-utf16/ }).reg;

const bytes = (pairs) => {
  const out = [];
  for (const c of pairs) {
    if (typeof c === 'number') { out.push(c & 0xff, (c >> 8) & 0xff); }
    else { out.push(c.charCodeAt(0) & 0xff, (c.charCodeAt(0) >> 8) & 0xff); }
  }
  return new Uint8Array(out);
};

test('decodes plain UTF-16LE and stops at NUL terminator by default', () => {
  assert.strictEqual(decodeUtf16LE(bytes(['h', 'i', 0, 0, 'j'])), 'hi');
});

test('stopAtNul:false decodes embedded NULs (MULTI_SZ pass)', () => {
  assert.strictEqual(
    decodeUtf16LE(bytes(['a', 0, 'b', 0, 0]), { stopAtNul: false }),
    'a\x00b\x00\x00',
  );
});

test('empty input → empty string', () => {
  assert.strictEqual(decodeUtf16LE(new Uint8Array(0)), '');
});

test('odd byte count drops the trailing byte', () => {
  assert.strictEqual(decodeUtf16LE(bytes(['o', 'k']).slice(0, 3)), 'o');
});

test('lone surrogates become U+FFFD, valid pairs decode', () => {
  // U+0041, lone high surrogate 0xD800, then valid pair 0xD83D 0xDE00 (😀)
  const b = bytes(['A', 0xd800, 0xd83d, 0xde00]);
  assert.strictEqual(decodeUtf16LE(b), 'A�\u{1F600}');
});

test('lone trailing low surrogate also becomes U+FFFD', () => {
  assert.strictEqual(decodeUtf16LE(bytes(['x', 0xdc00])), 'x�');
});

test('maxChars caps unbounded garbage', () => {
  const junk = new Uint8Array(2048).fill(0x41); // "AAAA..." as bytes
  const out = decodeUtf16LE(junk, { stopAtNul: false, maxChars: 10 });
  assert.strictEqual(out.length, 10);
});

test('formatGuid renders mixed-endian byte order (parseGUID port)', () => {
  // regedit-style GUID for bytes 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
  const b = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  assert.strictEqual(formatGuid(b), '{04030201-0605-0807-090a-0b0c0d0e0f10}');
});

test('formatGuid rejects wrong lengths', () => {
  assert.strictEqual(formatGuid(new Uint8Array(15)), null);
  assert.strictEqual(formatGuid(new Uint8Array(17)), null);
  assert.strictEqual(formatGuid(null), null);
});
