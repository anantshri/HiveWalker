'use strict';

// Byte-level mutation helpers for fuzz tests.

/** Flip one byte in a copy. */
function flipByte(buf, at) {
  const out = Uint8Array.from(buf);
  out[at] ^= 0xff;
  return out;
}

/** Truncate to n bytes. */
function truncate(buf, n) {
  return Uint8Array.from(buf.slice(0, n));
}

/** Zero a range in a copy. */
function zeroRange(buf, at, len) {
  const out = Uint8Array.from(buf);
  out.fill(0, at, Math.min(at + len, out.length));
  return out;
}

/** Seeded PRNG (mulberry32) — deterministic fuzz sequences. */
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

module.exports = { flipByte, truncate, zeroRange, mulberry32 };
