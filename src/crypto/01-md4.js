// rv.crypto — MD4 message digest, implemented from RFC 1320.
//
// MD4 is required for NTLM hash extraction from the SAM hive (the NT hash is
// MD4 of the UTF-16LE password). It is broken for collision resistance but
// that is irrelevant here: we only compute it as a decryption layer.
(function (RV) {
  'use strict';

  function rol(x, c) { x >>>= 0; return ((x << c) | (x >>> (32 - c))) >>> 0; }

  // Word order per round (RFC 1320 §3): round 1 processes X[0..15] in order,
  // round 2 steps by 4, round 3 interleaves by 8/4/12. Shifts cycle per op.
  const R1_K = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
  const R1_S = [3, 7, 11, 19];
  const R2_K = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
  const R2_S = [3, 5, 9, 13];
  const R3_K = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
  const R3_S = [3, 9, 11, 15];

  function md4(bytes) {
    // RFC 1320 §3: pad to 56 mod 64 with 0x80 then zeros, append 64-bit LE bit length.
    const bitLen = bytes.length * 8;
    const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) << 6);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bitLen >>> 0, true);
    dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const X = new Array(16);

    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) X[i] = dv.getUint32(off + i * 4, true);
      let a = a0, b = b0, c = c0, d = d0;

      // Each op: v = rol(a + F(b,c,d) + X[k] (+const), s); then the four
      // words shift right: (a,b,c,d) = (d,a,b,c) — i.e. v lands in b's slot.
      const op = (v) => { const t = d; d = c; c = b; b = v; a = t; };

      // Round 1 — F(x,y,z) = (x&y) | (~x & z)
      for (let i = 0; i < 16; i++) {
        op(rol((a + ((b & c) | (~b & d)) + X[R1_K[i]]) >>> 0, R1_S[i % 4]));
      }
      // Round 2 — G(x,y,z) = (x&y) | (x&z) | (y&z)
      for (let i = 0; i < 16; i++) {
        op(rol((a + ((b & c) | (b & d) | (c & d)) + X[R2_K[i]] + 0x5a827999) >>> 0, R2_S[i % 4]));
      }
      // Round 3 — H(x,y,z) = x ^ y ^ z
      for (let i = 0; i < 16; i++) {
        op(rol((a + (b ^ c ^ d) + X[R3_K[i]] + 0x6ed9eba1) >>> 0, R3_S[i % 4]));
      }

      a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
    }

    const out = new Uint8Array(16);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, a0, true);
    odv.setUint32(4, b0, true);
    odv.setUint32(8, c0, true);
    odv.setUint32(12, d0, true);
    return out;
  }

  RV.crypto = RV.crypto || {};
  RV.crypto.md4 = md4;
})(window.RV);
