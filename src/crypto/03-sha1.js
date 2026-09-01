// rv.crypto — SHA-1 digest, implemented from FIPS 180-1.
//
// Used by the Win10 1607+ SAM AES key derivation and the Win10+ LSA secret
// AES key schedule. Collision-broken, irrelevant for this use (decryption
// layer only).
(function (RV) {
  'use strict';

  function sha1(bytes) {
    const bitLen = bytes.length * 8;
    const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) << 6);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const dv = new DataView(padded.buffer);
    // 64-bit BE length; JS byte-length stays well under 2^53 bits in practice.
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    dv.setUint32(padded.length - 4, bitLen >>> 0);

    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const w = new Uint32Array(80);

    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 80; i++) {
        const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (x << 1) | (x >>> 31);
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      for (let i = 0; i < 80; i++) {
        let f, k;
        if (i < 20)      { f = (b & c) | (~b & d);           k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d;                    k = 0xca62c1d6; }
        const t = ((((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0);
        e = d; d = c;
        c = (b << 30) | (b >>> 2);
        b = a;
        a = t;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }

    const out = new Uint8Array(20);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, h0 >>> 0); odv.setUint32(4, h1 >>> 0); odv.setUint32(8, h2 >>> 0);
    odv.setUint32(12, h3 >>> 0); odv.setUint32(16, h4 >>> 0);
    return out;
  }

  RV.crypto = RV.crypto || {};
  RV.crypto.sha1 = sha1;
})(window.RV);
