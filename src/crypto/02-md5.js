// rv.crypto — MD5 message digest, implemented from RFC 1321.
//
// Used by the SysKey-era SAM hash decryption (RC4 key = MD5(bootkey ‖ …)) and
// the pre-Vista LSA secret key derivation.
(function (RV) {
  'use strict';

  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

  function md5(bytes) {
    const bitLen = bytes.length * 8;
    const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) << 6);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bitLen >>> 0, true);
    dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const M = new Uint32Array(16);

    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
      let a = a0, b = b0, c = c0, d = d0;
      for (let i = 0; i < 64; i++) {
        let f, g;
        if (i < 16)      { f = (b & c) | (~b & d);      g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);      g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d;               g = (3 * i + 5) % 16; }
        else             { f = c ^ (b | ~d);            g = (7 * i) % 16; }
        const t = (a + f + K[i] + M[g]) | 0;
        a = d; d = c; c = b;
        b = (b + ((t << S[i]) | (t >>> (32 - S[i])))) | 0;
      }
      a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
    }

    const out = new Uint8Array(16);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, a0 >>> 0, true);
    odv.setUint32(4, b0 >>> 0, true);
    odv.setUint32(8, c0 >>> 0, true);
    odv.setUint32(12, d0 >>> 0, true);
    return out;
  }

  RV.crypto = RV.crypto || {};
  RV.crypto.md5 = md5;
})(window.RV);
