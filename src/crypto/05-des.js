// rv.crypto — DES block cipher + the SAM/NTLM per-RID key schedule.
// Implemented from FIPS 46-3 (IP/FP/E/P/S-box/PC-1/PC-2 tables) and the
// publicly documented NTLM 7-byte→8-byte string-to-key expansion
// (DCE/RPC 1.1 §13.5.2). Validated against the FIPS 81 worked example
// (key 133457799BBCDFF1, PT 0123456789ABCDEF → 85E813540F0AB405).
//
// Internals operate on JS strings of '0'/'1' — unambiguous and directly
// mirrors the spec's bit-level definitions. SAM/LSA payloads are tiny
// (a few blocks each), so the string overhead is irrelevant here.
(function (RV) {
  'use strict';

  const IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
  ];
  const FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
  ];
  const E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
  ];
  const P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
  ];
  const SBOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
  ];
  const PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
  ];
  const PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
  ];
  const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

  // ---- bit-string helpers ('0'/'1' chars, 1-based positions = index+1)

  function toBits(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(2).padStart(8, '0');
    return s;
  }

  function fromBits(s) {
    const out = new Uint8Array(s.length / 8);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 8, 8), 2);
    return out;
  }

  function permS(s, table) {
    let o = '';
    for (let i = 0; i < table.length; i++) o += s[table[i] - 1];
    return o;
  }

  function xorS(a, b) {
    let o = '';
    for (let i = 0; i < a.length; i++) o += (a[i] === b[i] ? '0' : '1');
    return o;
  }

  // ---- key schedule (FIPS 46-3 §3)

  function subKeys(key8) {
    const k = permS(toBits(key8), PC1);
    let c = k.substr(0, 28), d = k.substr(28, 28);
    const keys = [];
    for (let round = 0; round < 16; round++) {
      const s = SHIFTS[round];
      c = c.substr(s) + c.substr(0, s);
      d = d.substr(s) + d.substr(0, s);
      keys.push(permS(c + d, PC2));
    }
    return keys;
  }

  // ---- Feistel function f(R, K): E → ⊕K → S-boxes → P

  function f(R, K) {
    const x = xorS(permS(R, E), K);
    let s = '';
    for (let box = 0; box < 8; box++) {
      const g = x.substr(box * 6, 6);
      const row = parseInt(g[0] + g[5], 2);   // bits 1 and 6
      const col = parseInt(g.substr(1, 4), 2); // bits 2..5
      s += SBOX[box][row][col].toString(2).padStart(4, '0');
    }
    return permS(s, P);
  }

  function cryptBlock(key8, block8, decrypt) {
    const keys = subKeys(key8);
    if (decrypt) keys.reverse();
    const M = permS(toBits(block8), IP);
    let L = M.substr(0, 32), R = M.substr(32, 32);
    for (let round = 0; round < 16; round++) {
      const prev = R;
      R = xorS(L, f(R, keys[round])); // R' = L ⊕ f(R)
      L = prev;
    }
    return fromBits(permS(R + L, FP)); // pre-output is R16‖L16
  }

  function desEncryptBlock(key8, block8) { return cryptBlock(key8, block8, false); }
  function desDecryptBlock(key8, block8) { return cryptBlock(key8, block8, true); }

  /** ECB decrypt of n*8 bytes (SAM blobs are exact multiples; no padding). */
  function desEcbDecrypt(key8, data) {
    if (data.length % 8 !== 0) throw new Error('desEcbDecrypt: data must be a multiple of 8 bytes');
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 8) out.set(desDecryptBlock(key8, data.subarray(i, i + 8)), i);
    return out;
  }

  function desEcbEncrypt(key8, data) {
    if (data.length % 8 !== 0) throw new Error('desEcbEncrypt: data must be a multiple of 8 bytes');
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 8) out.set(desEncryptBlock(key8, data.subarray(i, i + 8)), i);
    return out;
  }

  /**
   * NTLM string-to-key: expand 7 key bytes into 8 with odd-parity stop bits
   * (DCE/RPC 1.1 §13.5.2 "7-byte to 8-byte key expansion"). The 56 bits are
   * copied into the high 7 bits of each output byte; the low bit of each byte
   * is set so the byte has odd parity.
   */
  function desStringToKey(seed7) {
    if (seed7.length !== 7) throw new Error('desStringToKey: 7 bytes required');
    let bits = '';
    for (let i = 0; i < 7; i++) bits += seed7[i].toString(2).padStart(8, '0');
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      let b = parseInt(bits.substr(i * 7, 7), 2) << 1;
      let ones = 0;
      for (let j = 0; j < 8; j++) ones += (b >> j) & 1;
      if (ones % 2 === 0) b |= 1;
      out[i] = b;
    }
    return out;
  }

  /**
   * SAM per-RID DES key schedule: the two keys used to encrypt the LM/NT
   * hash halves under 2000/XP/2003, and the inner layer of later versions.
   * Public fact documented in every SAM-decryption write-up (adsecurity.org,
   * libyal documentation): from the 4 little-endian RID bytes r0..r3 —
   *   key1 = strToKey(r0 r1 r2 r3 r0&0x0F r1&0x0F r2&0x0F)
   *   key2 = strToKey(r3 r0 r1 r2 r0>>4   r1>>4   r2>>4)
   */
  function ridToDesKeys(rid) {
    const r = [rid & 0xff, (rid >>> 8) & 0xff, (rid >>> 16) & 0xff, (rid >>> 24) & 0xff];
    const k1 = desStringToKey(new Uint8Array([r[0], r[1], r[2], r[3], r[0] & 0x0f, r[1] & 0x0f, r[2] & 0x0f]));
    const k2 = desStringToKey(new Uint8Array([r[3], r[0], r[1], r[2], r[0] >> 4, r[1] >> 4, r[2] >> 4]));
    return [k1, k2];
  }

  RV.crypto = RV.crypto || {};
  Object.assign(RV.crypto, {
    desEncryptBlock, desDecryptBlock, desEcbDecrypt, desEcbEncrypt,
    desStringToKey, ridToDesKeys,
  });
})(window.RV);
