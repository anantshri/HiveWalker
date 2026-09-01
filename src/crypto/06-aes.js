// rv.crypto — AES-128/192/256 ECB block + CBC decrypt, implemented from
// FIPS 197 (§5.1 cipher, §5.3 inverse cipher) and SP 800-38A (CBC).
// Validated against FIPS 197 appendix C.1/C.3 and SP 800-38A F.2 vectors.
(function (RV) {
  'use strict';

  const SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ];
  const INV_SBOX = new Uint8Array(256);
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  function xtime(a) { return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff; }
  function gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) { if (b & 1) p ^= a; a = xtime(a); b >>= 1; }
    return p & 0xff;
  }

  /** Key expansion (FIPS 197 §5.2) into (Nr+1) 4-word round keys. */
  function expandKey(key) {
    const Nk = key.length / 4;
    if (Nk !== 4 && Nk !== 6 && Nk !== 8) throw new Error('AES key must be 16, 24 or 32 bytes');
    const Nr = Nk + 6;
    const w = [];
    for (let i = 0; i < Nk; i++) w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    for (let i = Nk; i < 4 * (Nr + 1); i++) {
      let t = w[i - 1].slice();
      if (i % Nk === 0) {
        // RotWord then SubWord then ⊕Rcon
        t = [SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]];
        t[0] ^= RCON[i / Nk - 1];
      } else if (Nk > 6 && i % Nk === 4) {
        t = t.map((x) => SBOX[x]);
      }
      w.push([w[i - Nk][0] ^ t[0], w[i - Nk][1] ^ t[1], w[i - Nk][2] ^ t[2], w[i - Nk][3] ^ t[3]]);
    }
    return { w, Nr };
  }

  // State is s[row][col]; input maps s[r][c] = block[4c+r] (FIPS 197 §3.4).

  function makeOps() {
    return {
      sub(s) { for (let i = 0; i < 4; i++) for (let j = 0; j < 4; j++) s[i][j] = SBOX[s[i][j]]; },
      isub(s) { for (let i = 0; i < 4; i++) for (let j = 0; j < 4; j++) s[i][j] = INV_SBOX[s[i][j]]; },
      // ShiftRows: row r rotates left by r; inverse rotates right by r.
      shift(s) { for (let r = 1; r < 4; r++) { const row = s[r].slice(); for (let c = 0; c < 4; c++) s[r][c] = row[(c + r) % 4]; } },
      ishift(s) { for (let r = 1; r < 4; r++) { const row = s[r].slice(); for (let c = 0; c < 4; c++) s[r][c] = row[(((c - r) % 4) + 4) % 4]; } },
      mix(s) {
        for (let c = 0; c < 4; c++) {
          const a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
          s[0][c] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
          s[1][c] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
          s[2][c] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
          s[3][c] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        }
      },
      imix(s) {
        for (let c = 0; c < 4; c++) {
          const a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
          s[0][c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
          s[1][c] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
          s[2][c] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
          s[3][c] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
        }
      },
    };
  }

  function loadState(block) {
    const s = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r][c] = block[4 * c + r];
    return s;
  }

  function dumpState(s) {
    const out = new Uint8Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[4 * c + r] = s[r][c];
    return out;
  }

  /** Encrypt one 16-byte block (FIPS 197 §5.1). */
  function encryptBlock(key, block) {
    const { w, Nr } = expandKey(key);
    const op = makeOps();
    const ark = (s, round) => { for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r][c] ^= w[round * 4 + c][r]; };
    const s = loadState(block);
    ark(s, 0);
    for (let round = 1; round < Nr; round++) { op.sub(s); op.shift(s); op.mix(s); ark(s, round); }
    op.sub(s); op.shift(s); ark(s, Nr);
    return dumpState(s);
  }

  /** Decrypt one 16-byte block (FIPS 197 §5.3 inverse cipher). */
  function decryptBlock(key, block) {
    const { w, Nr } = expandKey(key);
    const op = makeOps();
    const ark = (s, round) => { for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r][c] ^= w[round * 4 + c][r]; };
    const s = loadState(block);
    ark(s, Nr);
    for (let round = Nr - 1; round >= 1; round--) { op.ishift(s); op.isub(s); ark(s, round); op.imix(s); }
    op.ishift(s); op.isub(s); ark(s, 0);
    return dumpState(s);
  }

  /** AES-CBC decrypt (no unpadding — callers trim length prefixes). */
  function aesCbcDecrypt(key, iv, data) {
    if (key.length !== 16 && key.length !== 24 && key.length !== 32) throw new Error('aesCbcDecrypt: bad key length');
    if (iv.length !== 16) throw new Error('aesCbcDecrypt: iv must be 16 bytes');
    if (data.length % 16 !== 0) throw new Error('aesCbcDecrypt: data must be a multiple of 16 bytes');
    const out = new Uint8Array(data.length);
    let prev = iv;
    for (let i = 0; i < data.length; i += 16) {
      const dec = decryptBlock(key, data.subarray(i, i + 16));
      for (let j = 0; j < 16; j++) out[i + j] = dec[j] ^ prev[j];
      prev = data.subarray(i, i + 16);
    }
    return out;
  }

  RV.crypto = RV.crypto || {};
  RV.crypto.aesEncryptBlock = encryptBlock;
  RV.crypto.aesDecryptBlock = decryptBlock;
  RV.crypto.aesCbcDecrypt = aesCbcDecrypt;
})(window.RV);
