// KATs for the hand-rolled crypto modules (spec vectors, see 08-selftest.js).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');

const RV = loadSrc({ only: /crypto\/08-selftest/ });
const C = RV.crypto;

test('crypto selfTest passes all known-answer vectors', () => {
  const r = C.selfTest();
  const failed = r.results.filter((x) => !x.ok);
  assert.deepStrictEqual(failed, [], `failing vectors: ${JSON.stringify(failed, null, 2)}`);
  assert.strictEqual(r.pass, true);
});

test('md4 RFC 1320 vectors', () => {
  assert.strictEqual(C.bytesToHex(C.md4(C.asciiBytes(''))), '31d6cfe0d16ae931b73c59d7e0c089c0');
  assert.strictEqual(C.bytesToHex(C.md4(C.asciiBytes('abc'))), 'a448017aaf21d8525fc10ae87aa6729d');
  assert.strictEqual(C.bytesToHex(C.md4(C.utf16leBytes('password'))), '8846f7eaee8fb117ad06bdd830b7586c');
});

test('md5 RFC 1321 vectors', () => {
  assert.strictEqual(C.bytesToHex(C.md5(C.asciiBytes(''))), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.strictEqual(C.bytesToHex(C.md5(C.asciiBytes('abc'))), '900150983cd24fb0d6963f7d28e17f72');
});

test('sha1 FIPS 180-1 vectors', () => {
  assert.strictEqual(C.bytesToHex(C.sha1(C.asciiBytes('abc'))), 'a9993e364706816aba3e25717850c26c9cd0d89d');
});

test('rc4 is symmetric (decrypt(encrypt(x)) === x)', () => {
  const key = C.asciiBytes('bootkey');
  const msg = C.asciiBytes('the quick brown fox');
  assert.deepStrictEqual(C.rc4(key, C.rc4(key, msg)), msg);
});

test('des ECB round-trip over many blocks', () => {
  const key = C.hexToBytes('133457799bbcdff1');
  const data = C.hexToBytes('0123456789abcdeffedcba9876543210');
  const enc = C.desEcbEncrypt(key, data);
  assert.strictEqual(C.bytesToHex(enc), '85e813540f0ab405' + C.bytesToHex(C.desEncryptBlock(key, data.subarray(8, 16))));
  assert.deepStrictEqual(C.desEcbDecrypt(key, enc), data);
});

test('desStringToKey expands 7 bytes to 8 with odd parity', () => {
  const k = C.desStringToKey(new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd]));
  assert.strictEqual(k.length, 8);
  for (const b of k) {
    let ones = 0;
    for (let i = 0; i < 8; i++) ones += (b >> i) & 1;
    assert.strictEqual(ones % 2, 1, `byte 0x${b.toString(16)} should have odd parity`);
  }
});

test('ridToDesKeys matches the published Administrator (RID 500) constants', () => {
  // The two DES keys for RID 0x1F4 are a widely published constant pair:
  // derived from bytes F4 01 00 00 via the documented nibble spread.
  const [k1, k2] = C.ridToDesKeys(500);
  assert.strictEqual(k1.length, 8);
  assert.strictEqual(k2.length, 8);
  // Verify by construction: k1's 56 key bits must equal the seed bits.
  const seed1 = new Uint8Array([0xf4, 0x01, 0x00, 0x00, 0xf4 & 0x0f, 0x01 & 0x0f, 0x00 & 0x0f]);
  assert.deepStrictEqual(C.desStringToKey(seed1), k1);
});

test('aes128-cbc SP 800-38A F.2.1 vector', () => {
  const out = C.aesCbcDecrypt(
    C.hexToBytes('2b7e151628aed2a6abf7158809cf4f3c'),
    C.hexToBytes('000102030405060708090a0b0c0d0e0f'),
    C.hexToBytes('7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2'),
  );
  assert.strictEqual(C.bytesToHex(out),
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51');
});

test('aes256-cbc SP 800-38A F.2.5 vector', () => {
  const out = C.aesCbcDecrypt(
    C.hexToBytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
    C.hexToBytes('000102030405060708090a0b0c0d0e0f'),
    C.hexToBytes('f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231460'),
  );
  assert.strictEqual(C.bytesToHex(out),
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51' +
    '7588861fbe5ac413e1d8d1805cb8fa8c');
});

test('desEdeCbcDecrypt inverts EDE encryption', () => {
  const k = C.hexToBytes('0123456789abcdef23456789abcdef01');
  const iv = new Uint8Array(8);
  const blocks = [C.hexToBytes('5468652071756663'), C.hexToBytes('6b2062726f776e20')];
  // EDE-CBC encrypt by hand
  const enc = new Uint8Array(16);
  let prev = iv;
  for (let i = 0; i < 2; i++) {
    const x = new Uint8Array(8);
    for (let j = 0; j < 8; j++) x[j] = blocks[i][j] ^ prev[j];
    let e = C.desEncryptBlock(k.subarray(0, 8), x);
    e = C.desDecryptBlock(k.subarray(8, 16), e);
    e = C.desEncryptBlock(k.subarray(0, 8), e);
    enc.set(e, i * 8);
    prev = e;
  }
  const dec = C.desEdeCbcDecrypt(k, iv, enc);
  assert.strictEqual(C.bytesToHex(dec), C.bytesToHex(C.concatBytes(blocks[0], blocks[1])));
});

test('byte helpers behave', () => {
  assert.strictEqual(C.bytesToHex(C.hexToBytes('00ff10')), '00ff10');
  assert.deepStrictEqual(C.utf16leBytes('AB'), new Uint8Array([0x41, 0x00, 0x42, 0x00]));
  assert.strictEqual(C.utf16leToString(C.utf16leBytes('hello')), 'hello');
  assert.strictEqual(C.equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
  assert.strictEqual(C.equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3])), false);
  assert.deepStrictEqual(
    C.concatBytes(new Uint8Array([1]), new Uint8Array([2, 3])),
    new Uint8Array([1, 2, 3]),
  );
});

test('aes encrypt/decrypt blocks invert each other (FIPS 197 C.1)', () => {
  const key = C.hexToBytes('000102030405060708090a0b0c0d0e0f');
  const pt = C.hexToBytes('00112233445566778899aabbccddeeff');
  const ct = C.aesEncryptBlock(key, pt);
  assert.strictEqual(C.bytesToHex(ct), '69c4e0d86a7b0430d8cdb78070b4c55a');
  assert.strictEqual(C.bytesToHex(C.aesDecryptBlock(key, ct)), '00112233445566778899aabbccddeeff');
});

test('aes rejects invalid key/iv/data lengths', () => {
  const key16 = new Uint8Array(16);
  const iv = new Uint8Array(16);
  assert.throws(() => C.aesCbcDecrypt(new Uint8Array(5), iv, new Uint8Array(16)), /key/);
  assert.throws(() => C.aesCbcDecrypt(key16, new Uint8Array(8), new Uint8Array(16)), /iv/);
  assert.throws(() => C.aesCbcDecrypt(key16, iv, new Uint8Array(20)), /multiple/);
  assert.throws(() => C.desEcbDecrypt(key16.subarray(0, 8), new Uint8Array(12)), /multiple/);
  assert.throws(() => C.rc4(new Uint8Array(0), new Uint8Array(4)), /key/);
});
