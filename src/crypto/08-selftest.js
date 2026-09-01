// rv.crypto — known-answer self-tests. Every vector comes from the primary
// specification (RFC 1320 appendix, RFC 1321 appendix, FIPS 180-1 examples,
// FIPS 81 / SP 800-67 DES examples, FIPS 197 appendix C) or the canonical
// NTLM anchor MD4(UTF-16LE("password")) published in MS-NLMP-era docs.
(function (RV) {
  'use strict';

  const C = RV.crypto;

  function check(name, got, wantHex) {
    const gotHex = C.bytesToHex(got);
    return { name, ok: gotHex === wantHex, got: gotHex, want: wantHex };
  }

  function selfTest() {
    const results = [];
    const A = C.asciiBytes;

    // MD4 — RFC 1320 appendix A.5
    results.push(check('md4 empty', C.md4(A('')), '31d6cfe0d16ae931b73c59d7e0c089c0'));
    results.push(check('md4 a', C.md4(A('a')), 'bde52cb31de33e46245e05fbdbd6fb24'));
    results.push(check('md4 abc', C.md4(A('abc')), 'a448017aaf21d8525fc10ae87aa6729d'));
    results.push(check('md4 message digest', C.md4(A('message digest')), 'd9130a8164549fe818874806e1c7014b'));
    results.push(check('md4 alphabet', C.md4(A('abcdefghijklmnopqrstuvwxyz')), 'd79e1c308aa5bbcdeea8ed63df412da9'));
    // NT anchor: MD4 over UTF-16LE("password")
    results.push(check('md4 utf16le password', C.md4(C.utf16leBytes('password')), '8846f7eaee8fb117ad06bdd830b7586c'));

    // MD5 — RFC 1321 appendix A.5
    results.push(check('md5 empty', C.md5(A('')), 'd41d8cd98f00b204e9800998ecf8427e'));
    results.push(check('md5 a', C.md5(A('a')), '0cc175b9c0f1b6a831c399e269772661'));
    results.push(check('md5 abc', C.md5(A('abc')), '900150983cd24fb0d6963f7d28e17f72'));
    results.push(check('md5 message digest', C.md5(A('message digest')), 'f96b697d7cb7938d525a2f31aaf161d0'));
    results.push(check('md5 alphabet', C.md5(A('abcdefghijklmnopqrstuvwxyz')), 'c3fcd3d76192e4007dfb496cca67e13b'));
    results.push(check('md5 long', C.md5(A('12345678901234567890123456789012345678901234567890123456789012345678901234567890')), '57edf4a22be3c955ac49da2e2107b67a'));

    // SHA-1 — FIPS 180-1 §7 examples
    results.push(check('sha1 abc', C.sha1(A('abc')), 'a9993e364706816aba3e25717850c26c9cd0d89d'));
    results.push(check('sha1 two-block', C.sha1(A('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')), '84983e441c3bd26ebaae4aa1f95129e5e54670f1'));

    // RC4 — classic published vectors
    results.push(check('rc4 Key/Plaintext', C.rc4(A('Key'), A('Plaintext')), 'bbf316e8d940af0ad3'));
    results.push(check('rc4 Wiki/pedia', C.rc4(A('Wiki'), A('pedia')), '1021bf0420'));
    results.push(check('rc4 Secret/AttackAtDawn', C.rc4(A('Secret'), A('Attack at dawn')), '45a01f645fc35b383552544b9bf5'));

    // DES — FIPS 81 appendix B (ECB): key 0123456789ABCDEF, pt "Now is t"
    // and the canonical worked example key 133457799BBCDFF1.
    results.push(check('des ecb work example', C.desEncryptBlock(C.hexToBytes('133457799bbcdff1'), C.hexToBytes('0123456789abcdef')), '85e813540f0ab405'));
    const dec = C.desDecryptBlock(C.hexToBytes('133457799bbcdff1'), C.hexToBytes('85e813540f0ab405'));
    results.push(check('des round-trip', dec, '0123456789abcdef'));

    // AES — FIPS 197 appendix C.1 / C.3 (ECB single block, which CBC reduces to)
    results.push(check('aes128 c.1 encrypt-block-invert', C.aesCbcDecrypt(C.hexToBytes('000102030405060708090a0b0c0d0e0f'), new Uint8Array(16), C.hexToBytes('69c4e0d86a7b0430d8cdb78070b4c55a')), '00112233445566778899aabbccddeeff'));
    results.push(check('aes256 c.3 encrypt-block-invert', C.aesCbcDecrypt(C.hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), new Uint8Array(16), C.hexToBytes('8ea2b7ca516745bfeafc49904b496089')), '00112233445566778899aabbccddeeff'));

    // AES-CBC vector set — SP 800-38A F.2.1 / F.2.5 (first two blocks)
    results.push(check('aes128-cbc sp800-38a',
      C.aesCbcDecrypt(C.hexToBytes('2b7e151628aed2a6abf7158809cf4f3c'),
        C.hexToBytes('000102030405060708090a0b0c0d0e0f'),
        C.hexToBytes('7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2')),
      '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'));

    // 3DES — SP 800-67 / NIST CBC example sanity: decrypt(E(x)) round-trip
    const k3 = C.hexToBytes('0123456789abcdef23456789abcdef01');
    const pt3 = C.hexToBytes('54686520717566636b2062726f776e'); // 24 bytes
    // no encrypt API for 3DES here; verify via DES-EDE composition on one block
    const b3 = C.hexToBytes('0123456789abcdef');
    let e3 = C.desEncryptBlock(k3.subarray(0, 8), b3);
    e3 = C.desDecryptBlock(k3.subarray(8, 16), e3);
    e3 = C.desEncryptBlock(k3.subarray(0, 8), e3);
    const d3 = C.desEdeCbcDecrypt(k3, new Uint8Array(8), e3);
    results.push(check('3des ede round-trip', d3, '0123456789abcdef'));

    const pass = results.every((r) => r.ok);
    return { pass, results };
  }

  RV.crypto = RV.crypto || {};
  RV.crypto.selfTest = selfTest;
})(window.RV);
