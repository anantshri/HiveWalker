// rv.crypto — 3DES (DES-EDE) CBC decrypt for the XP/2003 LSA secret layer.
// Two-key EDE (encrypt-decrypt-encrypt with K1=K3) is what LSA uses; the
// LSA "LSA key" decrypt path feeds 16-byte keys where the first 8 bytes are
// K1 and the last 8 are K2 (K3 = K1).
(function (RV) {
  'use strict';

  const C = RV.crypto;

  /**
   * DES-EDE-CBC decrypt. key16 = K1‖K2 (K3 = K1). data must be a multiple
   * of 8 bytes. Returns plaintext of the same length (no unpadding).
   */
  function desEdeCbcDecrypt(key16, iv8, data) {
    if (key16.length !== 16) throw new Error('desEdeCbcDecrypt: key must be 16 bytes');
    if (iv8.length !== 8) throw new Error('desEdeCbcDecrypt: iv must be 8 bytes');
    if (data.length % 8 !== 0) throw new Error('desEdeCbcDecrypt: data must be a multiple of 8 bytes');
    const k1 = key16.subarray(0, 8);
    const k2 = key16.subarray(8, 16);
    const out = new Uint8Array(data.length);
    let prev = iv8;
    for (let i = 0; i < data.length; i += 8) {
      const block = data.subarray(i, i + 8);
      // EDE decrypt of one block: D(K1) then E(K2) then D(K3=K1)
      let b = C.desDecryptBlock(k1, block);
      b = C.desEncryptBlock(k2, b);
      b = C.desDecryptBlock(k1, b);
      for (let j = 0; j < 8; j++) out[i + j] = b[j] ^ prev[j];
      prev = block;
    }
    return out;
  }

  RV.crypto = RV.crypto || {};
  RV.crypto.desEdeCbcDecrypt = desEdeCbcDecrypt;
})(window.RV);
