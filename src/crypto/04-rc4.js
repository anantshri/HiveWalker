// rv.crypto — RC4 stream cipher, implemented from the published spec
// (Schneier, Applied Cryptography 2nd ed., §17.1). Symmetric: encrypt and
// decrypt are the same operation. Used by the Vista–Win10 1607 SAM hash
// layer and the pre-Vista LSA secret layer.
(function (RV) {
  'use strict';

  function rc4(key, data) {
    if (!key || key.length === 0) throw new Error('rc4: key required');
    // Key-scheduling algorithm
    const S = new Uint8Array(256);
    for (let i = 0; i < 256; i++) S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % key.length]) & 0xff;
      const t = S[i]; S[i] = S[j]; S[j] = t;
    }
    // Pseudo-random generation algorithm
    const out = new Uint8Array(data.length);
    let i = 0; j = 0;
    for (let n = 0; n < data.length; n++) {
      i = (i + 1) & 0xff;
      j = (j + S[i]) & 0xff;
      const t = S[i]; S[i] = S[j]; S[j] = t;
      out[n] = data[n] ^ S[(S[i] + S[j]) & 0xff];
    }
    return out;
  }

  RV.crypto = RV.crypto || {};
  RV.crypto.rc4 = rc4;
})(window.RV);
