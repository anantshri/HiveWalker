// rv.crypto — shared byte helpers for the hand-rolled crypto modules.
//
// Zero-dependency constraint: everything runs from file:// with no crypto.subtle
// (not a secure context), so MD4/MD5/SHA-1/RC4/DES/AES are implemented from
// their published specifications (RFC 1320/1321, FIPS 180-1, FIPS 46-3,
// FIPS 197). Nothing here is transcribed from third-party code.
(function (RV) {
  'use strict';

  /** Lowercase hex, 2 chars per byte. */
  function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
  }

  function hexToBytes(hex) {
    const s = hex.length % 2 === 0 ? hex : '0' + hex;
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  function concatBytes() {
    let n = 0;
    for (let i = 0; i < arguments.length; i++) n += arguments[i].length;
    const out = new Uint8Array(n);
    let o = 0;
    for (let i = 0; i < arguments.length; i++) { out.set(arguments[i], o); o += arguments[i].length; }
    return out;
  }

  /** UTF-16LE encoding of a BMP string (the NTLM/SAM string encoding). */
  function utf16leBytes(str) {
    const out = new Uint8Array(str.length * 2);
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      out[i * 2] = c & 0xff;
      out[i * 2 + 1] = c >> 8;
    }
    return out;
  }

  function utf16leToString(bytes) {
    let out = '';
    const n = bytes.length - (bytes.length % 2);
    for (let i = 0; i < n; i += 2) {
      const c = bytes[i] | (bytes[i + 1] << 8);
      if (c === 0) break;
      out += String.fromCharCode(c);
    }
    return out;
  }

  function asciiBytes(str) {
    const out = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
    return out;
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  RV.crypto = RV.crypto || {};
  Object.assign(RV.crypto, {
    bytesToHex, hexToBytes, concatBytes, utf16leBytes, utf16leToString,
    asciiBytes, equalBytes,
  });
})(window.RV);
