// rv.reg — tolerant UTF-16LE decoding + GUID formatting.
// Ports of RegRipper's rr_helper.pl getUnicodeStr / parseGUID behaviour.
(function (RV) {
  'use strict';

  const { LIMITS } = RV.reg.consts;

  /**
   * Decode UTF-16LE bytes to a JS string, stopping at the first NUL code unit
   * (the terminator REG_SZ/MULTI_SZ data carries). Tolerates: odd byte counts
   * (drops the trailing byte), lone surrogates (→ U+FFFD), missing terminator
   * (decodes everything), and caps output length.
   *
   * @param {Uint8Array} bytes
   * @param {{maxChars?: number, stopAtNul?: boolean}} [opts]
   */
  function decodeUtf16LE(bytes, opts) {
    const maxChars = (opts && opts.maxChars) || LIMITS.MAX_STRING_CHARS;
    const stopAtNul = !opts || opts.stopAtNul !== false;
    const n = bytes.length - (bytes.length % 2);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let out = '';
    for (let i = 0; i + 2 <= n && out.length < maxChars; i += 2) {
      const code = view.getUint16(i, true);
      if (stopAtNul && code === 0) break;
      if (code >= 0xd800 && code <= 0xdbff) {
        const lo = i + 4 <= n ? view.getUint16(i + 2, true) : NaN;
        if (lo >= 0xdc00 && lo <= 0xdfff) {
          out += String.fromCharCode(code, lo);
          i += 2;
        } else {
          out += '�';
        }
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        out += '�';
      } else {
        out += String.fromCharCode(code);
      }
    }
    return out;
  }

  /**
   * Render 16 bytes as {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} using the
   * mixed-endian GUID byte order (parseGUID port). Non-16-byte input → null.
   * @param {Uint8Array} bytes
   */
  function formatGuid(bytes) {
    if (!bytes || bytes.length !== 16) return null;
    const h = (b) => b.toString(16).padStart(2, '0');
    const p = (a) => a.map(h).join('');
    return (
      `{${p([bytes[3], bytes[2], bytes[1], bytes[0]])}` +
      `-${p([bytes[5], bytes[4]])}` +
      `-${p([bytes[7], bytes[6]])}` +
      `-${p([bytes[8], bytes[9]])}` +
      `-${p([bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])}}`
    );
  }

  RV.reg.decodeUtf16LE = decodeUtf16LE;
  RV.reg.formatGuid = formatGuid;
})(window.RV);
