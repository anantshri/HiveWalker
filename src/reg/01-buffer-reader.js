// rv.reg — the sole byte-access path for hive data. Every read is bounds-
// checked and throws RegistryParseError carrying the offending offset.
(function (RV) {
  'use strict';

  class RegistryParseError extends Error {
    constructor(message, offset) {
      super(offset == null ? message : `${message} (at offset 0x${offset.toString(16)})`);
      this.name = 'RegistryParseError';
      this.offset = typeof offset === 'number' ? offset : null;
    }
  }

  class BufferReader {
    /**
     * @param {ArrayBuffer|Uint8Array} buffer
     */
    constructor(buffer) {
      if (buffer instanceof Uint8Array) {
        this._bytes = buffer;
        this._view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      } else if (buffer instanceof ArrayBuffer) {
        this._bytes = new Uint8Array(buffer);
        this._view = new DataView(buffer);
      } else {
        throw new TypeError('BufferReader expects ArrayBuffer or Uint8Array');
      }
      this.length = this._bytes.length;
    }

    inBounds(offset, byteCount) {
      return (
        Number.isInteger(offset) && Number.isInteger(byteCount) &&
        offset >= 0 && byteCount >= 0 && offset + byteCount <= this.length
      );
    }

    _check(offset, byteCount, what) {
      if (!this.inBounds(offset, byteCount)) {
        throw new RegistryParseError(
          `${what} read of ${byteCount} byte(s) past end of buffer`, offset,
        );
      }
    }

    u8(offset) {
      this._check(offset, 1, 'u8');
      return this._view.getUint8(offset);
    }

    u16(offset) {
      this._check(offset, 2, 'u16');
      return this._view.getUint16(offset, true);
    }

    u32(offset) {
      this._check(offset, 4, 'u32');
      return this._view.getUint32(offset, true);
    }

    i32(offset) {
      this._check(offset, 4, 'i32');
      return this._view.getInt32(offset, true);
    }

    u64(offset) {
      this._check(offset, 8, 'u64');
      return this._view.getBigUint64(offset, true);
    }

    ascii(offset, byteCount) {
      this._check(offset, byteCount, 'ascii');
      let out = '';
      for (let i = 0; i < byteCount; i++) out += String.fromCharCode(this._bytes[offset + i]);
      return out;
    }

    utf16le(offset, byteCount) {
      this._check(offset, byteCount, 'utf16le');
      const n = byteCount - (byteCount % 2); // tolerate odd lengths
      let out = '';
      for (let i = 0; i < n; i += 2) {
        out += String.fromCharCode(this._view.getUint16(offset + i, true));
      }
      return out;
    }

    /** Copy — never a live view. */
    bytes(offset, byteCount) {
      this._check(offset, byteCount, 'bytes');
      return this._bytes.slice(offset, offset + byteCount);
    }

    /** ASCII signature used for record dispatch; length is sig length. */
    sig(offset, byteCount) {
      this._check(offset, byteCount, 'sig');
      return this.ascii(offset, byteCount);
    }
  }

  RV.reg.RegistryParseError = RegistryParseError;
  RV.reg.BufferReader = BufferReader;
})(window.RV);
