// rv.reg — typed value-data decoders + regedit-style display strings.
(function (RV) {
  'use strict';

  const {
    REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN,
    REG_LINK, REG_MULTI_SZ, REG_QWORD, BINARY_TYPES, VALUE_TYPE_NAMES, LIMITS,
  } = RV.reg.consts;

  /**
   * Decode raw bytes by value type.
   * @returns {{kind:'string'|'multi'|'number'|'binary', value:string|string[]|number|bigint|Uint8Array, note?:string}}
   */
  function decodeValue(type, raw) {
    const len = raw ? raw.length : 0;
    const view = len ? new DataView(raw.buffer, raw.byteOffset, raw.byteLength) : null;
    switch (type) {
      case REG_SZ:
      case REG_EXPAND_SZ:
      case REG_LINK:
        if (len === 0) return { kind: 'string', value: '' };
        if (len % 2 !== 0 && len < 2) return { kind: 'string', value: '', note: 'truncated' };
        return { kind: 'string', value: RV.reg.decodeUtf16LE(raw) };
      case REG_MULTI_SZ: {
        if (len === 0) return { kind: 'multi', value: [] };
        // Decode without stopping at NUL, then split on NUL.
        const full = RV.reg.decodeUtf16LE(raw, { stopAtNul: false }).split('\0');
        // Drop the trailing empty strings from the double terminator.
        while (full.length > 0 && full[full.length - 1] === '') full.pop();
        // A single leading empty string means the data was just terminators.
        if (full.length === 1 && full[0] === '') return { kind: 'multi', value: [] };
        return { kind: 'multi', value: full };
      }
      case REG_DWORD: {
        if (len !== 4) return { kind: 'binary', value: raw, note: `DWORD with ${len} bytes` };
        return { kind: 'number', value: view.getUint32(0, true) };
      }
      case REG_DWORD_BIG_ENDIAN: {
        if (len !== 4) return { kind: 'binary', value: raw, note: `DWORD_BE with ${len} bytes` };
        return { kind: 'number', value: view.getUint32(0, false) };
      }
      case REG_QWORD: {
        if (len !== 8) return { kind: 'binary', value: raw, note: `QWORD with ${len} bytes` };
        return { kind: 'number', value: view.getBigUint64(0, true) };
      }
      case REG_NONE:
        return { kind: 'binary', value: raw ?? new Uint8Array(0), note: len === 0 ? '(empty)' : undefined };
      default:
        // REG_BINARY and the three resource types.
        return { kind: 'binary', value: raw ?? new Uint8Array(0) };
    }
  }

  function hexPreview(raw, max = 16) {
    if (!raw || raw.length === 0) return '(zero-length binary value)';
    const n = Math.min(max, raw.length);
    let s = '';
    for (let i = 0; i < n; i++) s += raw[i].toString(16).padStart(2, '0') + ' ';
    return s.trim() + (raw.length > n ? ' …' : '');
  }

  /**
   * Regedit-style cell text for the values table.
   * @returns {{text:string, note?:string}}
   */
  function formatValueData(type, raw, opts) {
    const name = (opts && opts.name) || '';
    const decoded = decodeValue(type, raw);
    const typeName = VALUE_TYPE_NAMES[type] || `unknown (0x${type.toString(16)})`;
    switch (decoded.kind) {
      case 'string':
        return { text: decoded.value, note: decoded.note };
      case 'multi':
        return { text: decoded.value.join(' ¦ ') };
      case 'number':
        return {
          text: typeof decoded.value === 'bigint'
            ? decoded.value.toString()
            : String(decoded.value >>> 0),
          note: hexNumericNote(type, decoded.value),
        };
      case 'binary': {
        // GUID decoration for 16-byte binaries under GUID-ish names.
        if (raw && raw.length === 16 && /guid|classid|iid/i.test(name)) {
          const guid = RV.reg.formatGuid(raw);
          if (guid) return { text: `${guid}  (${hexPreview(raw)})` };
        }
        return { text: hexPreview(raw), note: decoded.note };
      }
      default:
        return { text: '' };
    }
  }

  function hexNumericNote(type, value) {
    if (type === REG_DWORD || type === REG_DWORD_BIG_ENDIAN) {
      return `0x${(typeof value === 'bigint' ? value : BigInt(value >>> 0)).toString(16).padStart(8, '0')}`;
    }
    if (type === REG_QWORD) {
      return `0x${value.toString(16).padStart(16, '0')}`;
    }
    return undefined;
  }

  RV.reg.decodeValue = decodeValue;
  RV.reg.formatValueData = formatValueData;
  RV.reg.hexPreview = hexPreview;
})(window.RV);
