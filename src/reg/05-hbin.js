// rv.reg — hbin directory + cell access.
//
// Cell offsets stored inside records (subkey lists, value lists, nk parent
// pointers, data offsets) are relative to the *first hbin*, which begins at
// absolute file offset 4096. A cell starts with an i32 size; a negative size
// means the cell is in use (allocated), positive means free. The record
// ("nk", "vk", "lf"…) begins immediately after those 4 bytes.
(function (RV) {
  'use strict';

  const { SIG, NO_OFFSET, LIMITS } = RV.reg.consts;
  const { BufferReader, RegistryParseError } = RV.reg;

  const FIRST_HBIN_ABS = LIMITS.REGF_BLOCK_SIZE; // 4096

  /** Normalise the 0xffffffff "no offset" sentinel to null. */
  function optOffset(u32) {
    return u32 === NO_OFFSET ? null : u32;
  }

  /**
   * Walk hbin blocks from file offset 4096 while the signature holds.
   * @returns {{fileOffset:number, relOffset:number, size:number, timestamp:bigint}[]}
   */
  function scanHiveBins(reader) {
    const bins = [];
    let abs = FIRST_HBIN_ABS;
    while (abs + 0x20 <= reader.length) {
      if (reader.sig(abs, 4) !== SIG.HBIN) break;
      const selfRel = reader.u32(abs + 0x04);
      const size = reader.u32(abs + 0x08);
      if (size === 0 || size % LIMITS.HBIN_SIZE !== 0) break; // corrupt size
      if (selfRel !== abs - FIRST_HBIN_ABS) break; // sanity: must match position
      if (abs + size > reader.length) {
        // Truncated final hbin: still record what's readable.
        bins.push({
          fileOffset: abs,
          relOffset: selfRel,
          size: reader.length - abs,
          timestamp: reader.u64(abs + 0x18),
          truncated: true,
        });
        break;
      }
      bins.push({ fileOffset: abs, relOffset: selfRel, size, timestamp: reader.u64(abs + 0x18) });
      abs += size;
    }
    return bins;
  }

  /**
   * Directory of valid absolute file-offset ranges, used to reject cells
   * pointing outside any hbin (e.g. into the base block or past EOF).
   */
  function buildBinMap(bins) {
    const ranges = bins.map((b) => [b.fileOffset, b.fileOffset + b.size]);
    return {
      count: bins.length,
      totalBytes: bins.reduce((n, b) => n + b.size, 0),
      contains(abs, len) {
        return ranges.some(([lo, hi]) => abs >= lo && abs + len <= hi);
      },
    };
  }

  /**
   * Read a cell header at a hive-relative offset.
   * @param {BufferReader} reader
   * @param {object} binMap from buildBinMap
   * @param {number} rel offset relative to first hbin
   * @returns {{abs:number, size:number, allocated:boolean, dataAbs:number}}
   */
  function cellAt(reader, binMap, rel) {
    if (rel === null || rel === undefined || rel < 0) {
      throw new RegistryParseError(`invalid cell offset ${rel}`, null);
    }
    const abs = FIRST_HBIN_ABS + rel;
    if (!binMap.contains(abs, 8)) {
      throw new RegistryParseError(`cell offset 0x${rel.toString(16)} outside hive bins`, abs);
    }
    const raw = reader.i32(abs);
    const size = Math.abs(raw);
    if (size < 5) {
      throw new RegistryParseError(`implausible cell size ${size}`, abs);
    }
    return {
      abs,
      size,
      allocated: raw < 0,
      dataAbs: abs + 4,
    };
  }

  RV.reg.optOffset = optOffset;
  RV.reg.scanHiveBins = scanHiveBins;
  RV.reg.buildBinMap = buildBinMap;
  RV.reg.cellAt = cellAt;
  RV.reg.FIRST_HBIN_ABS = FIRST_HBIN_ABS;
})(window.RV);
