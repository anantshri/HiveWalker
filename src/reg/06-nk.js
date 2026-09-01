// rv.reg — nk (key node) records, version-dispatched by signature.
(function (RV) {
  'use strict';

  const { NK_LAYOUTS, KEY_COMP_NAME, LIMITS } = RV.reg.consts;
  const { BufferReader, RegistryParseError } = RV.reg;

  /**
   * @param {BufferReader} reader
   * @param {object} binMap
   * @param {number} rel offset of the nk cell (relative to first hbin)
   * @param {object} [ctx] {warnings: string[]} — collects soft failures
   * @returns {{rel:number, layout:string, flags:number, timestamp:bigint,
   *   parentRel:number|null, subkeyCount:number, subkeyListRel:number|null,
   *   valueCount:number, valueListRel:number|null, skRel:number|null,
   *   classNameRel:number|null, classNameLen:number, name:string,
   *   maxSubkeyNameLen:number, maxClassNameLen:number, maxValNameLen:number,
   *   maxValDataLen:number}}
   */
  function parseNk(reader, binMap, rel, ctx) {
    const warnings = ctx && ctx.warnings;
    const cell = RV.reg.cellAt(reader, binMap, rel);
    const dataAbs = cell.dataAbs;

    // Signature dispatch: classic "nk" vs Win10 1709+ "CM_KEY_NODE".
    let layout = null;
    for (const key of Object.keys(NK_LAYOUTS)) {
      const L = NK_LAYOUTS[key];
      if (reader.inBounds(dataAbs, L.sigLen) && reader.sig(dataAbs, L.sigLen) === L.sig) {
        layout = L;
        break;
      }
    }
    if (!layout) {
      const found = reader.inBounds(dataAbs, 4) ? reader.ascii(dataAbs, 4) : '????';
      throw new RegistryParseError(`expected nk record, found ${JSON.stringify(found)}`, dataAbs);
    }
    if (cell.size < layout.nameAt) {
      throw new RegistryParseError(`nk cell too small (${cell.size})`, dataAbs);
    }

    const flags = reader.u16(dataAbs + layout.flags);
    const timestamp = reader.u64(dataAbs + layout.timestamp);
    const parentRel = RV.reg.optOffset(reader.u32(dataAbs + layout.parent));
    const subkeyCount = reader.u32(dataAbs + layout.subkeyCount);
    const subkeyListRel = RV.reg.optOffset(reader.u32(dataAbs + layout.subkeyList));
    const valueCount = reader.u32(dataAbs + layout.valueCount);
    const valueListRel = RV.reg.optOffset(reader.u32(dataAbs + layout.valueList));
    const skRel = RV.reg.optOffset(reader.u32(dataAbs + layout.sk));
    const classNameRel = RV.reg.optOffset(reader.u32(dataAbs + layout.className));
    const nameLen = reader.u16(dataAbs + layout.nameLen);
    const classLen = reader.u16(dataAbs + layout.classLen);

    // Name: compressed flag → single-byte chars, else UTF-16LE.
    let name = '';
    const nameAvail = cell.size - layout.nameAt;
    const nameBytes = Math.min(nameLen, Math.max(0, nameAvail));
    if (nameBytes > 0) {
      if (flags & KEY_COMP_NAME) {
        name = reader.ascii(dataAbs + layout.nameAt, nameBytes);
      } else {
        name = reader.utf16le(dataAbs + layout.nameAt, nameBytes);
      }
    }
    if (nameLen > nameBytes && warnings) {
      warnings.push(`key name truncated (${nameBytes} of ${nameLen} bytes)`);
    }

    // 0xFFFFFFFF counts mean "none" (real hives use this on value-less keys);
    // anything else implausible degrades to a warning rather than failing.
    const effSubkeys = subkeyCount === 0xffffffff ? 0 : subkeyCount;
    const effValues = valueCount === 0xffffffff ? 0 : valueCount;
    const saneCounts =
      effSubkeys <= LIMITS.MAX_SUBKEYS_PER_NODE &&
      effValues <= LIMITS.MAX_VALUES_PER_NODE;
    if (!saneCounts && warnings) {
      warnings.push(`implausible counts (subkeys ${subkeyCount}, values ${valueCount})`);
    }

    return {
      rel,
      layout: layout.sig,
      flags,
      timestamp,
      parentRel,
      subkeyCount: saneCounts ? effSubkeys : 0,
      subkeyListRel,
      valueCount: saneCounts ? effValues : 0,
      valueListRel,
      skRel,
      classNameRel,
      classNameLen: classLen,
      name,
      maxSubkeyNameLen: reader.u32(dataAbs + layout.maxSubkeyLen),
      maxClassNameLen: reader.u32(dataAbs + layout.maxClassLen),
      maxValNameLen: reader.u32(dataAbs + layout.maxValNameLen),
      maxValDataLen: reader.u32(dataAbs + layout.maxValDataLen),
    };
  }

  RV.reg.parseNk = parseNk;
})(window.RV);
