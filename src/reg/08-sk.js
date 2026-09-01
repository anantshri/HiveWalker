// rv.reg — sk (security) cells. The viewer surfaces refcount; the svcacls
// plugin additionally consumes the raw self-relative security descriptor via
// readSkDescriptor.
(function (RV) {
  'use strict';

  const { SK_LAYOUTS } = RV.reg.consts;

  // Descriptor bytes start right after the header: 0x14 for classic 'sk',
  // 0x1d for CM_KEY_SECURITY (sig is 11 bytes + 4 fields).
  const DESCRIPTOR_OFFSETS = Object.freeze({ sk: 0x14, CM_KEY_SECURITY: 0x1d });

  /**
   * @returns {{rel:number, prevRel:number|null, nextRel:number|null,
   *   refCount:number, descriptorLen:number}|null} null when rel is null
   */
  function parseSk(reader, binMap, rel) {
    if (rel == null) return null;
    const cell = RV.reg.cellAt(reader, binMap, rel);
    const dataAbs = cell.dataAbs;
    let layout = null;
    for (const key of Object.keys(SK_LAYOUTS)) {
      const L = SK_LAYOUTS[key];
      if (reader.inBounds(dataAbs, L.sigLen) && reader.sig(dataAbs, L.sigLen) === L.sig) {
        layout = L;
        break;
      }
    }
    if (!layout) return { rel, prevRel: null, nextRel: null, refCount: 0, descriptorLen: 0, unknown: true };
    return {
      rel,
      prevRel: RV.reg.optOffset(reader.u32(dataAbs + layout.prev)),
      nextRel: RV.reg.optOffset(reader.u32(dataAbs + layout.next)),
      refCount: reader.u32(dataAbs + layout.refCount),
      descriptorLen: reader.u32(dataAbs + layout.descriptorLen),
    };
  }

  /**
   * Read the raw self-relative SECURITY_DESCRIPTOR bytes from an sk cell.
   * Never throws: returns {rel, unknown:true} when the cell is unrecognised
   * or the descriptor would run past the hive bounds.
   * @returns {{rel:number, descriptor:Uint8Array, refCount:number,
   *   descriptorLen:number}|{rel:number, unknown:true}|null}
   */
  function readSkDescriptor(reader, binMap, rel) {
    if (rel == null) return null;
    const cell = RV.reg.cellAt(reader, binMap, rel);
    const dataAbs = cell.dataAbs;
    for (const key of Object.keys(SK_LAYOUTS)) {
      const L = SK_LAYOUTS[key];
      if (!(reader.inBounds(dataAbs, L.sigLen) && reader.sig(dataAbs, L.sigLen) === L.sig)) continue;
      const descLen = reader.u32(dataAbs + L.descriptorLen);
      const descAbs = dataAbs + DESCRIPTOR_OFFSETS[key];
      if (descLen === 0 || !reader.inBounds(descAbs, descLen)) {
        return { rel, unknown: true };
      }
      return {
        rel,
        refCount: reader.u32(dataAbs + L.refCount),
        descriptorLen: descLen,
        descriptor: reader.bytes(descAbs, descLen),
      };
    }
    return { rel, unknown: true };
  }

  RV.reg.parseSk = parseSk;
  RV.reg.readSkDescriptor = readSkDescriptor;
})(window.RV);
