// rv.reg — sk (security) cells. Minimal: the viewer surfaces refcount only;
// descriptor/SID decoding is a documented non-goal.
(function (RV) {
  'use strict';

  const { SK_LAYOUTS } = RV.reg.consts;

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

  RV.reg.parseSk = parseSk;
})(window.RV);
