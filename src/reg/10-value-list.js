// rv.reg — value lists: an array of u32 vk offsets. Some old hives pad the
// list to an even number of slots; we read `count` entries and ignore any
// trailing padding.
(function (RV) {
  'use strict';

  const { LIMITS } = RV.reg.consts;
  const { BufferReader } = RV.reg;

  /**
   * @param {BufferReader} reader
   * @param {object} binMap
   * @param {number|null} listRel
   * @param {number} count value count from the nk record
   * @param {{warnings?: string[]}} [ctx]
   * @returns {number[]} vk offsets
   */
  function resolveValueOffsets(reader, binMap, listRel, count, ctx) {
    if (listRel == null || count === 0) return [];
    if (count > LIMITS.MAX_VALUES_PER_NODE) {
      if (ctx && ctx.warnings) ctx.warnings.push(`value count ${count} exceeds cap`);
      return [];
    }
    const warnings = ctx && ctx.warnings;
    let cell;
    try {
      cell = RV.reg.cellAt(reader, binMap, listRel);
    } catch (e) {
      if (warnings) warnings.push(`unreadable value list: ${e.message}`);
      return [];
    }
    const slots = Math.floor(cell.size / 4);
    const n = Math.min(count, slots);
    if (count > slots && warnings) {
      warnings.push(`value list declares ${count} values, room for ${slots}`);
    }
    const out = [];
    for (let i = 0; i < n; i++) {
      const off = reader.u32(cell.dataAbs + i * 4);
      if (off === 0) continue; // sparse padding
      out.push(off);
    }
    return out;
  }

  RV.reg.resolveValueOffsets = resolveValueOffsets;
})(window.RV);
