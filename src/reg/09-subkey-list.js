// rv.reg — subkey-list resolution: lf/lh (hash entries), li/db (plain
// offsets), ri/CM_KEY_INDEX (indirection). Iterative with a visited set so
// cyclic or overlapping structures terminate; unknown signatures degrade to
// a warning instead of throwing.
(function (RV) {
  'use strict';

  const { SIG, HASHED_LIST_SIGS, INDEX_LIST_SIGS, INDIRECT_LIST_SIGS, LIMITS } = RV.reg.consts;
  const { BufferReader } = RV.reg;

  // Signatures that appear at the start of a subkey-list cell. Length is
  // sniffed: 2-byte classic sigs, 11-byte CM_KEY_* sigs. CM list records use
  // the same count-at-0x02 convention as their classic counterparts.
  const CM_SIGS = [SIG.CM_KEY_FAST_INDEX, SIG.CM_KEY_FAST_LEAF, SIG.CM_KEY_HASH_LEAF, SIG.CM_KEY_INDEX_LEAF, SIG.CM_KEY_INDEX];

  function sniffLayout(reader, dataAbs) {
    if (!reader.inBounds(dataAbs, 2)) return null;
    const ascii2 = reader.ascii(dataAbs, 2);
    if ([SIG.LF, SIG.LH, SIG.LI, SIG.RI, SIG.DB].includes(ascii2)) {
      return { sig: ascii2, sigLen: 2 };
    }
    if (reader.inBounds(dataAbs, 11)) {
      const ascii11 = reader.ascii(dataAbs, 11);
      if (CM_SIGS.includes(ascii11)) return { sig: ascii11, sigLen: 11 };
    }
    return null;
  }

  /**
   * Resolve a subkey list into nk rel-offsets.
   *
   * @param {BufferReader} reader
   * @param {object} binMap
   * @param {number|null} listRel
   * @param {{warnings?: string[]}} [ctx]
   * @returns {number[]} nk offsets (possibly empty on soft failure)
   */
  function resolveSubkeyOffsets(reader, binMap, listRel, ctx) {
    if (listRel == null) return [];
    const warnings = ctx && ctx.warnings;
    const out = [];
    const seenLists = new Set(); // cycle guard on list records
    const worklist = [listRel];
    let emitted = 0;

    while (worklist.length > 0) {
      if (emitted > LIMITS.MAX_LIST_ENTRIES) {
        if (warnings) warnings.push('subkey list exceeded entry cap; truncated');
        break;
      }
      const rel = worklist.pop();
      if (seenLists.has(rel)) continue; // already expanded (or cyclic)
      seenLists.add(rel);

      let cell;
      let dataAbs;
      let layout;
      try {
        cell = RV.reg.cellAt(reader, binMap, rel);
        dataAbs = cell.dataAbs;
        layout = sniffLayout(reader, dataAbs);
      } catch (e) {
        if (warnings) warnings.push(`unreadable subkey list at 0x${rel.toString(16)}: ${e.message}`);
        continue;
      }
      if (!layout) {
        if (warnings) {
          const found = reader.inBounds(dataAbs, 4) ? JSON.stringify(reader.ascii(dataAbs, 4)) : '?';
          warnings.push(`unknown subkey list signature ${found} at 0x${rel.toString(16)}`);
        }
        continue;
      }

      // count: u16 at 0x02 (both classic and CM forms)
      const count = reader.u16(dataAbs + 2);
      const entryArea = cell.size - 4 - layout.sigLen; // bytes available for entries
      let entrySize;
      if (HASHED_LIST_SIGS.has(layout.sig)) entrySize = 8;
      else entrySize = 4; // li/db/ri and CM leaf/index forms
      const maxEntries = Math.floor(entryArea / entrySize);
      const n = Math.min(count, maxEntries);
      if (count > maxEntries && warnings) {
        warnings.push(`subkey list at 0x${rel.toString(16)} declares ${count} entries, room for ${maxEntries}`);
      }

      const entriesAt = dataAbs + layout.sigLen + 2;
      const indirect = INDIRECT_LIST_SIGS.has(layout.sig);
      for (let i = 0; i < n; i++) {
        const at = entriesAt + i * entrySize;
        const target = reader.u32(at);
        if (indirect) {
          worklist.push(target);
        } else {
          out.push(target);
          emitted++;
        }
      }
    }
    return out;
  }

  RV.reg.resolveSubkeyOffsets = resolveSubkeyOffsets;
  RV.reg.sniffSubkeyListLayout = sniffLayout;
})(window.RV);
