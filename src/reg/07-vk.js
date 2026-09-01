// rv.reg — vk (value) records + data resolution (inline vs external cell).
(function (RV) {
  'use strict';

  const { VK_LAYOUTS, VALUE_COMP_NAME } = RV.reg.consts;
  const { BufferReader, RegistryParseError } = RV.reg;

  const INLINE_FLAG = 0x80000000;

  /**
   * @param {BufferReader} reader
   * @param {object} binMap
   * @param {number} rel
   * @returns {{rel:number, name:string, type:number, dataLen:number,
   *   dataRel:number|null, inline:boolean, flags:number}}
   */
  function parseVk(reader, binMap, rel) {
    const cell = RV.reg.cellAt(reader, binMap, rel);
    const dataAbs = cell.dataAbs;

    let layout = null;
    for (const key of Object.keys(VK_LAYOUTS)) {
      const L = VK_LAYOUTS[key];
      if (reader.inBounds(dataAbs, L.sigLen) && reader.sig(dataAbs, L.sigLen) === L.sig) {
        layout = L;
        break;
      }
    }
    if (!layout) {
      const found = reader.inBounds(dataAbs, 4) ? reader.ascii(dataAbs, 4) : '????';
      throw new RegistryParseError(`expected vk record, found ${JSON.stringify(found)}`, dataAbs);
    }

    const nameLen = reader.u16(dataAbs + layout.nameLen);
    const rawDataLen = reader.u32(dataAbs + layout.dataLen);
    const type = reader.u32(dataAbs + layout.type);
    const flags = reader.u16(dataAbs + layout.flags);

    let name = '';
    const nameAvail = cell.size - layout.nameAt;
    const nameBytes = Math.min(nameLen, Math.max(0, nameAvail));
    if (nameBytes > 0) {
      // Value names are almost always single-byte; the flag decides.
      if (flags & VALUE_COMP_NAME) {
        name = reader.ascii(dataAbs + layout.nameAt, nameBytes);
      } else {
        name = reader.utf16le(dataAbs + layout.nameAt, nameBytes);
      }
    }

    // Inline rule: high bit set → bytes live in the "data offset" slot.
    const inline = (rawDataLen & INLINE_FLAG) !== 0;
    const dataLen = inline ? rawDataLen & 0x7fffffff : rawDataLen;
    const dataSlotAbs = dataAbs + layout.dataOffset;
    const dataSlotRel = reader.u32(dataSlotAbs);
    const dataRel = inline ? null : RV.reg.optOffset(dataSlotRel);

    return {
      rel, name, type, dataLen, dataRel, inline, flags,
      inlineDataAbs: inline ? dataSlotAbs : null,
    };
  }

  /**
   * Fetch the value's raw bytes (bounds-checked).
   * @returns {Uint8Array}
   */
  function vkRawData(reader, binMap, vk) {
    if (vk.dataLen === 0) return new Uint8Array(0);
    if (vk.inline) {
      if (vk.inlineDataAbs == null) {
        throw new RegistryParseError('inline value missing its slot position', null);
      }
      if (!reader.inBounds(vk.inlineDataAbs, vk.dataLen)) {
        throw new RegistryParseError(`inline data (${vk.dataLen}B) exceeds record`, vk.inlineDataAbs);
      }
      return reader.bytes(vk.inlineDataAbs, vk.dataLen);
    }
    if (vk.dataRel == null) {
      throw new RegistryParseError('value has neither inline data nor a data cell', null);
    }
    const cell = RV.reg.cellAt(reader, binMap, vk.dataRel);
    const abs = cell.dataAbs;
    if (!reader.inBounds(abs, vk.dataLen)) {
      throw new RegistryParseError(`data cell too small for ${vk.dataLen} bytes`, abs);
    }
    return reader.bytes(abs, vk.dataLen);
  }

  RV.reg.parseVk = parseVk;
  RV.reg.vkRawData = vkRawData;
})(window.RV);
