'use strict';

// Synthetic regf hive WRITER — an independent code path from the parser in
// src/reg/. Tests build hives here and assert the parser reads back exactly
// what was written; because both sides share only the format spec, agreement
// is strong evidence the offsets are right.
//
// Design: cells are appended into a virtual cell area that grows in 4096-byte
// hbins, each bin reserving its first 0x20 bytes for the hbin header. A
// record never straddles a bin boundary (padding is inserted when the next
// record wouldn't fit in the remaining payload). Cell "relative offsets" are
// the format's offsets-from-first-hbin — i.e. binIndex*4096 + 0x20 + inBin.

const REGBLOCK_SIZE = 4096;
const HBIN_HEADER = 0x20;
const PAYLOAD = REGBLOCK_SIZE - HBIN_HEADER;

/** Growable hive image: regf block + hbins, with post-hoc u32 patching. */
class HiveImage {
  constructor() {
    this.buf = Buffer.alloc(REGBLOCK_SIZE + REGBLOCK_SIZE);
    this.hbinCount = 1;
    this._writeHbinHeader(0);
    // Explicit write cursor: rel offset of the next free payload byte.
    this._top = HBIN_HEADER;
  }

  _writeHbinHeader(i) {
    const at = REGBLOCK_SIZE + i * REGBLOCK_SIZE;
    this.buf.write('hbin', at, 'latin1');
    this.buf.writeUInt32LE(i * REGBLOCK_SIZE, at + 0x04);
    this.buf.writeUInt32LE(REGBLOCK_SIZE, at + 0x08);
    this.buf.writeBigUInt64LE(0x01d0c7a57f5a6c00n, at + 0x18);
  }

  /** Ensure a cell of `size` bytes fits in the current bin; else add a bin. */
  _reserve(size) {
    const room = this.hbinCount * REGBLOCK_SIZE - this._top;
    if (size > room) {
      this.buf = Buffer.concat([this.buf, Buffer.alloc(REGBLOCK_SIZE)]);
      this.hbinCount += 1;
      this._writeHbinHeader(this.hbinCount - 1);
      this._top = (this.hbinCount - 1) * REGBLOCK_SIZE + HBIN_HEADER;
    }
  }

  /**
   * Append a cell: i32 size header (negative = allocated) then payload.
   * @param {Buffer} payload
   * @returns {number} the cell's rel offset (position of the size field)
   */
  appendCell(payload) {
    const size = payload.length + 4;
    if (size > PAYLOAD) throw new Error(`builder: cell too large (${size})`);
    this._reserve(size);
    const rel = this._top;
    const abs = REGBLOCK_SIZE + rel;
    this.buf.writeInt32LE(-size, abs);
    payload.copy(this.buf, abs + 4);
    this._top += size;
    return rel;
  }

  writeU32At(abs, v) { this.buf.writeUInt32LE(v >>> 0, abs); }

  finalise(o, rootRel) {
    this.buf.write('regf', 0, 'latin1');
    this.buf.writeUInt32LE(1, 0x04);
    this.buf.writeUInt32LE(1, 0x08);
    this.buf.writeBigUInt64LE(0x01d0c7a57f5a6c00n, 0x0c);
    this.buf.writeUInt32LE(o.major, 0x14);
    this.buf.writeUInt32LE(o.minor, 0x18);
    this.buf.writeUInt32LE(0, 0x1c);
    this.buf.writeUInt32LE(1, 0x20);
    this.buf.writeUInt32LE(rootRel, 0x24);
    this.buf.writeUInt32LE(this.hbinCount * REGBLOCK_SIZE, 0x28);
    this.buf.writeUInt32LE(1, 0x2c);
    const name = Buffer.alloc(128);
    Buffer.from(o.fileName, 'utf16le').copy(name, 0);
    name.copy(this.buf, 0x30);
    let sum = 0;
    for (let i = 0; i < 0x1fc; i += 4) sum = (sum + this.buf.readUInt32LE(i)) >>> 0;
    this.buf.writeUInt32LE(((sum >>> 16) ^ (sum & 0xffff)) >>> 0, 0x1fc);
    return new Uint8Array(this.buf);
  }
}

// ---------------------------------------------------------------------------
// Key spec model

class KeySpec {
  constructor(name, opts = {}) {
    this.name = name;
    this.lastWrite = opts.lastWrite ?? 0n;
    this.className = opts.className ?? null;
    this.volatile = !!opts.volatile;
    this.security = opts.security ?? null; // raw self-relative SECURITY_DESCRIPTOR bytes → sk cell
    this.children = [];
    this.values = [];
  }
  key(name, opts, build) {
    const k = new KeySpec(name, opts || {});
    if (typeof build === 'function') build(k);
    this.children.push(k);
    return k;
  }
  value(name, type, data) {
    this.values.push({ name, type, data });
    return this;
  }
}

// Value-data encoding (independent from the parser's decoders).
function encodeValueData(type, data) {
  let bytes;
  switch (type) {
    case 1: case 2: case 6:
      bytes = Buffer.from(String(data ?? '') + '\0', 'utf16le');
      break;
    case 7: {
      const parts = Array.isArray(data) ? data : [String(data ?? '')];
      bytes = Buffer.from(parts.map((s) => String(s) + '\0').join('') + '\0', 'utf16le');
      break;
    }
    case 4: { const b = Buffer.alloc(4); b.writeUInt32LE(Number(data ?? 0) >>> 0); bytes = b; break; }
    case 5: { const b = Buffer.alloc(4); b.writeUInt32BE(Number(data ?? 0) >>> 0); bytes = b; break; }
    case 11: { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(data ?? 0)); bytes = b; break; }
    default:
      bytes = Buffer.from(data instanceof Uint8Array ? data : (data ?? []));
  }
  return bytes;
}

const NK_HEADER = { nk: 0x4c, CM_KEY_NODE: 0x55 };
const VK_HEADER = { vk: 0x16, CM_KEY_VALUE: 0x20 };

// ---------------------------------------------------------------------------
// The builder

class HiveBuilder {
  constructor(opts = {}) {
    this.opts = {
      major: opts.major ?? 1,
      minor: opts.minor ?? 5,
      fileName: opts.fileName ?? '\\??\\C:\\test\\hive',
      nkLayout: opts.nkLayout ?? 'nk',
      vkLayout: opts.vkLayout ?? 'vk',
      subkeyList: opts.subkeyList ?? 'lf',
      forceInline: opts.forceInline ?? true,
    };
    this.root = new KeySpec('root', { lastWrite: 0x01d0c7a57f5a6c00n });
  }

  build(build) { build(this.root); return this; }

  toBuffer() {
    const o = this.opts;
    const img = new HiveImage();

    const emitDataCell = (bytes) => img.appendCell(bytes);

    const emitVk = (spec) => {
      const bytes = encodeValueData(spec.type, spec.data);
      const inline = bytes.length > 0 && bytes.length <= 4 && o.forceInline;
      let dataRel = null;
      if (!inline) dataRel = emitDataCell(bytes);

      const nameBytes = spec.name ? Buffer.from(spec.name, 'latin1') : Buffer.alloc(0);
      const isCM = o.vkLayout === 'CM_KEY_VALUE';
      const header = VK_HEADER[isCM ? 'CM_KEY_VALUE' : 'vk'];
      const payload = Buffer.alloc(header + nameBytes.length);
      let p = 0;
      payload.write(isCM ? 'CM_KEY_VALUE' : 'vk', p, 'latin1'); p += isCM ? 12 : 2;
      payload.writeUInt16LE(nameBytes.length, p); p += 2;
      if (inline) {
        payload.writeUInt32LE((0x80000000 | bytes.length) >>> 0, p); p += 4;
        bytes.copy(payload, p); p += 4; // bytes live in the "data offset" slot
      } else {
        payload.writeUInt32LE(bytes.length, p); p += 4;
        payload.writeUInt32LE(dataRel, p); p += 4;
      }
      payload.writeUInt32LE(spec.type, p); p += 4;
      payload.writeUInt16LE(nameBytes.length > 0 ? 0x0001 : 0, p); p += 2; // VALUE_COMP_NAME
      payload.writeUInt16LE(0, p); p += 2; // spare
      nameBytes.copy(payload, p);
      return img.appendCell(payload);
    };

    const emitHashList = (rels, sig) => {
      // Layout: sig[2] count u16 entries...
      const payload = Buffer.alloc(4 + 8 * rels.length);
      payload.write(sig, 0, 'latin1');
      payload.writeUInt16LE(rels.length, 2);
      rels.forEach((r, i) => {
        payload.writeUInt32LE(r, 4 + i * 8);
        payload.writeUInt32LE(0xdeadbeef, 4 + i * 8 + 4); // hash, ignored
      });
      return img.appendCell(payload);
    };

    const emitSubkeyList = (childRels) => {
      const style = o.subkeyList;
      if (style === 'li') {
        const payload = Buffer.alloc(4 + 4 * childRels.length);
        payload.write('li', 0, 'latin1');
        payload.writeUInt16LE(childRels.length, 2);
        childRels.forEach((r, i) => payload.writeUInt32LE(r, 4 + i * 4));
        return img.appendCell(payload);
      }
      if (style === 'ri') {
        const pages = [];
        for (let i = 0; i < childRels.length; i += 100) {
          pages.push(emitHashList(childRels.slice(i, i + 100), 'lf'));
        }
        const payload = Buffer.alloc(4 + 4 * pages.length);
        payload.write('ri', 0, 'latin1');
        payload.writeUInt16LE(pages.length, 2);
        pages.forEach((r, i) => payload.writeUInt32LE(r, 4 + i * 4));
        return img.appendCell(payload);
      }
      return emitHashList(childRels, style === 'lh' ? 'lh' : 'lf');
    };

    const emitKey = (spec, depth) => {
      if (depth > 64) throw new Error('builder: tree too deep');
      const childRecs = spec.children.map((c) => emitKey(c, depth + 1));
      const childRels = childRecs.map((c) => c.rel);
      const valueRels = spec.values.map((v) => emitVk(v));

      let valueListRel = 0xffffffff;
      if (valueRels.length > 0) {
        const payload = Buffer.alloc(4 * valueRels.length);
        valueRels.forEach((r, i) => payload.writeUInt32LE(r, i * 4));
        valueListRel = img.appendCell(payload);
      }

      let subkeyListRel = 0xffffffff;
      if (childRels.length > 0) subkeyListRel = emitSubkeyList(childRels);

      let classRel = 0xffffffff;
      if (spec.className != null) {
        classRel = emitDataCell(Buffer.from(spec.className + '\0', 'utf16le'));
      }

      // Optional sk cell so security-descriptor reads are testable end-to-end.
      let skRel = 0xffffffff;
      if (spec.security != null) {
        const d = Buffer.isBuffer(spec.security) ? spec.security : Buffer.from(spec.security);
        const payload = Buffer.alloc(0x14 + d.length);
        payload.write('sk', 0, 'latin1');
        payload.writeUInt32LE(0xffffffff, 0x04); // prev
        payload.writeUInt32LE(0xffffffff, 0x08); // next
        payload.writeUInt32LE(1, 0x0c);          // refCount
        payload.writeUInt32LE(d.length, 0x10);   // descriptor length
        d.copy(payload, 0x14);
        skRel = img.appendCell(payload);
      }

      const nameBytes = Buffer.from(spec.name, 'latin1');
      const isCM = o.nkLayout === 'CM_KEY_NODE';
      const header = NK_HEADER[isCM ? 'CM_KEY_NODE' : 'nk'];
      const payload = Buffer.alloc(header + nameBytes.length);
      let p = 0;
      payload.write(isCM ? 'CM_KEY_NODE' : 'nk', p, 'latin1'); p += isCM ? 11 : 2;
      payload.writeUInt16LE(0x0020 | (spec.volatile ? 0x0001 : 0), p); p += 2; // KEY_COMP_NAME
      payload.writeBigUInt64LE(spec.lastWrite, p); p += 8;
      payload.writeUInt32LE(0, p); p += 4; // access bits
      const parentAt = p; p += 4; // parent rel — patched by caller
      payload.writeUInt32LE(spec.children.length, p); p += 4;
      payload.writeUInt32LE(0, p); p += 4; // volatile subkey count
      payload.writeUInt32LE(subkeyListRel, p); p += 4;
      payload.writeUInt32LE(0xffffffff, p); p += 4; // volatile value count (-1)
      payload.writeUInt32LE(spec.values.length, p); p += 4;
      payload.writeUInt32LE(valueListRel, p); p += 4;
      payload.writeUInt32LE(skRel, p); p += 4; // sk
      payload.writeUInt32LE(classRel, p); p += 4;
      payload.writeUInt32LE(64, p); p += 4; // max subkey name len
      payload.writeUInt32LE(64, p); p += 4; // max class len
      payload.writeUInt32LE(512, p); p += 4; // max value name len
      payload.writeUInt32LE(0x10000, p); p += 4; // max value data len
      payload.writeUInt32LE(0, p); p += 4; // unknown field (0x44)
      payload.writeUInt16LE(nameBytes.length, p); p += 2; // 0x48
      payload.writeUInt16LE(spec.className != null ? Buffer.byteLength(spec.className + '\0', 'utf16le') : 0, p); p += 2; // 0x4a
      nameBytes.copy(payload, p); // 0x4c
      const rel = img.appendCell(payload);
      // Children were emitted before us; point their parent fields at this key.
      for (const child of childRecs) img.writeU32At(child.parentAbs, rel);
      const parentAbs = REGBLOCK_SIZE + rel + 4 + parentAt;
      return { rel, parentAbs, spec };
    };

    const rootRec = emitKey(this.root, 0);
    // root's parent field → itself (regedit root convention)
    img.writeU32At(rootRec.parentAbs, rootRec.rel);

    return img.finalise(o, rootRec.rel);
  }
}

module.exports = { HiveBuilder, KeySpec, REGBLOCK_SIZE };
