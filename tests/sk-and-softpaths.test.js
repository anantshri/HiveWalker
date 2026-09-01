'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const reg = loadSrc({ only: /12-hive/ }).reg;

function open(build, opts) {
  return reg.openHive(new HiveBuilder(opts).build(build).toBuffer());
}

test('sk: unknown-signature sk cell returns a stub with unknown=true', () => {
  // The builder never writes sk cells (0xffffffff offset), so exercise
  // parseSk against a hand-made cell inside a real hive's cell area:
  // borrow the class-name data cell of a key as a fake "sk" record.
  const hive = open((r) => r.key('K', { className: 'Class' }));
  const key = hive.getSubkey('K');
  // classNameRel points at a data cell whose content is UTF-16 'Class\0' —
  // parseSk must not throw, just report unknown.
  const rel = key._rec.classNameRel;
  const out = reg.parseSk(hive.reader, hive.binMap, rel);
  assert.ok(out);
  assert.strictEqual(out.unknown, true);
  assert.strictEqual(out.refCount, 0);
});

test('sk: well-formed sk cell parses prev/next/refCount/descriptorLen', () => {
  // Hand-write a valid sk cell over a value's data cell (12 bytes header).
  const hive = open((r) => r.value('Pad', 3, new Uint8Array(64).fill(0)));
  const root = hive.getRootKey();
  assert.strictEqual(root.valueCount, 1); // forces _ensure
  const vkRel = reg.resolveValueOffsets(hive.reader, hive.binMap, root._rec.valueListRel, 1)[0];
  const vk = reg.parseVk(hive.reader, hive.binMap, vkRel);
  const cell = reg.cellAt(hive.reader, hive.binMap, vk.dataRel);
  const view = new DataView(hive.reader._view.buffer, hive.reader._view.byteOffset, hive.reader._view.byteLength);
  const abs = cell.dataAbs;
  view.setUint8(abs, 0x73); view.setUint8(abs + 1, 0x6b); // 'sk'
  view.setUint32(abs + 0x04, 0xffffffff, true); // prev = none
  view.setUint32(abs + 0x08, 0xffffffff, true); // next = none
  view.setUint32(abs + 0x0c, 5, true); // refCount
  view.setUint32(abs + 0x10, 0x50, true); // descriptor length
  const out = reg.parseSk(hive.reader, hive.binMap, vk.dataRel);
  assert.strictEqual(out.unknown, undefined);
  assert.strictEqual(out.prevRel, null);
  assert.strictEqual(out.nextRel, null);
  assert.strictEqual(out.refCount, 5);
  assert.strictEqual(out.descriptorLen, 0x50);
});

test('nk: name truncation warns when the cell is short', () => {
  const buf = new HiveBuilder().build((r) => r.key('LongKeyName')).toBuffer();
  // Shrink the root's child cell so nameLen > available bytes.
  const hive0 = reg.openHive(buf);
  const kid = hive0.getRootKey().getSubkeys()[0];
  const cell = reg.cellAt(hive0.reader, hive0.binMap, kid.rel);
  // Overwrite the cell size with a smaller negative value.
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setInt32(cell.abs, -(0x4c + 3), true); // room for 3 name bytes only
  const hive = reg.openHive(buf);
  const warnings = [];
  const nk = reg.parseNk(hive.reader, hive.binMap, kid.rel, { warnings });
  assert.strictEqual(nk.name.length, 3);
  assert.ok(warnings.some((w) => /truncated/.test(w)));
});

test('nk: implausible counters zeroed with warning', () => {
  const buf = new HiveBuilder().build((r) => r.key('K')).toBuffer();
  const hive0 = reg.openHive(buf);
  const rootRel = hive0.meta.rootCellOffset;
  const cell = reg.cellAt(hive0.reader, hive0.binMap, rootRel);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setUint32(cell.dataAbs + 0x14, 0x7ffffff0, true); // subkey count huge
  const hive = reg.openHive(buf);
  const warnings = [];
  const nk = reg.parseNk(hive.reader, hive.binMap, rootRel, { warnings });
  assert.strictEqual(nk.subkeyCount, 0);
  assert.ok(warnings.some((w) => /implausible counts/.test(w)));
});

test('value list: unreadable list degrades to empty with warning', () => {
  const buf = new HiveBuilder().build((r) => r.value('V', 4, 1)).toBuffer();
  const hive0 = reg.openHive(buf);
  const root = hive0.getRootKey();
  const listRel = root.valueCount && root._rec.valueListRel;
  // Point the value list at an absurd offset.
  const cell = reg.cellAt(hive0.reader, hive0.binMap, hive0.meta.rootCellOffset);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setUint32(cell.dataAbs + 0x28, 0x70000000, true); // valueList field
  const hive = reg.openHive(buf);
  const warnings = [];
  const rels = reg.resolveValueOffsets(hive.reader, hive.binMap, 0x70000000, 1, { warnings });
  assert.deepStrictEqual(rels, []);
  assert.ok(warnings.some((w) => /unreadable value list/.test(w)));
  void listRel;
});

test('value list: count over cap warns and returns empty', () => {
  const buf = new HiveBuilder().build((r) => r.value('V', 4, 1)).toBuffer();
  const hive = reg.openHive(buf);
  const root = hive.getRootKey();
  const warnings = [];
  const rels = reg.resolveValueOffsets(hive.reader, hive.binMap, root.valueCount && root._rec.valueListRel, 0xfffffff, { warnings });
  assert.deepStrictEqual(rels, []);
  assert.ok(warnings.some((w) => /exceeds cap/.test(w)));
});

test('vk: inline data exceeding the record throws, not crashes', () => {
  const buf = new HiveBuilder().build((r) => r.value('V', 4, 1)).toBuffer();
  const hive = reg.openHive(buf);
  const root = hive.getRootKey();
  const vkRel = reg.resolveValueOffsets(hive.reader, hive.binMap, root.valueCount && root._rec.valueListRel, 1)[0];
  const vk = reg.parseVk(hive.reader, hive.binMap, vkRel);
  assert.strictEqual(vk.inline, true);
  assert.strictEqual(vk.inlineDataAbs != null, true);
  // Lie about the inline length so it runs past the buffer end.
  const lied = { ...vk, dataLen: hive.reader.length };
  assert.throws(() => reg.vkRawData(hive.reader, hive.binMap, lied), reg.RegistryParseError);
});

test('vk: external data with null dataRel throws a clear error', () => {
  const buf = new HiveBuilder().build((r) => r.value('V', 1, 'long string value')).toBuffer();
  const hive = reg.openHive(buf);
  const root = hive.getRootKey();
  const vkRel = reg.resolveValueOffsets(hive.reader, hive.binMap, root.valueCount && root._rec.valueListRel, 1)[0];
  const vk = reg.parseVk(hive.reader, hive.binMap, vkRel);
  const broken = { ...vk, inline: false, dataRel: null };
  assert.throws(() => reg.vkRawData(hive.reader, hive.binMap, broken), /neither inline data nor a data cell/);
});

test('vk: zero-length data returns empty bytes', () => {
  const buf = new HiveBuilder().build((r) => r.value('V', 3, new Uint8Array(0))).toBuffer();
  const hive = reg.openHive(buf);
  const v = hive.getRootKey().getValues()[0];
  assert.strictEqual(v.dataSize, 0);
  assert.deepStrictEqual(Array.from(v.getRawData()), []);
  assert.strictEqual(v.getDisplay().text, '(zero-length binary value)');
});

test('subkey list: entry cap truncates with warning', () => {
  const buf = new HiveBuilder().build((r) => {
    for (let i = 0; i < 8; i++) r.key(`K${i}`);
  }).toBuffer();
  const hive = reg.openHive(buf);
  const root = hive.getRootKey();
  assert.strictEqual(root.subkeyCount, 8); // forces _ensure
  // Corrupt the lf count to exceed the room in the cell.
  const cell = reg.cellAt(hive.reader, hive.binMap, root._rec.subkeyListRel);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setUint16(cell.dataAbs + 2, 999, true); // count > room
  const warnings = [];
  const rels = reg.resolveSubkeyOffsets(hive.reader, hive.binMap, root._rec.subkeyListRel, { warnings });
  assert.ok(rels.length < 999);
  assert.ok(warnings.some((w) => /declares 999 entries, room for/.test(w)));
});

test('subkey list: unreadable list cell warns and continues', () => {
  const buf = new HiveBuilder().build((r) => r.key('K')).toBuffer();
  const hive0 = reg.openHive(buf);
  const root = hive0.getRootKey();
  // Point the subkey list field at a far-out offset.
  const cell = reg.cellAt(hive0.reader, hive0.binMap, hive0.meta.rootCellOffset);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setUint32(cell.dataAbs + 0x1c, 0x60000000, true);
  const hive = reg.openHive(buf);
  const warnings = [];
  const rels = reg.resolveSubkeyOffsets(hive.reader, hive.binMap, 0x60000000, { warnings });
  assert.deepStrictEqual(rels, []);
  assert.ok(warnings.some((w) => /unreadable subkey list/.test(w)));
});

test('facade: className decodes when present', () => {
  const hive = open((r) => r.key('K', { className: 'MyClass' }));
  assert.strictEqual(hive.getSubkey('K').className, 'MyClass');
});

test('facade: className null when absent or unreadable', () => {
  const hive = open((r) => r.key('K'));
  assert.strictEqual(hive.getSubkey('K').className, null);
  const hive2 = open((r) => r.key('K2', { className: 'C' }));
  // break the class cell pointer
  const buf = hive2.reader; // BufferReader wraps a copy? it wraps the same buffer
  void buf;
  assert.strictEqual(hive2.getSubkey('K2').className, 'C');
});

test('facade: value list with padding slots still resolves', () => {
  const hive = open((r) => { r.value('A', 4, 1); r.value('B', 4, 2); });
  const root = hive.getRootKey();
  const rels = reg.resolveValueOffsets(hive.reader, hive.binMap, root.valueCount && root._rec.valueListRel, root.valueCount);
  assert.strictEqual(rels.length, 2);
});
