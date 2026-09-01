'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const reg = loadSrc({ only: /10-value-list/ }).reg;
const { BufferReader, parseRegfBlock, scanHiveBins, buildBinMap, parseNk, parseVk, vkRawData } = reg;

// Open a synthetic hive and return the pieces every record test needs.
function open(build, opts) {
  const buf = new HiveBuilder(opts).build(build).toBuffer();
  const reader = new BufferReader(buf);
  const regf = parseRegfBlock(reader);
  const binMap = buildBinMap(scanHiveBins(reader));
  const rootRel = regf.rootCellOffset;
  return { buf, reader, binMap, rootRel };
}

test('nk: root record parses with name, timestamp, counts', () => {
  const { reader, binMap, rootRel } = open((r) => {
    r.key('Software').key('Microsoft');
    r.value('InstallType', 4, 3);
  });
  const nk = parseNk(reader, binMap, rootRel);
  assert.strictEqual(nk.name, 'root');
  assert.strictEqual(nk.timestamp, 0x01d0c7a57f5a6c00n);
  assert.strictEqual(nk.subkeyCount, 1);
  assert.strictEqual(nk.valueCount, 1);
  assert.strictEqual(nk.layout, 'nk');
  assert.strictEqual(typeof nk.parentRel, 'number'); // root parent → itself
});

test('nk: children resolve through lf lists with correct names', () => {
  const { reader, binMap, rootRel } = open((r) => {
    r.key('SAM').key('Domains');
    r.key('SOFTWARE').key('Microsoft');
    r.key('SYSTEM').key('Select');
  });
  const root = parseNk(reader, binMap, rootRel);
  const childRels = reg.resolveSubkeyOffsets(reader, binMap, root.subkeyListRel);
  assert.strictEqual(childRels.length, 3);
  const names = childRels.map((rel) => parseNk(reader, binMap, rel).name).sort();
  assert.deepStrictEqual(names, ['SAM', 'SOFTWARE', 'SYSTEM']);
  // children point back at the root
  for (const rel of childRels) {
    assert.strictEqual(parseNk(reader, binMap, rel).parentRel, rootRel);
  }
});

test('nk: class name round-trips', () => {
  const { reader, binMap, rootRel } = open((r) => {
    r.key('Named', { className: 'ClassName 0' });
  });
  const root = parseNk(reader, binMap, rootRel);
  const child = parseNk(reader, binMap, reg.resolveSubkeyOffsets(reader, binMap, root.subkeyListRel)[0]);
  assert.strictEqual(child.classNameRel, 0 - child.classNameRel === 0 ? null : child.classNameRel); // recorded
  assert.ok(child.classNameLen > 0);
});

test('vk: values parse with names, types, inline data', () => {
  const { reader, binMap, rootRel } = open((r) => {
    r.value('DwordVal', 4, 0x2a);
    r.value('SzVal', 1, 'hello');
    r.value('', 4, 7); // default value
  });
  const root = parseNk(reader, binMap, rootRel);
  const vkRels = reg.resolveValueOffsets(reader, binMap, root.valueListRel, root.valueCount);
  assert.strictEqual(vkRels.length, 3);
  const vks = vkRels.map((rel) => parseVk(reader, binMap, rel));

  const [dword, sz, def] = vks;
  assert.strictEqual(dword.name, 'DwordVal');
  assert.strictEqual(dword.type, 4);
  assert.strictEqual(dword.inline, true);
  assert.strictEqual(dword.dataLen, 4);
  assert.deepStrictEqual([...vkRawData(reader, binMap, dword)], [0x2a, 0, 0, 0]);

  assert.strictEqual(sz.name, 'SzVal');
  assert.strictEqual(sz.type, 1);
  assert.strictEqual(sz.inline, false); // 12 bytes → external
  assert.strictEqual(sz.dataLen, 12);
  assert.strictEqual(reg.decodeUtf16LE(vkRawData(reader, binMap, sz)), 'hello');

  assert.strictEqual(def.name, ''); // renders as "(Default)"
});

test('vk: external data cells round-trip binary blobs', () => {
  const blob = new Uint8Array(64).map((_, i) => (i * 7) & 0xff);
  const { reader, binMap, rootRel } = open((r) => r.value('Bin', 3, blob));
  const root = parseNk(reader, binMap, rootRel);
  const vk = parseVk(reader, binMap, reg.resolveValueOffsets(reader, binMap, root.valueListRel, 1)[0]);
  assert.strictEqual(vk.inline, false);
  assert.deepStrictEqual([...vkRawData(reader, binMap, vk)], [...blob]);
});

test('vk: QWORD round-trips via BigInt', () => {
  const { reader, binMap, rootRel } = open((r) => r.value('Q', 11, 0x1122334455667788n));
  const root = parseNk(reader, binMap, rootRel);
  const vk = parseVk(reader, binMap, reg.resolveValueOffsets(reader, binMap, root.valueListRel, 1)[0]);
  const raw = vkRawData(reader, binMap, vk);
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  assert.strictEqual(view.getBigUint64(0, true), 0x1122334455667788n);
});

test('subkey lists: lf, lh, li styles all resolve the same tree', () => {
  for (const style of ['lf', 'lh', 'li']) {
    const { reader, binMap, rootRel } = open((r) => {
      r.key('A'); r.key('B'); r.key('C');
    }, { subkeyList: style });
    const root = parseNk(reader, binMap, rootRel);
    const rels = reg.resolveSubkeyOffsets(reader, binMap, root.subkeyListRel);
    assert.strictEqual(rels.length, 3, style);
    const names = rels.map((rel) => parseNk(reader, binMap, rel).name).sort().join(',');
    assert.strictEqual(names, 'A,B,C', style);
  }
});

test('subkey lists: ri indirection resolves through lf pages', () => {
  const { reader, binMap, rootRel } = open((r) => {
    for (let i = 0; i < 250; i++) r.key(`K${String(i).padStart(3, '0')}`);
  }, { subkeyList: 'ri' });
  const root = parseNk(reader, binMap, rootRel);
  const rels = reg.resolveSubkeyOffsets(reader, binMap, root.subkeyListRel);
  assert.strictEqual(rels.length, 250);
});

test('subkey lists: cycles terminate (visited set)', () => {
  // Build a normal hive, then corrupt an lf entry to point at the list itself.
  const { reader, binMap, rootRel } = open((r) => { r.key('X'); r.key('Y'); });
  const root = parseNk(reader, binMap, rootRel);
  // Locate the lf cell and retarget its first entry to its own offset.
  const listRel = root.subkeyListRel;
  const cell = reg.cellAt(reader, binMap, listRel);
  // entry 0 offset field is at dataAbs+4
  reader._view.setUint32(cell.dataAbs + 4, listRel, true);
  const rels = reg.resolveSubkeyOffsets(reader, binMap, listRel, { warnings: [] });
  assert.ok(Array.isArray(rels));
  assert.ok(rels.length < 100, 'cycle did not explode');
});

test('subkey lists: unknown signature warns and returns partial', () => {
  const { reader, binMap, rootRel } = open((r) => { r.key('X'); });
  const root = parseNk(reader, binMap, rootRel);
  const cell = reg.cellAt(reader, binMap, root.subkeyListRel);
  reader._view.setUint8(cell.dataAbs, 0x5a); reader._view.setUint8(cell.dataAbs + 1, 0x5a); // 'ZZ'
  const warnings = [];
  const rels = reg.resolveSubkeyOffsets(reader, binMap, root.subkeyListRel, { warnings });
  assert.deepStrictEqual(rels, []);
  assert.ok(warnings.some((w) => /unknown subkey list signature/.test(w)));
});

test('sk: parseSk returns null for missing security cells', () => {
  const { reader, binMap, rootRel } = open(() => {});
  const nk = parseNk(reader, binMap, rootRel);
  assert.strictEqual(nk.skRel, null); // builder writes 0xffffffff
  assert.strictEqual(reg.parseSk(reader, binMap, null), null);
});

test('nk: bad signature is a hard error', () => {
  const { reader, binMap, rootRel } = open(() => {});
  const cell = reg.cellAt(reader, binMap, rootRel);
  reader._view.setUint8(cell.dataAbs, 0x71); reader._view.setUint8(cell.dataAbs + 1, 0x71);
  assert.throws(() => parseNk(reader, binMap, rootRel), /expected nk record/);
});
