'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const reg = loadSrc({ only: /05-hbin/ }).reg;
const { BufferReader, parseRegfBlock, scanHiveBins, buildBinMap, cellAt, optOffset } = reg;

test('regf block: metadata round-trips from a synthetic hive', () => {
  const buf = new HiveBuilder({ fileName: '\\??\\C:\\Users\\test\\NTUSER.DAT' }).build(() => {}).toBuffer();
  const r = new BufferReader(buf);
  const b = parseRegfBlock(r);
  assert.strictEqual(b.major, 1);
  assert.strictEqual(b.minor, 5);
  assert.strictEqual(b.majorVersion, '1.5');
  assert.strictEqual(b.fileName, '\\??\\C:\\Users\\test\\NTUSER.DAT');
  assert.strictEqual(b.sequence1, 1);
  assert.strictEqual(b.dirty, false);
  assert.strictEqual(b.checksumValid, true);
  assert.strictEqual(b.format, 1);
  assert.strictEqual(b.cluster, 1);
  assert.strictEqual(b.hiveBinsSize % 4096, 0);
});

test('regf block: non-regf input is a hard error', () => {
  const r = new BufferReader(new Uint8Array(8192).fill(0x41).buffer);
  assert.throws(() => parseRegfBlock(r), /not a registry hive/);
});

test('regf block: undersized file rejected before sig check', () => {
  const r = new BufferReader(new Uint8Array(100).buffer);
  assert.throws(() => parseRegfBlock(r), /too small for a regf base block/);
});

test('regf block: corrupted checksum is a warning, not an error', () => {
  const buf = new HiveBuilder().build(() => {}).toBuffer();
  buf[0x1fc] ^= 0xff;
  const b = parseRegfBlock(new BufferReader(buf));
  assert.strictEqual(b.checksumValid, false); // parse still succeeded
});

test('regf block: dirty when sequence numbers diverge', () => {
  const buf = new HiveBuilder().build(() => {}).toBuffer();
  const view = new DataView(buf.buffer);
  view.setUint32(0x08, 2, true);
  const b = parseRegfBlock(new BufferReader(buf));
  assert.strictEqual(b.dirty, true);
});

test('hbins: synthetic hive scans at least one bin', () => {
  const buf = new HiveBuilder().build((r) => r.key('Child')).toBuffer();
  const r = new BufferReader(buf);
  const regf = parseRegfBlock(r);
  const bins = scanHiveBins(r);
  assert.ok(bins.length >= 1);
  assert.strictEqual(bins[0].fileOffset, 4096);
  assert.strictEqual(bins[0].relOffset, 0);
  const map = buildBinMap(bins);
  assert.strictEqual(map.totalBytes, regf.hiveBinsSize);
  assert.strictEqual(map.contains(4096, 8), true);
  assert.strictEqual(map.contains(0, 8), false); // base block is not a cell area
});

test('cells: allocated cells read back negative-size headers', () => {
  const buf = new HiveBuilder().build((r) => r.key('Child')).toBuffer();
  const r = new BufferReader(buf);
  const bins = scanHiveBins(r);
  const map = buildBinMap(bins);
  // Root cell sits where the base block says (children are emitted before
  // their parent, so the root lands after its subtree).
  const rootRel = parseRegfBlock(r).rootCellOffset;
  assert.ok(rootRel > 0);
  const cell = cellAt(r, map, rootRel);
  assert.strictEqual(cell.allocated, true);
  assert.ok(cell.size > 0x4c);
  assert.strictEqual(r.sig(cell.dataAbs, 2), 'nk');
});

test('cells: offsets outside bins are rejected', () => {
  const buf = new HiveBuilder().build(() => {}).toBuffer();
  const r = new BufferReader(buf);
  const map = buildBinMap(scanHiveBins(r));
  // rel offsets that would land before the first hbin or past its end
  assert.throws(() => cellAt(r, map, -1), /invalid cell offset/);
  const pastEnd = buf.length - 4096 + 8; // beyond final hbin
  assert.throws(() => cellAt(r, map, pastEnd), /outside hive bins/);
});

test('optOffset normalises the no-offset sentinel', () => {
  assert.strictEqual(optOffset(0xffffffff), null);
  assert.strictEqual(optOffset(0xfffffffe), 0xfffffffe); // only exact sentinel
  assert.strictEqual(optOffset(1234), 1234);
  assert.strictEqual(optOffset(0), 0);
});
