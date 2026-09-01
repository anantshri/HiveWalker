'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

// Load everything (parser + view-models); UI DOM binders after 21- use
// document at call time, not load time, so they're safe to load in Node.
const RV = loadSrc();
const { viewModel } = RV.ui;
const reg = RV.reg;

function hiveWith(build, opts) {
  return reg.openHive(new HiveBuilder(opts).build(build).toBuffer());
}

test('treeNode: collapsed node exposes metadata without children', () => {
  const hive = hiveWith((r) => { r.key('A'); r.key('B'); });
  const root = hive.getRootKey();
  const node = viewModel.treeNode(root, false);
  assert.strictEqual(node.name, 'root');
  assert.strictEqual(node.hasChildren, true);
  assert.strictEqual(node.children, null); // lazy
  assert.strictEqual(node.expanded, false);
  assert.strictEqual(node.warning, false);
});

test('treeNode: expanded node includes sorted children', () => {
  const hive = hiveWith((r) => { r.key('Zebra'); r.key('apple'); });
  const node = viewModel.treeNode(hive.getRootKey(), true);
  assert.deepStrictEqual(node.children.map((c) => c.name), ['apple', 'Zebra']);
});

test('treeNode: warning flag reflects parse warnings', () => {
  const buf = new HiveBuilder().build((r) => { r.key('Good'); r.key('Bad'); }).toBuffer();
  const probe = reg.openHive(buf);
  const badRel = probe.getRootKey().getSubkeys().find((k) => k.name === 'Bad').rel;
  const cell = reg.cellAt(probe.reader, probe.binMap, badRel);
  buf[cell.dataAbs] = 0x71; buf[cell.dataAbs + 1] = 0x71;
  const hive = reg.openHive(buf);
  const root = hive.getRootKey();
  root.getSubkeys(); // force parse, collect warnings
  const node = viewModel.treeNode(root, false);
  assert.strictEqual(node.warning, true);
  assert.ok(node.warningCount >= 1);
});

test('valuesPane: header, columns, and row content', () => {
  const hive = hiveWith((r) => {
    r.value('Name', 1, 'Data');
    r.value('Num', 4, 5);
    r.value('', 4, 0);
  });
  const vm = viewModel.valuesPane(hive.getRootKey());
  assert.strictEqual(vm.keyPath, 'root');
  assert.match(vm.lastWrite, /UTC/);
  assert.deepStrictEqual(vm.columns, ['Name', 'Type', 'Data']);
  assert.strictEqual(vm.rows.length, 3);
  assert.strictEqual(vm.rows[0].name, '(Default)'); // default first
  assert.strictEqual(vm.rows[1].name, 'Name');
  assert.strictEqual(vm.rows[1].type, 'REG_SZ');
  assert.strictEqual(vm.rows[1].data, 'Data');
  assert.strictEqual(vm.rows[2].data, '5');
});

test('hexRows: 16-per-row layout with offset, hex, ascii', () => {
  const bytes = new Uint8Array(36); // 2 full rows + 4 bytes
  for (let i = 0; i < 36; i++) bytes[i] = i + 0x30; // '0'.. printable
  const rows = viewModel.hexRows(bytes);
  assert.strictEqual(rows.length, 3);
  assert.strictEqual(rows[0].offsetHex, '0x00000000');
  assert.match(rows[0].hex, /^30 31 32 .* 3f$/);
  assert.strictEqual(rows[0].ascii.length, 16);
  assert.strictEqual(rows[2].ascii.length, 4);
  assert.strictEqual(rows[2].offset, 32);
});

test('hexRows: windowing via from/to', () => {
  const bytes = new Uint8Array(100);
  const rows = viewModel.hexRows(bytes, { from: 16, to: 40 });
  assert.strictEqual(rows.length, 2); // 16..31, 32..39 (partial)
  assert.strictEqual(rows[0].offset, 16);
});

test('hexRows: non-printable bytes render as dots', () => {
  const rows = viewModel.hexRows(new Uint8Array([0x00, 0x41, 0xff]));
  assert.strictEqual(rows[0].ascii, '·A·');
});

test('hiveMeta: metadata rows and warnings', () => {
  const hive = hiveWith(() => {}, { fileName: '\\??\\C:\\Windows\\SYSTEM32\\CONFIG\\SAM' });
  const vm = viewModel.hiveMeta(hive);
  assert.strictEqual(vm.title, '\\??\\C:\\Windows\\SYSTEM32\\CONFIG\\SAM');
  const byKey = Object.fromEntries(vm.rows);
  assert.strictEqual(byKey['Format version'], '1.5');
  assert.strictEqual(byKey['Dirty (logs not applied)'], 'no');
  assert.strictEqual(byKey['Checksum valid'], 'yes');
});

test('statusBar: composes selection info', () => {
  const hive = hiveWith((r) => { r.key('K').value('v', 4, 1); });
  const key = hive.getSubkey('K');
  const vm = viewModel.statusBar(hive, key, null);
  assert.match(vm.text, /root\\K/);
  assert.match(vm.text, /0 keys, 1 values/);
  const withCounts = viewModel.statusBar(hive, key, { keys: 2, values: 1 });
  assert.match(withCounts.text, /total: 2 keys/);
});
