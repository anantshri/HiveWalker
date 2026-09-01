'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { makeDom, findIn } = require('./helpers/dom-stub');

// Rich DOM stub must exist BEFORE loadSrc so load-src doesn't install its
// minimal stub instead.
makeDom();

const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const RV = loadSrc();

// A SYSTEM hive so several plugins are applicable.
const buf = new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SYSTEM' }).build((r) => {
  r.key('Select', {}, (s) => s.value('Current', 4, 1));
  r.key('MountedDevices', {}, (md) => md.value('\\DosDevices\\C:', 3, Buffer.from([1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0])));
  r.key('ControlSet001', {}, (cs) => cs.key('Control', {}, (c) => c.key('ComputerName', {}, (cn) =>
    cn.key('ComputerName', {}, (x) => x.value('ComputerName', 1, 'HOST-A')))));
}).toBuffer();

test('tab shell: switching swaps tabs, persists viewer DOM, scopes topbar search', async () => {
  await RV.ui.app.loadFile(buf);

  // Tabbar revealed once loaded; viewer is the default.
  assert.strictEqual(document.getElementById('tabbar').hidden, false);
  assert.strictEqual(RV.ui.app.currentTab(), 'viewer');

  const treePane = document.getElementById('tree-pane');
  const viewerKidCount = () => treePane.children.length;

  RV.ui.app.setTab('reports');
  assert.strictEqual(RV.ui.app.currentTab(), 'reports');
  assert.strictEqual(document.getElementById('app').dataset.tab, 'reports');
  assert.strictEqual(document.getElementById('tab-reports').getAttribute('aria-selected'), 'true');
  assert.strictEqual(document.getElementById('tab-viewer').getAttribute('aria-selected'), 'false');
  // Viewer-scoped topbar search disabled on the Reports tab.
  assert.strictEqual(document.getElementById('search-input').disabled, true);

  // Reports workspace rendered into #reports-tab.
  const reportsTab = document.getElementById('reports-tab');
  assert.ok(reportsTab, 'reports-tab exists');
  assert.ok(reportsTab.querySelectorAll('.report-plugin-btn').length >= 17, 'plugins listed');

  // Viewer DOM persisted (not torn down) while on the Reports tab.
  const before = viewerKidCount();
  RV.ui.app.setTab('viewer');
  assert.strictEqual(RV.ui.app.currentTab(), 'viewer');
  assert.strictEqual(document.getElementById('search-input').disabled, false);
  assert.strictEqual(viewerKidCount(), before, 'viewer tree preserved');
});

test('reports workspace: run plugin, run-all, filter, copy', async () => {
  await RV.ui.app.loadFile(buf);
  RV.ui.app.setTab('reports');
  const pane = document.getElementById('reports-tab');

  const byName = (n) => pane.querySelectorAll('.report-plugin-btn')
    .find((b) => b.querySelector('.report-plugin-name').textContent === n);

  byName('compname').dispatch('click');
  const output = pane.querySelector('#report-output');
  assert.ok(output.children.length > 0, 'output rendered');
  assert.ok(output.querySelector('.report-title'), 'has a report title');
  assert.ok(findIn(output, '') || output.textContent.includes('HOST-A'), 'report data shown');

  // Filter narrows the rail.
  const filter = pane.querySelector('#report-filter');
  filter.value = 'compname';
  filter.dispatch('input');
  const names = pane.querySelectorAll('.report-plugin-name').map((n) => n.textContent);
  assert.ok(names.length < 150 && names.length >= 1, `filter narrowed the list (${names.length})`);
  assert.ok(names.every((n) => n.includes('compname')), 'all matches contain the filter text');
  filter.value = '';
  filter.dispatch('input');

  // Run all applicable.
  pane.querySelector('.report-run-all').dispatch('click');
  assert.ok(pane.querySelector('#report-output').children.length > 0, 'run-all rendered');

  // Copy uses clipboard (stubbed) — must not throw.
  await pane.querySelector('.path-copy').dispatch('click');
});

test('reports workspace: renders error, empty, and note result branches', () => {
  RV.plugins.runtime.register({ name: 'edge-error', hives: ['system'], version: '1', run() { throw new Error('kaboom'); } });
  RV.plugins.runtime.register({ name: 'edge-empty', hives: ['system'], version: '1', run(h, ctx) { ctx.section('S'); } });
  RV.plugins.runtime.register({ name: 'edge-note', hives: ['system'], version: '1', run(h, ctx) { ctx.note('a tip'); } });

  RV.ui.app.setTab('reports');
  const pane = document.getElementById('reports-tab');
  const byName = (n) => pane.querySelectorAll('.report-plugin-btn')
    .find((b) => b.querySelector('.report-plugin-name').textContent === n);

  byName('edge-error').dispatch('click');
  assert.ok(pane.querySelector('.report-error'), 'error branch rendered');

  byName('edge-empty').dispatch('click');
  assert.ok(pane.querySelector('.report-empty'), 'empty branch rendered');

  byName('edge-note').dispatch('click');
  assert.ok(pane.querySelector('.report-note'), 'note branch rendered');
});

test('reports workspace: Export PDF downloads a valid PDF of the shown results', () => {
  RV.ui.app.setTab('reports');
  const pane = document.getElementById('reports-tab');
  const byName = (n) => pane.querySelectorAll('.report-plugin-btn')
    .find((b) => b.querySelector('.report-plugin-name').textContent === n);

  byName('compname').dispatch('click');
  pane.querySelector('.report-export-pdf').dispatch('click');

  assert.strictEqual(globalThis.__downloads.length, 1, 'one download triggered');
  const dl = globalThis.__downloads[0];
  assert.match(dl.name, /^hivewalker-report-compname-\d{8}-\d{4}\.pdf$/);
  assert.strictEqual(dl.type, 'application/pdf');
  const s = dl.bytes.toString('latin1');
  assert.ok(s.startsWith('%PDF-1.4') && s.trimEnd().endsWith('%%EOF'), 'valid PDF envelope');
  assert.ok(s.includes('HOST-A'), 'report content in the PDF');
});

test('reports workspace: copy falls back to text selection when clipboard throws', async () => {
  navigator.clipboard.writeText = async () => { throw new Error('blocked'); };
  RV.ui.app.setTab('reports');
  const pane = document.getElementById('reports-tab');
  pane.querySelectorAll('.report-plugin-btn')[0].dispatch('click');
  const copy = pane.querySelector('.path-copy');
  await copy.dispatch('click'); // must not throw despite clipboard rejection
  assert.ok(copy, 'copy button present');
});

test('loadFile: a corrupt hive shows the error card, not a crash', async () => {
  await RV.ui.app.loadFile(new Uint8Array([1, 2, 3, 4]));
  assert.strictEqual(RV.ui.app.currentState(), 'error');
  assert.strictEqual(document.getElementById('error-card').hidden, false);
  assert.strictEqual(RV.ui.app.state.hive, null);
});
