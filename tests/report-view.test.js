'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /20-view-model/ });
const { viewModel } = RV.ui;

// Hand-built result objects — the DOM-free view-model needs no hive.
function fakeResult(overrides) {
  return Object.assign({
    plugin: 'demo', shortDescr: 'Demo plugin', hiveTypes: ['system'],
    category: 'config', mitre: 'T1082', version: '20240101', ranAt: new Date(),
    error: null,
    sections: [{
      title: 'Section A',
      blocks: [
        { kind: 'text', lines: ['hello', 'world'] },
        { kind: 'kv', pairs: [['Key', 'Val']] },
        { kind: 'note', text: 'a tip' },
        { kind: 'table', columns: ['C1', 'C2'], rows: [['a', 'b']] },
      ],
    }],
  }, overrides);
}

test('reportText: banner, MITRE line, and all block kinds', () => {
  const t = viewModel.reportText(fakeResult());
  assert.match(t, /^demo v\.20240101/);
  assert.match(t, /\(system\) Demo plugin/);
  assert.match(t, /MITRE: T1082 \(config\)/);
  assert.match(t, /Section A/);
  assert.match(t, /hello/);
  assert.match(t, /Key\s+Val/);
  assert.match(t, /a tip/);
  assert.match(t, /C1 \| C2/);
  assert.match(t, /a \| b/);
});

test('reportText: error short-circuits the body', () => {
  const t = viewModel.reportText(fakeResult({ error: { name: 'TypeError', message: 'nope' }, sections: [] }));
  assert.match(t, /ERROR: TypeError: nope/);
});

test('reportView: meta rows, title, and empty flag', () => {
  const v = viewModel.reportView(fakeResult());
  assert.strictEqual(v.title, 'demo — Demo plugin');
  assert.deepStrictEqual(v.meta[0], ['Hive', 'system']);
  assert.strictEqual(v.empty, false);

  const emptyView = viewModel.reportView(fakeResult({ sections: [{ title: 'X', blocks: [] }] }));
  assert.strictEqual(emptyView.empty, true);
});

test('reportTextAll: joins multiple results with a separator', () => {
  const t = viewModel.reportTextAll([fakeResult(), fakeResult({ plugin: 'demo2' })]);
  assert.match(t, /demo v\./);
  assert.match(t, /demo2 v\./);
  assert.match(t, /-{60}/);
});

test('pluginList: applicable plugins sorted first, with detected types', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('MountedDevices');
  }).toBuffer());
  const list = viewModel.pluginList(hive);
  assert.ok(list.detectedTypes.includes('system'));
  assert.ok(list.plugins.length >= 17);
  // Everything applicable comes before anything non-applicable.
  const firstNonApplicable = list.plugins.findIndex((p) => !p.applicable);
  const lastApplicable = list.plugins.map((p) => p.applicable).lastIndexOf(true);
  assert.ok(firstNonApplicable === -1 || firstNonApplicable > lastApplicable);
  assert.ok(list.plugins.find((p) => p.name === 'compname').applicable);
});
