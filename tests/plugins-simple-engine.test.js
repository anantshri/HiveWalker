'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime, simple } = RV.plugins;

function open(hb) { return RV.reg.openHive(hb.toBuffer()); }
const text = (name, hive) => RV.ui.viewModel.reportText(runtime.run(name, hive));

test('registerSimple: rejects a descriptor with no paths', () => {
  assert.throws(() => simple.registerSimple({ name: 'bad', hives: ['software'] }), /paths\[\] required/);
});

test('mode values: dumps all values of a key', () => {
  simple.registerSimple({
    name: 't-values', hives: ['software'], version: '1', mode: 'values',
    paths: ['Vendor\\App'],
  });
  const hive = open(new HiveBuilder().build((r) => r.key('Vendor', {}, (v) => v.key('App', {}, (a) => {
    a.value('Path', 1, 'C:\\app.exe');
    a.value('Port', 4, 8080);
  }))));
  const t = text('t-values', hive);
  assert.match(t, /Path.*C:\\app\.exe/s);
  assert.match(t, /Port.*8080/s);
});

test('mode named: dumps only the listed values', () => {
  simple.registerSimple({
    name: 't-named', hives: ['software'], version: '1', mode: 'named',
    names: ['Wanted'], paths: ['K'],
  });
  const hive = open(new HiveBuilder().build((r) => r.key('K', {}, (k) => {
    k.value('Wanted', 1, 'yes');
    k.value('Ignored', 1, 'no');
  })));
  const t = text('t-named', hive);
  assert.match(t, /Wanted.*yes/s);
  assert.doesNotMatch(t, /Ignored/);
});

test('mode subkeys: lists subkeys with selected values + LastWrite', () => {
  simple.registerSimple({
    name: 't-subkeys', hives: ['software'], version: '1', mode: 'subkeys',
    subkeyNames: ['DisplayName'], paths: ['Apps'],
  });
  const hive = open(new HiveBuilder().build((r) => r.key('Apps', {}, (a) => {
    a.key('App1', {}, (k) => k.value('DisplayName', 1, 'First App'));
    a.key('App2', {}, (k) => k.value('DisplayName', 1, 'Second App'));
  })));
  const t = text('t-subkeys', hive);
  assert.match(t, /App1.*First App/s);
  assert.match(t, /App2.*Second App/s);
});

test('mode mru: orders by MRUListEx', () => {
  simple.registerSimple({
    name: 't-mru', hives: ['ntuser'], version: '1', mode: 'mru',
    paths: ['MRUKey'],
  });
  const hive = open(new HiveBuilder().build((r) => r.key('MRUKey', {}, (k) => {
    k.value('MRUListEx', 3, Buffer.from([1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]));
    k.value('0', 1, 'first');
    k.value('1', 1, 'second');
  })));
  const t = text('t-mru', hive);
  // order is 1 then 0 → "second" appears before "first"
  assert.ok(t.indexOf('second') < t.indexOf('first'));
});

test('mode mru: orders by old-style MRUList (letters)', () => {
  simple.registerSimple({
    name: 't-mru2', hives: ['ntuser'], version: '1', mode: 'mru',
    paths: ['MRUKey2'],
  });
  const hive = open(new HiveBuilder().build((r) => r.key('MRUKey2', {}, (k) => {
    k.value('MRUList', 1, 'ba');
    k.value('a', 1, 'alpha');
    k.value('b', 1, 'bravo');
  })));
  const t = text('t-mru2', hive);
  assert.ok(t.indexOf('bravo') < t.indexOf('alpha')); // order b,a
});

test('ccs prefix: system descriptor resolves ControlSetNNN', () => {
  simple.registerSimple({
    name: 't-ccs', hives: ['system'], version: '1', mode: 'values', ccs: true,
    paths: ['Control\\Thing'],
  });
  const hive = open(new HiveBuilder().build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('MountedDevices');
    r.key('ControlSet001', {}, (cs) => cs.key('Control', {}, (c) => c.key('Thing', {}, (th) => th.value('V', 1, 'ok'))));
  }));
  const t = text('t-ccs', hive);
  assert.match(t, /ControlSet001\\Control\\Thing/);
  assert.match(t, /ok/);
});

test('multi-path + not-found: missing paths reported gracefully', () => {
  simple.registerSimple({
    name: 't-multi', hives: ['software'], version: '1', mode: 'values',
    paths: ['A\\X', 'B\\X'],
  });
  const present = open(new HiveBuilder().build((r) => r.key('B', {}, (b) => b.key('X', {}, (x) => x.value('v', 1, 'hi')))));
  assert.match(text('t-multi', present), /B\\X/);

  const absent = open(new HiveBuilder().build((r) => r.key('Nothing')));
  const res = runtime.run('t-multi', absent);
  assert.strictEqual(res.error, null);
  assert.match(RV.ui.viewModel.reportText(res), /None of the target paths were found/);
});

test('registerAll: registers a batch and skips malformed descriptors', () => {
  const ok = simple.registerAll([
    { name: 't-batch-1', hives: ['software'], version: '1', mode: 'values', paths: ['P'] },
    { name: 't-batch-bad', hives: ['software'] }, // no paths → skipped
    { name: 't-batch-2', hives: ['software'], version: '1', mode: 'values', paths: ['Q'] },
  ]);
  assert.strictEqual(ok, 2);
  assert.ok(runtime.get('t-batch-1'));
  assert.ok(runtime.get('t-batch-2'));
  assert.strictEqual(runtime.get('t-batch-bad'), null);
});
