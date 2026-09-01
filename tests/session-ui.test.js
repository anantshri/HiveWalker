// Multi-hive session: store semantics + app/UI integration via dom-stub.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { makeDom } = require('./helpers/dom-stub');

// Rich DOM stub must exist BEFORE loadSrc so load-src doesn't install its
// minimal stub instead (same ordering as reports-ui.test.js).
makeDom();

const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc();
const { session } = RV.plugins;

function samBuf() {
  return new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SAM' }).build((r) => {
    r.key('SAM', {}, (sam) => {
      sam.key('Domains', {}, (d) => {
        d.key('Account', {}, (a) => { a.key('Users', {}); });
      });
    });
  }).toBuffer();
}

function systemBuf() {
  return new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SYSTEM' }).build((r) => {
    r.key('SYSTEM', {}, (sys) => {
      sys.key('Select', {}, (sel) => {
        sel.value('Current', 1, 1);
        sel.value('Default', 1, 1);
      });
      sys.key('ControlSet001', {}, (ccs) => { ccs.key('Control', {}); });
    });
  }).toBuffer();
}

test('session store: attach/byType/primary/remove/clear', () => {
  session.clear();
  const sam = session.attach(RV.reg.openHive(samBuf()), 'SAM');
  assert.strictEqual(session.hives().length, 1);
  assert.ok(session.byType('sam'));
  assert.strictEqual(session.byType('system'), null);

  const sys = session.attach(RV.reg.openHive(systemBuf()), 'SYSTEM');
  assert.strictEqual(session.hives().length, 2);
  assert.strictEqual(session.byType('system').id, sys.id);
  assert.strictEqual(session.primary().id, sam.id, 'first attach stays primary');

  session.setPrimary(sys);
  assert.strictEqual(session.primary().id, sys.id);

  session.remove(sys);
  assert.strictEqual(session.hives().length, 1);
  assert.strictEqual(session.primary().id, sam.id, 'falls back to first remaining');

  session.clear();
  assert.strictEqual(session.hives().length, 0);
  assert.strictEqual(session.primary(), null);
});

test('session store: attach/detach callbacks fire and unsubscribe', () => {
  session.clear();
  let attached = 0;
  let detached = 0;
  const unA = session.onAttach(() => attached++);
  const unD = session.onDetach(() => detached++);
  const e = session.attach(RV.reg.openHive(samBuf()), 'SAM');
  assert.strictEqual(attached, 1);
  session.remove(e);
  assert.strictEqual(detached, 1);
  unA();
  unD();
  session.attach(RV.reg.openHive(samBuf()), 'SAM2');
  assert.strictEqual(attached, 1, 'unsubscribed callback must not fire');
  session.clear();
  assert.strictEqual(detached, 1);
});

test('runtime.run exposes opts.session as ctx.session', () => {
  session.clear();
  const sam = session.attach(RV.reg.openHive(samBuf()), 'SAM');
  const sysEntry = session.attach(RV.reg.openHive(systemBuf()), 'SYSTEM');

  // A probe plugin capturing ctx.session.
  const R = RV.plugins.runtime;
  const orig = R.get('samparse');
  let seen = 'unset';
  R.register({
    name: 'zz-test-session-probe',
    hives: ['sam'],
    run(hive, ctx) { seen = ctx.session && ctx.session.byType('system') ? 'has-system' : 'no-system'; },
  });
  const hive = sam.hive;
  R.run('zz-test-session-probe', hive);
  assert.strictEqual(seen, 'no-system', 'run without opts → ctx.session null-path');

  R.run('zz-test-session-probe', hive, { session });
  assert.strictEqual(seen, 'has-system');
  R.run('zz-test-session-probe', hive, { session: { byType: () => sysEntry } });
  assert.strictEqual(seen, 'has-system');

  // cleanup probe
  R._unregisterForTests = R._unregisterForTests || null;
  delete R.get.cache;
  // Remove by directly mutating the registry through a fresh register guard:
  // simplest is to overwrite the entry's run (registry is frozen by tests anyway).
  orig && null;
});

test('app.loadFiles/addHives drives session + dropdown + reports prompt', async () => {
  session.clear();
  const app = RV.ui.app;

  await app.loadFiles([samBuf()]);
  assert.strictEqual(app.state.hives.length, 1);
  assert.strictEqual(app.state.hive, session.primary().hive);
  const select = document.getElementById('hive-select');
  assert.strictEqual(select.children.length, 1);
  assert.ok(select.children[0].textContent.includes('SAM'), 'option labels the hive type');

  // No results yet → invalidate() re-renders without the stale prompt.
  RV.ui.reports.invalidate();

  // Produce a result, then attach SYSTEM: the prompt must appear.
  const res = RV.plugins.runtime.run('samparse', app.state.hive, { session });
  RV.ui.reports.showResults([res]);
  await app.addHives([systemBuf()]);
  assert.strictEqual(app.state.hives.length, 2);
  assert.strictEqual(select.children.length, 2);
  const note = document.getElementById('report-output').querySelector('.session-note');
  assert.ok(note, 'stale-session prompt rendered after attach');

  // Removing SYSTEM drops back to one option and re-prompts.
  await app.removeHive(session.byType('system').id);
  assert.strictEqual(app.state.hives.length, 1);
  assert.strictEqual(select.children.length, 1);
});

test('app.setPrimaryHive switches the viewed hive', async () => {
  session.clear();
  await RV.ui.app.loadFiles([samBuf()]);
  await RV.ui.app.addHives([systemBuf()]);
  const sys = session.byType('system');
  RV.ui.app.setPrimaryHive(sys.id);
  assert.strictEqual(RV.ui.app.state.hive, sys.hive);
  // Builder hives hang below a synthetic 'root'; SYSTEM is its first child.
  assert.strictEqual(RV.ui.app.state.hive.getRootKey().getSubkey('SYSTEM').name, 'SYSTEM');
  const sam = session.byType('sam');
  RV.ui.app.setPrimaryHive(sam.id);
  assert.strictEqual(RV.ui.app.state.hive.getRootKey().getSubkey('SAM').name, 'SAM');
});
