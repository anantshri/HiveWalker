'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime } = RV.plugins;

// A hive with the control-set + marker keys present so getControlSet resolves
// and both software/ntuser branches are exercised. The descriptors' target
// data keys are mostly absent → every plugin must degrade gracefully.
const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SYSTEM' }).build((r) => {
  r.key('Select', {}, (s) => s.value('Current', 4, 1));
  r.key('MountedDevices');
  r.key('ControlSet001', {}, (cs) => cs.key('Control'));
  r.key('Microsoft', {}, (m) => {
    m.key('Windows', {}, (w) => w.key('CurrentVersion'));
    m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion'));
  });
}).toBuffer());

test('all descriptor plugins are registered', () => {
  const simple = runtime.all().filter((p) => p.simple);
  assert.ok(simple.length >= 130, `expected 130+ descriptor plugins, got ${simple.length}`);
});

test('every descriptor plugin runs without throwing (graceful not-found)', () => {
  const failures = [];
  for (const p of runtime.all().filter((x) => x.simple)) {
    const res = runtime.run(p, hive);
    if (res.error) failures.push(`${p.name}: ${res.error.name}: ${res.error.message}`);
    // Must always produce at least one section (data or a not-found note).
    if (!res.sections || res.sections.length === 0) failures.push(`${p.name}: no sections`);
  }
  assert.deepStrictEqual(failures, [], failures.join('\n'));
});

test('descriptor engine surfaces data when the target key exists (values mode)', () => {
  // screensaver: ntuser, values, Control Panel\Desktop
  const nt = RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => {
    r.key('Control Panel', {}, (cp) => cp.key('Desktop', {}, (d) => {
      d.value('SCRNSAVE.EXE', 1, 'C:\\Windows\\scrnsave.scr');
      d.value('ScreenSaveTimeOut', 1, '600');
    }));
  }).toBuffer());
  const t = RV.ui.viewModel.reportText(runtime.run('screensaver', nt));
  assert.match(t, /scrnsave\.scr/);
  assert.match(t, /600/);
});

test('descriptor engine resolves CCS-relative paths (system, values)', () => {
  // A ccs descriptor: find one and feed it its key under ControlSet001.
  const ccsPlugin = runtime.all().find((p) => p.simple && p.name === 'trailersupport');
  if (!ccsPlugin) return; // tolerate corpus changes
  const sys = RV.reg.openHive(new HiveBuilder({ fileName: 'SYSTEM' }).build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('MountedDevices');
    r.key('ControlSet001', {}, (cs) => cs.key('Services', {}, (svc) => svc.key('HTTP', {}, (h) => h.key('Parameters', {}, (p) => p.value('EnableTrailerSupport', 4, 1)))));
  }).toBuffer());
  const t = RV.ui.viewModel.reportText(runtime.run('trailersupport', sys));
  assert.match(t, /ControlSet001\\Services\\HTTP\\Parameters/);
  assert.match(t, /EnableTrailerSupport/);
});
