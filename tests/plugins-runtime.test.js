'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

// Load reg + plugin layers (no UI needed for runtime/helpers tests).
const RV = loadSrc({ only: /plugins\/43-sam/ });
const { runtime, helpers } = RV.plugins;

function open(hb) { return RV.reg.openHive(hb.toBuffer()); }

// --- guessHiveType ---------------------------------------------------------

test('guessHiveType: SYSTEM via MountedDevices + Select', () => {
  const hive = open(new HiveBuilder().build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('MountedDevices');
    r.key('ControlSet001');
  }));
  assert.ok(helpers.guessHiveType(hive).has('system'));
});

test('guessHiveType: SOFTWARE via CurrentVersion marker keys', () => {
  const hive = open(new HiveBuilder().build((r) => {
    r.key('Microsoft', {}, (m) => {
      m.key('Windows', {}, (w) => w.key('CurrentVersion'));
      m.key('Windows NT', {}, (w) => w.key('CurrentVersion'));
    });
  }));
  assert.ok(helpers.guessHiveType(hive).has('software'));
});

test('guessHiveType: SAM via Domains\\Account\\Users', () => {
  const hive = open(new HiveBuilder().build((r) => {
    r.key('SAM', {}, (s) => s.key('Domains', {}, (d) => d.key('Account', {}, (a) => a.key('Users'))));
  }));
  assert.ok(helpers.guessHiveType(hive).has('sam'));
});

test('guessHiveType: embedded filename basename becomes a tag', () => {
  const hive = open(new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SYSTEM' }).build((r) => {
    r.key('Placeholder');
  }));
  const tags = helpers.guessHiveType(hive);
  assert.ok(tags.has('system'), 'basename "system" from embedded name');
});

test('guessHiveType: unknown when no markers match', () => {
  const hive = open(new HiveBuilder({ fileName: '' }).build((r) => r.key('Nothing')));
  assert.ok(helpers.guessHiveType(hive).has('unknown'));
});

// --- getControlSet ---------------------------------------------------------

test('getControlSet: reads Select\\Current → ControlSet001', () => {
  const hive = open(new HiveBuilder().build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('ControlSet001', {}, (c) => c.key('Control'));
  }));
  const ccs = helpers.getControlSet(hive);
  assert.strictEqual(ccs.name, 'ControlSet001');
  assert.ok(ccs.key);
});

test('getControlSet: honours Current=2', () => {
  const hive = open(new HiveBuilder().build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 2));
    r.key('ControlSet001');
    r.key('ControlSet002');
  }));
  assert.strictEqual(helpers.getControlSet(hive).name, 'ControlSet002');
});

test('getControlSet: falls back to ControlSet001 when Select missing', () => {
  const hive = open(new HiveBuilder().build((r) => r.key('ControlSet001')));
  assert.strictEqual(helpers.getControlSet(hive).name, 'ControlSet001');
});

test('getControlSet: falls back to first ControlSetNNN present', () => {
  const hive = open(new HiveBuilder().build((r) => r.key('ControlSet003')));
  assert.strictEqual(helpers.getControlSet(hive).name, 'ControlSet003');
});

test('getControlSet: null when no control set exists', () => {
  const hive = open(new HiveBuilder().build((r) => r.key('Nothing')));
  assert.strictEqual(helpers.getControlSet(hive).name, null);
  assert.strictEqual(helpers.getControlSet(hive).key, null);
});

// --- registry / run / runAll ----------------------------------------------

test('register: rejects malformed plugins', () => {
  assert.throws(() => runtime.register({}), /name required/);
  assert.throws(() => runtime.register({ name: 'x' }), /hives\[\] required/);
  assert.throws(() => runtime.register({ name: 'x', hives: ['system'] }), /run\(\) required/);
});

test('register: rejects duplicate names', () => {
  assert.throws(() => runtime.register({ name: 'compname', hives: ['system'], run() {} }), /already registered/);
});

test('run: captures a thrown plugin error instead of propagating', () => {
  runtime.register({ name: 'test-throw', hives: ['system'], version: '1', run() { throw new Error('boom'); } });
  const hive = open(new HiveBuilder().build((r) => r.key('X')));
  const res = runtime.run('test-throw', hive);
  assert.strictEqual(res.error.message, 'boom');
  assert.strictEqual(res.plugin, 'test-throw');
});

test('applicableTo: filters by detected hive types', () => {
  const hive = open(new HiveBuilder().build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('MountedDevices');
  }));
  const names = runtime.applicableTo(hive).map((p) => p.name);
  assert.ok(names.includes('compname'), 'system plugin applicable');
  assert.ok(!names.includes('winver'), 'software plugin not applicable');
});

test('runAll: honours an already-aborted signal', () => {
  const hive = open(new HiveBuilder().build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('MountedDevices');
  }));
  const ctrl = new AbortController();
  ctrl.abort();
  const { results, aborted } = runtime.runAll(hive, { signal: ctrl.signal });
  assert.strictEqual(aborted, true);
  assert.strictEqual(results.length, 0);
});

// --- report builder (ctx) --------------------------------------------------

test('makeContext: builds structured sections/blocks', () => {
  const ctx = helpers.makeContext();
  ctx.section('S1');
  ctx.rptMsg('line1');
  ctx.rptMsg('line2');
  ctx.kv('a', 1);
  ctx.note('tip');
  const t = ctx.table(['c1', 'c2']);
  t.row(['x', 'y']);
  const secs = ctx.sections();
  assert.strictEqual(secs.length, 1);
  assert.strictEqual(secs[0].title, 'S1');
  assert.deepStrictEqual(secs[0].blocks[0], { kind: 'text', lines: ['line1', 'line2'] });
  assert.deepStrictEqual(secs[0].blocks[1], { kind: 'kv', pairs: [['a', '1']] });
  assert.deepStrictEqual(secs[0].blocks[2], { kind: 'note', text: 'tip' });
  assert.deepStrictEqual(secs[0].blocks[3], { kind: 'table', columns: ['c1', 'c2'], rows: [['x', 'y']] });
});

test('makeContext: table truncates beyond MAX_PLUGIN_ROWS', () => {
  const ctx = helpers.makeContext();
  const t = ctx.table(['n']);
  for (let i = 0; i < helpers.MAX_PLUGIN_ROWS + 50; i++) t.row([i]);
  const rows = ctx.sections()[0].blocks[0].rows;
  assert.strictEqual(rows.length, helpers.MAX_PLUGIN_ROWS + 1);
  assert.deepStrictEqual(rows[rows.length - 1], ['(truncated)']);
});
