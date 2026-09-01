'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime, helpers } = RV.plugins;

const hive = RV.reg.openHive(new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SAM' }).build((r) => {
  r.key('SAM', {}, (s) => s.key('Domains', {}, (d) => d.key('Account', {}, (a) => a.key('Users', {}, (users) => {
    users.key('Names', {}, (names) => {
      names.key('Administrator');
      names.key('alice');
    });
    users.key('000001F4'); // RID 500
    users.key('000003E9'); // RID 1001
  }))));
}).toBuffer());

const text = (name) => RV.ui.viewModel.reportText(runtime.run(name, hive));

test('hive detected as sam', () => {
  assert.ok(helpers.guessHiveType(hive).has('sam'));
});

test('samparse: usernames from Names, RIDs decoded hex→dec', () => {
  const t = text('samparse');
  assert.match(t, /Administrator/);
  assert.match(t, /alice/);
  assert.match(t, /000001F4/);
  assert.match(t, /\b500\b/);
  assert.match(t, /\b1001\b/);
});
