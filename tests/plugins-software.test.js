'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime } = RV.plugins;

const INSTALL_UNIX = 1609459200; // 2021-01-01T00:00:00Z

const hive = RV.reg.openHive(new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SOFTWARE' }).build((r) => {
  r.key('Microsoft', {}, (m) => {
    m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => {
      cv.key('Run', {}, (run) => {
        run.value('OneDrive', 1, 'C:\\OneDrive.exe');
        run.value('Sidebar', 2, '%ProgramFiles%\\Sidebar.exe');
      });
      cv.key('Uninstall', {}, (un) => un.key('App1', {}, (a) => {
        a.value('DisplayName', 1, 'App One');
        a.value('DisplayVersion', 1, '1.2.3');
        a.value('Publisher', 1, 'ACME Corp');
      }));
    }));
    m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion', {}, (cv) => {
      cv.value('ProductName', 1, 'Windows 10 Pro');
      cv.value('ReleaseID', 1, '2009');
      cv.value('CurrentBuild', 1, '19045');
      cv.value('RegisteredOwner', 1, 'Alice');
      cv.value('InstallDate', 4, INSTALL_UNIX);
      cv.key('ProfileList', {}, (pl) => pl.key('S-1-5-21-1001', {}, (s) => s.value('ProfileImagePath', 1, 'C:\\Users\\Alice')));
      cv.key('NetworkCards', {}, (nc) => nc.key('1', {}, (c) => {
        c.value('Description', 1, 'Intel Ethernet NIC');
        c.value('ServiceName', 1, '{svc-guid}');
      }));
    }));
  });
}).toBuffer());

const text = (name) => RV.ui.viewModel.reportText(runtime.run(name, hive));

test('winver: product info + InstallDate (DWORD unix epoch)', () => {
  const t = text('winver');
  assert.match(t, /Windows 10 Pro/);
  assert.match(t, /ReleaseID\s+2009/);
  assert.match(t, /RegisteredOwner\s+Alice/);
  assert.match(t, /InstallDate\s+2021-01-01 00:00:00 UTC/);
});

test('uninstall: display name, version, publisher', () => {
  const t = text('uninstall');
  assert.match(t, /App One/);
  assert.match(t, /1\.2\.3/);
  assert.match(t, /ACME Corp/);
});

test('run: reports autostart values (SW + expanded path)', () => {
  const t = text('run');
  assert.match(t, /Microsoft\\Windows\\CurrentVersion\\Run/);
  assert.match(t, /OneDrive/);
  assert.match(t, /C:\\OneDrive\.exe/);
  assert.match(t, /Sidebar/);
});

test('profilelist: SID → ProfileImagePath', () => {
  const t = text('profilelist');
  assert.match(t, /S-1-5-21-1001/);
  assert.match(t, /C:\\Users\\Alice/);
});

test('networkcards: description listed', () => {
  assert.match(text('networkcards'), /Intel Ethernet NIC/);
});

test('applicable set for a SOFTWARE hive includes winver, run, uninstall', () => {
  const names = runtime.applicableTo(hive).map((p) => p.name);
  for (const n of ['winver', 'run', 'uninstall', 'profilelist', 'networkcards']) assert.ok(names.includes(n), n);
});
