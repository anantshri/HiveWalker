'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime } = RV.plugins;
const text = (name, hive) => RV.ui.viewModel.reportText(runtime.run(name, hive));

function u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; }
function filenameBytes(name) {
  return Buffer.concat([Buffer.from(name, 'utf16le'), Buffer.from([0, 0])]);
}

// A hive with the marker keys present but the target data keys absent, so every
// plugin exercises its graceful "not found" path without erroring.
const barren = RV.reg.openHive(new HiveBuilder().build((r) => {
  r.key('Select', {}, (s) => s.value('Current', 4, 1));
  r.key('MountedDevices');           // present but empty → (none) sections
  r.key('ControlSet001');            // no Control/Services/Enum children
  r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => {
    m.key('Windows', {}, (w) => w.key('CurrentVersion'));
    m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion'));
  }));
}).toBuffer());

for (const name of ['compname', 'timezone', 'shutdown', 'services', 'usbstor', 'ips',
  'winver', 'uninstall', 'run', 'profilelist', 'networkcards',
  'userassist', 'recentdocs', 'typedpaths', 'runmru', 'samparse']) {
  test(`${name}: missing target keys → graceful, no error`, () => {
    const res = runtime.run(name, barren);
    assert.strictEqual(res.error, null, `${name} threw: ${res.error && res.error.message}`);
    // Produces some output (a "not found"/"(none)" line or empty section note).
    assert.ok(RV.ui.viewModel.reportView(res).sections.length > 0);
  });
}

test('mountdev: empty key reports (none) for each category', () => {
  assert.match(text('mountdev', barren), /Drives[\s\S]*\(none\)/);
});

test('shutdown: Windows key present but ShutdownTime value absent', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SYSTEM' }).build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('MountedDevices');
    r.key('ControlSet001', {}, (cs) => cs.key('Control', {}, (c) => c.key('Windows')));
  }).toBuffer());
  assert.match(text('shutdown', hive), /ShutdownTime value not found/);
});

// UserAssist variant branches: zero-timestamp XP + Win7 records and an
// odd-length value all fall into the "no time stamps" list.
test('userassist: entries with no timestamp are listed separately', () => {
  const EXPLORER = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer';
  const H = RV.plugins.helpers;
  const data16zero = Buffer.concat([u32(0), u32(3), Buffer.alloc(8)]); // val2==0 → no time
  const data72zero = Buffer.alloc(72);                                  // FILETIME all zero
  const oddLen = Buffer.from([1, 2, 3, 4, 5]);                          // neither 16 nor 72
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => {
      m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => cv.key('Explorer', {}, (ex) =>
        ex.key('UserAssist', {}, (ua) => ua.key('{G}', {}, (g) => g.key('Count', {}, (count) => {
          count.value(H.rot13('NoTimeXP'), 3, data16zero);
          count.value(H.rot13('NoTimeWin7'), 3, data72zero);
          count.value(H.rot13('OddLen'), 3, oddLen);
        }))))));
      m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion'));
    }));
  }).toBuffer());
  const t = text('userassist', hive);
  assert.match(t, /Value names with no time stamps:/);
  assert.match(t, /NoTimeXP/);
  assert.match(t, /NoTimeWin7/);
  assert.match(t, /OddLen/);
});

test('typedpaths: present but empty key reports "no values"', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => {
      m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => cv.key('Explorer', {}, (ex) => ex.key('TypedPaths'))));
      m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion'));
    }));
  }).toBuffer());
  assert.match(text('typedpaths', hive), /TypedPaths has no values/);
});

test('samparse: Users present but no Names subkey', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SAM' }).build((r) => {
    r.key('SAM', {}, (s) => s.key('Domains', {}, (d) => d.key('Account', {}, (a) => a.key('Users', {}, (u) => {
      u.key('000001F4');
    }))));
  }).toBuffer());
  const t = text('samparse', hive);
  assert.match(t, /Names subkey not found/);
  assert.match(t, /000001F4/);
});

// RecentDocs old-style MRUList (letters, not MRUListEx) + subkey traversal.
test('recentdocs: MRUList-style subkey entries', () => {
  const EX = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer';
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => {
      m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => cv.key('Explorer', {}, (ex) =>
        ex.key('RecentDocs', {}, (rd) => rd.key('.txt', {}, (sub) => {
          sub.value('MRUList', 1, 'ba');
          sub.value('a', 3, filenameBytes('a.txt'));
          sub.value('b', 3, filenameBytes('b.txt'));
        })))));
      m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion'));
    }));
  }).toBuffer());
  const t = text('recentdocs', hive);
  assert.match(t, /RecentDocs\\\.txt/);
  assert.match(t, /a\.txt/);
  assert.match(t, /b\.txt/);
});
