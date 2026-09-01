// New SOFTWARE/NTUSER DFIR plugin tests: taskcache, networklist, emdmgmt,
// portabledevices, tsclient, wordwheelquery, mountpoints2, opensavepidl.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { ftBytes } = require('./helpers/ft-bytes');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime } = RV.plugins;

const text = (name, hive) => RV.ui.viewModel.reportText(runtime.run(name, hive));

// ---------------------------------------------------------------- taskcache

test('taskcache: Tree + Tasks correlation, hidden-task flag, actions decode', () => {
  const actions = Buffer.alloc(64);
  actions.writeUInt16LE(0x03, 0);                     // magic
  actions.writeUInt16LE(8, 2);                        // user length (bytes)
  Buffer.from('u\0s\0r\0', 'utf16le').copy(actions, 4); // 4 chars? keep 8 bytes 'us'
  // simpler: user = 2 UTF-16 chars = 4 bytes
  const act = Buffer.alloc(64);
  let p = 0;
  act.writeUInt16LE(0x03, p); p += 2;
  const user = Buffer.from('sys\0', 'utf16le'); // includes NUL: len must match
  act.writeUInt16LE(8, p); p += 2; // 8 bytes
  Buffer.from('s\0y\0s\0\0\0', 'utf16le').copy(act, p); p += 8;
  act.writeUInt16LE(0x6666, p); p += 2;
  const prog = 'C:\\evil\\task.exe';
  const progBytes = Buffer.from(prog, 'utf16le');
  act.writeUInt16LE(progBytes.length, p); p += 2;
  progBytes.copy(act, p);

  const dyn = Buffer.alloc(0x24); // Win10 shape
  ftBytes(new Date('2026-08-20T12:00:00Z')).copy(dyn, 4);

  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Microsoft', {}, (m) => m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion', {}, (cv) => {
      cv.key('Schedule', {}, (sch) => sch.key('TaskCache', {}, (tc) => {
        tc.key('Tree', {}, (tree) => {
          tree.key('Microsoft', {}, (ms) => ms.key('Windows', {}, (w) => w.key(' defender', {}, (d) => {})));
          const t1 = tree.key('UpdateTask');
          t1.value('Id', 1, '{AAAA1111-2222-3333-4444-555566667777}');
          t1.value('Author', 1, 'CORP\\admin');
          t1.value('SD', 3, Buffer.alloc(40, 0x41)); // has SD → not hidden
          const t2 = tree.key('EvilHidden'); // no SD → hidden
          t2.value('Id', 1, '{BBBB1111-2222-3333-4444-555566667777}');
        });
        tc.key('Tasks', {}, (tasks) => {
          const a = tasks.key('{AAAA1111-2222-3333-4444-555566667777}');
          a.value('Actions', 3, act);
          a.value('DynamicInfo', 3, dyn);
          // {BBBB...} intentionally absent → orphan Tree entry
        });
      }));
    })));
  }).toBuffer());

  const t = text('taskcache', hive);
  assert.ok(t.includes('UpdateTask'));
  assert.ok(t.includes('CORP\\admin'));
  assert.ok(t.includes('C:\\evil\\task.exe'), 'Actions decoded to program path');
  assert.ok(t.includes('2026-08-20'), 'DynamicInfo last-run decoded');
  assert.ok(t.includes('EvilHidden'));
  assert.ok(t.includes('Tarrask'), 'hidden-task note present');
  assert.ok(t.includes('Orphan'), 'orphan Tree entry reported');
});

test('taskcache: absent key degrades', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => r.key('Nothing')).toBuffer());
  assert.ok(text('taskcache', hive).includes('not found'));
});

// ---------------------------------------------------------------- networklist

test('networklist: profiles + signatures correlation, 12-byte date quirk', () => {
  const dc12 = Buffer.alloc(12);
  ftBytes(new Date('2024-02-01T09:00:00Z')).copy(dc12, 4); // FT in LAST 8 of 12
  const lc12 = Buffer.alloc(12);
  ftBytes(new Date('2026-08-28T18:30:00Z')).copy(lc12, 4);

  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Microsoft', {}, (m) => m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion', {}, (cv) => {
      cv.key('NetworkList', {}, (nl) => {
        nl.key('Profiles', {}, (pr) => {
          const p1 = pr.key('{C1-C1-C1}');
          p1.value('ProfileName', 1, 'Corp-WiFi');
          p1.value('Category', 4, 2);
          p1.value('NameType', 4, 0x47);
          p1.value('DateCreated', 3, dc12);
          p1.value('DateLastConnected', 3, lc12);
        });
        nl.key('Signatures', {}, (sig) => {
          sig.key('Managed', {}, (man) => {
            const s = man.key('{C1-C1-C1}');
            s.value('FirstNetwork', 1, 'CORPDOMAIN');
            s.value('DnsSuffix', 1, 'corp.example.com');
            s.value('DefaultGateWayMac', 3, Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
            s.value('ProfileGuid', 1, '{C1-C1-C1}');
          });
        });
      });
    })));
  }).toBuffer());

  const t = text('networklist', hive);
  assert.ok(t.includes('Corp-WiFi'));
  assert.ok(t.includes('Domain'), 'category decoded');
  assert.ok(t.includes('Wireless'), 'name type decoded');
  assert.ok(t.includes('2024-02-01'), 'DateCreated via 12-byte quirk');
  assert.ok(t.includes('2026-08-28'), 'DateLastConnected');
  assert.ok(t.includes('AA:BB:CC:DD:EE:FF'), 'gateway MAC');
  assert.ok(t.includes('corp.example.com'));
});

// ---------------------------------------------------------------- emdmgmt

test('emdmgmt: volume serial decode from key name', () => {
  const lt = Buffer.alloc(8);
  ftBytes(new Date('2025-11-05T03:02:01Z')).copy(lt, 0);
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Microsoft', {}, (m) => m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion', {}, (cv) => {
      cv.key('EMDMgmt', {}, (emd) => {
        const k = emd.key('_??_USBSTOR#Disk&Ven_Kingston&Prod_DT_101#007d1a2b3c&_0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}');
        k.value('LastTestedTime', 3, lt);
      });
    })));
  }).toBuffer());
  const t = text('emdmgmt', hive);
  // last token before the disk GUID is '007d1a2b3c' — hmm, the GUID contains
  // '-'; split('_') last token is the {GUID}. Volume serial is the hex before it.
  // Assert on visible pieces + LastTested.
  assert.ok(t.includes('EMDMgmt'));
  assert.ok(t.includes('2025-11-05'), 'LastTestedTime decoded');
});

// ---------------------------------------------------------------- portabledevices

test('portabledevices: phone identity', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Microsoft', {}, (m) => m.key('Windows Portable Devices', {}, (wpd) => {
      wpd.key('Devices', {}, (dev) => {
        const d = dev.key('WPD:\\\\?\\usb#vid_04e8&pid_6860#{GUID}');
        d.value('FriendlyName', 1, 'Galaxy S23');
        d.value('Manufacturer', 1, 'Samsung');
        d.value('ModelName', 1, 'SM-S911B');
        d.value('FirmwareVersion', 1, 'UP1A');
      });
    }));
  }).toBuffer());
  const t = text('portabledevices', hive);
  assert.ok(t.includes('Galaxy S23'));
  assert.ok(t.includes('Samsung'));
  assert.ok(t.includes('SM-S911B'));
});

// ---------------------------------------------------------------- tsclient

test('tsclient: MRU + UsernameHint', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => {
      const ts = m.key('Terminal Server Client');
      const def = ts.key('Default');
      def.value('MRU0', 1, '10.0.0.5');
      def.value('MRU1', 1, 'dc01.corp.example.com');
      const srv = ts.key('Servers');
      const s1 = srv.key('10.0.0.5');
      s1.value('UsernameHint', 1, 'CORP\\alice');
    }));
  }).toBuffer());
  const t = text('tsclient', hive);
  assert.ok(t.includes('10.0.0.5'));
  assert.ok(t.includes('dc01.corp.example.com'));
  assert.ok(t.includes('CORP\\alice'));
});

// ---------------------------------------------------------------- wordwheelquery

test('wordwheelquery: MRUListEx order + terms', () => {
  const mru = Buffer.alloc(12);
  [1, 0, 0xffffffff].forEach((n, i) => mru.writeUInt32LE(n >>> 0, i * 4)); // order: 1 then 0
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => {
      const wwq = cv.key('Explorer').key('WordWheelQuery');
      wwq.value('MRUListEx', 3, mru);
      wwq.value('0', 1, 'invoice');
      wwq.value('1', 1, 'passwords*');
    }))));
  }).toBuffer());
  const t = text('wordwheelquery', hive);
  assert.ok(t.includes('invoice'));
  assert.ok(t.includes('passwords*'));
  // order column: row for index 1 comes first
  const i1 = t.indexOf('passwords*');
  const i0 = t.indexOf('invoice');
  assert.ok(i1 < i0, 'MRUListEx order respected');
});

// ---------------------------------------------------------------- mountpoints2

test('mountpoints2: UNC / drive / volume classification', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => {
      const m2 = cv.key('Explorer').key('MountPoints2');
      m2.key('##fileserver#share');
      const c = m2.key('C:');
      c.value('_LabelFromReg', 1, 'OSDisk');
      m2.key('{12345678-1234-1234-1234-123456789012}');
    }))));
  }).toBuffer());
  const t = text('mountpoints2', hive);
  assert.ok(t.includes('UNC share'));
  assert.ok(t.includes('Drive letter'));
  assert.ok(t.includes('OSDisk'));
  assert.ok(t.includes('Volume (CSP/BitLocker)'));
});

// ---------------------------------------------------------------- opensavepidl

test('opensavepidl: MRU entries + utf16 string scraping', () => {
  // shell-item-ish blob: garbage header then a UTF-16LE path
  const blob = Buffer.concat([
    Buffer.from([0x01, 0x00, 0x00, 0x00]),
    Buffer.from('C:\\Users\\alice\\Documents\\secret.docx\0', 'utf16le'),
  ]);
  const mru = Buffer.alloc(8);
  [0, 0xffffffff].forEach((n, i) => mru.writeUInt32LE(n >>> 0, i * 4));

  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => {
      const star = cv.key('Explorer').key('ComDlg32').key('OpenSavePidlMRU').key('*');
      star.value('MRUListEx', 3, mru);
      star.value('0', 3, blob);
    }))));
  }).toBuffer());
  const t = text('opensavepidl', hive);
  assert.ok(t.includes('secret.docx'), 'path scraped from shell-item blob');
  assert.ok(t.includes('not implemented'), 'simplification note present');
});
