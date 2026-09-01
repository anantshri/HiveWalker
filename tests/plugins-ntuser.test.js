'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { ftBytes } = require('./helpers/ft-bytes');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime, helpers } = RV.plugins;
const enc = helpers.rot13; // ROT13 is its own inverse — encode == decode

function u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; }

// UserAssist XP record: session, count(=10 → shown as 5), FILETIME.
const data16 = Buffer.concat([u32(0), u32(10), ftBytes(new Date('2022-05-05T01:02:03Z'))]);
// UserAssist Win7 record: count at 0x04, FILETIME at 0x3c.
const data72 = Buffer.alloc(72);
data72.writeUInt32LE(3, 4);
ftBytes(new Date('2022-06-06T04:05:06Z')).copy(data72, 60);

function filenameBytes(name) {
  return Buffer.concat([Buffer.from(name, 'utf16le'), Buffer.from([0, 0]), Buffer.from([0x14, 0x00])]);
}
const mruListEx = Buffer.from([1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]); // order 1,0 then terminator

const hive = RV.reg.openHive(new HiveBuilder({ fileName: '\\??\\C:\\Users\\Alice\\NTUSER.DAT' }).build((r) => {
  r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => {
    m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => cv.key('Explorer', {}, (ex) => {
      ex.key('UserAssist', {}, (ua) => ua.key('{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}', {}, (g) => g.key('Count', {}, (count) => {
        count.value(enc('UEME_RUNPATH:calc.exe'), 3, data16);
        count.value(enc('UEME_RUNPATH:notepad.exe'), 3, data72);
      })));
      ex.key('RecentDocs', {}, (rd) => {
        rd.value('MRUListEx', 3, mruListEx);
        rd.value('0', 3, filenameBytes('report.docx'));
        rd.value('1', 3, filenameBytes('photo.jpg'));
      });
      ex.key('TypedPaths', {}, (tp) => {
        tp.value('url1', 1, 'C:\\Users\\Alice\\Documents');
        tp.value('url2', 1, 'ftp://files.example');
      });
      ex.key('RunMRU', {}, (rm) => {
        rm.value('MRUList', 1, 'ba');
        rm.value('a', 1, 'calc.exe\\1');
        rm.value('b', 1, 'notepad.exe\\1');
      });
    })));
    m.key('Windows NT', {}, (wn) => wn.key('CurrentVersion'));
  }));
}).toBuffer());

const text = (name) => RV.ui.viewModel.reportText(runtime.run(name, hive));

test('hive detected as ntuser', () => {
  assert.ok(helpers.guessHiveType(hive).has('ntuser'));
});

test('userassist: ROT13-decoded names, run counts, timestamps', () => {
  const t = text('userassist');
  assert.match(t, /UEME_RUNPATH:calc\.exe \(5\)/); // XP: 10 − 5
  assert.match(t, /2022-05-05 01:02:03 UTC/);
  assert.match(t, /UEME_RUNPATH:notepad\.exe \(3\)/); // Win7
  assert.match(t, /2022-06-06 04:05:06 UTC/);
});

test('recentdocs: MRUListEx order + decoded filenames', () => {
  const t = text('recentdocs');
  assert.match(t, /report\.docx/);
  assert.match(t, /photo\.jpg/);
});

test('typedpaths: url values listed', () => {
  const t = text('typedpaths');
  assert.match(t, /C:\\Users\\Alice\\Documents/);
  assert.match(t, /ftp:\/\/files\.example/);
});

test('runmru: MRUList order + commands', () => {
  const t = text('runmru');
  assert.match(t, /MRUList\s+ba/);
  assert.match(t, /calc\.exe/);
  assert.match(t, /notepad\.exe/);
});
