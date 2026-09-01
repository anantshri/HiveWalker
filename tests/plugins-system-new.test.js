// New SYSTEM-pack plugins: bootkey, shimcache, bam, wpdbusenum, svcacls.
// Plus the bootkey→DES round-trip that gates samhashes (crypto-sam part 1).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { ftBytes } = require('./helpers/ft-bytes');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime, helpers } = RV.plugins;
const C = RV.crypto;
const D = RV.decoders;

// bootkey derivation is the inverse of a scramble: choose a known bootkey,
// scramble it ourselves (inverse pbox), and plant the parts as class names.
const PBOX = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7];
const BOOTKEY = C.hexToBytes('00112233445566778899aabbccddeeff');
const scrambled = new Uint8Array(16);
for (let i = 0; i < 16; i++) scrambled[PBOX[i]] = BOOTKEY[i];
const hexParts = C.bytesToHex(scrambled).match(/.{8}/g); // JD, Skew1, GBG, Data

function systemHive(extra) {
  return RV.reg.openHive(new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SYSTEM' }).build((r) => {
    r.key('Select', {}, (s) => { s.value('Current', 4, 1); });
    r.key('ControlSet001', {}, (cs) => {
      cs.key('Control', {}, (c) => {
        c.key('Lsa', {}, (lsa) => {
          lsa.key('JD', { className: hexParts[0] });
          lsa.key('Skew1', { className: hexParts[1] });
          lsa.key('GBG', { className: hexParts[2] });
          lsa.key('Data', { className: hexParts[3] });
        });
        if (extra) extra(cs, c);
      });
    });
  }).toBuffer());
}

test('getBootKey derives the planted bootkey from Lsa class names', () => {
  const hive = systemHive();
  const got = helpers.getBootKey(hive);
  assert.ok(got, 'bootkey derivation succeeds');
  assert.strictEqual(C.bytesToHex(got.bootKey), '00112233445566778899aabbccddeeff');
  assert.strictEqual(got.parts.JD, hexParts[0]);
});

test('getBootKey returns null when class names are missing', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => r.key('Nothing')).toBuffer());
  assert.strictEqual(helpers.getBootKey(hive), null);
});

test('bootkey plugin reports the derived key', () => {
  const res = runtime.run('bootkey', systemHive());
  assert.strictEqual(res.error, null);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('00112233445566778899aabbccddeeff'));
  assert.ok(text.includes('SAM or SECURITY'));
});

// ---- shimcache plugin (end-to-end through the AppCompatData value) --------

test('shimcache plugin parses a synthetic Win7 blob from the hive', () => {
  const path = Buffer.from('C:\\Windows\\Temp\\bad.dll\0', 'utf16le');
  const HEADER = 0x80, ENTRY = 0x30;
  const PATH_OFF = HEADER + ENTRY;
  const blob = Buffer.alloc(HEADER + ENTRY + path.length);
  blob.writeUInt32LE(0xbadc0fee, 0);
  blob.writeUInt32LE(1, 4);
  blob.writeUInt16LE(path.length, HEADER);
  blob.writeUInt16LE(path.length + 2, HEADER + 2);
  blob.writeUInt32LE(0, HEADER + 4);
  blob.writeUInt32LE(PATH_OFF, HEADER + 8);
  ftBytes(new Date(Date.UTC(2026, 0, 15))).copy(blob, HEADER + 16);
  blob.writeUInt32LE(0x2, HEADER + 28); // CSRSS
  path.copy(blob, PATH_OFF);

  const hive = systemHive((cs, c) => {
    c.key('Session Manager', {}, (sm) => {
      sm.key('AppCompatCache', {}, (ac) => ac.value('AppCompatCache', 3, blob));
    });
  });
  const res = runtime.run('shimcache', hive);
  assert.strictEqual(res.error, null);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('C:\\Windows\\Temp\\bad.dll'));
  assert.ok(text.includes('yes'), 'exec flag rendered');
});

test('shimcache plugin degrades when key is absent', () => {
  const res = runtime.run('shimcache', systemHive());
  assert.strictEqual(res.error, null);
  assert.ok(RV.ui.viewModel.reportText(res).includes('not found'));
});

// ---- bam plugin ---------------------------------------------------------------

test('bam plugin lists per-SID execution entries with timestamps', () => {
  const hive = systemHive((cs) => {
    cs.key('Services', {}, (svcs) => {
      svcs.key('bam', {}, (bam) => {
        bam.key('State', {}, (st) => {
          st.key('UserSettings', {}, (us) => {
            us.key('S-1-5-21-1000-2000-3000-1001', {}, (sid) => {
              sid.value('SequenceNumber', 4, 42);
              sid.value('Version', 4, 1);
              sid.value('C:\\Tools\\poc.exe', 3, ftBytes(new Date(Date.UTC(2026, 5, 1))));
            });
          });
        });
      });
    });
  });
  const res = runtime.run('bam', hive);
  assert.strictEqual(res.error, null);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('S-1-5-21-1000-2000-3000-1001'));
  assert.ok(text.includes('C:\\Tools\\poc.exe'));
  assert.ok(text.includes('2026-06-01'));
});

// ---- wpdbusenum plugin ----------------------------------------------------------

test('wpdbusenum plugin lists enumerated portable devices', () => {
  const hive = systemHive((cs) => {
    cs.key('Enum', {}, (en) => {
      en.key('SWD', {}, (swd) => {
        swd.key('WPDBUSENUM', {}, (wpd) => {
          wpd.key('{11111111-2222-3333-4444-555555555555}', {}, (dev) => {
            dev.key('#Phone#SKU#8&2', {});
          });
        });
      });
    });
  });
  const res = runtime.run('wpdbusenum', hive);
  assert.strictEqual(res.error, null);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('{11111111-2222-3333-4444-555555555555}'));
  assert.ok(text.includes('#Phone#SKU#8&2'));
});

// ---- svcacls plugin -------------------------------------------------------------

function buildSd({ ownerSid, accessMask, aceSid }) {
  const sidBytes = (sidText) => {
    const parts = sidText.split('-').map(Number);
    const subs = parts.slice(3);
    const out = [1, subs.length, 0, 0, 0, 0, 0, parts[2]];
    for (const s of subs) out.push(s & 0xff, (s >>> 8) & 0xff, (s >>> 16) & 0xff, (s >>> 24) & 0xff);
    return out;
  };
  const owner = sidBytes(ownerSid);
  const ace = sidBytes(aceSid);
  const aclOff = 20 + owner.length;
  const aceOff = aclOff + 8;
  const b = new Uint8Array(aceOff + 8 + ace.length);
  const dv = new DataView(b.buffer);
  b[0] = 1;
  dv.setUint16(2, 0x8000, true);
  dv.setUint32(4, 20, true);
  dv.setUint32(16, aclOff, true);
  b.set(owner, 20);
  b[aclOff] = 2;
  dv.setUint16(aclOff + 4, 1, true);
  b[aceOff] = 0x00;
  dv.setUint32(aceOff + 4, accessMask, true);
  b.set(ace, aceOff + 8);
  return b;
}

test('svcacls flags a weak service key and passes a clean one', () => {
  const weak = buildSd({ ownerSid: 'S-1-5-18', accessMask: 0xf003f, aceSid: 'S-1-5-11' });
  const clean = buildSd({ ownerSid: 'S-1-5-18', accessMask: 0x0001, aceSid: 'S-1-5-32-545' });
  const hive = systemHive((cs) => {
    cs.key('Services', {}, (svcs) => {
      svcs.key('weaksvc', { security: Buffer.from(weak) });
      svcs.key('cleansvc', { security: Buffer.from(clean) });
      svcs.key('nodesc', {});
    });
  });
  const res = runtime.run('svcacls', hive);
  assert.strictEqual(res.error, null);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('weaksvc'), 'weak service flagged');
  assert.ok(text.includes('Authenticated Users'));
  assert.ok(text.includes('T1574.011'));
  assert.ok(!text.includes('cleansvc'), 'clean service not flagged');
  assert.ok(text.includes('1 expose'), 'no-descriptor count reported'); // grammar: "1 expose(s) no sk descriptor"
});

// ---- bootkey→DES round-trip (gate for samhashes) ------------------------------

test('SAM rid-DES round-trip: encrypt with rid keys, decrypt back', () => {
  // RID 500 (Administrator): NT hash must survive an encrypt/decrypt cycle
  // under ridToDesKeys — the exact layer samhashes will invert.
  const nt = C.hexToBytes('8846f7eaee8fb117ad06bdd830b7586c');
  const [k1, k2] = C.ridToDesKeys(500);
  const enc = C.concatBytes(
    C.desEncryptBlock(k1, nt.subarray(0, 8)),
    C.desEncryptBlock(k2, nt.subarray(8, 16)),
  );
  const dec = C.concatBytes(
    C.desDecryptBlock(k1, enc.subarray(0, 8)),
    C.desDecryptBlock(k2, enc.subarray(8, 16)),
  );
  assert.strictEqual(C.bytesToHex(dec), '8846f7eaee8fb117ad06bdd830b7586c');
});

test('RC4(MD5(bootkey‖rid)) Vista-layer sanity: symmetric round-trip', () => {
  const boot = C.hexToBytes('00112233445566778899aabbccddeeff');
  const rid = 1001;
  const ridLe = new Uint8Array([0xe9, 0x03, 0x00, 0x00]);
  const key = C.md5(C.concatBytes(boot, ridLe));
  const blob = C.hexToBytes('aabbccddeeff00112233445566778899');
  assert.deepStrictEqual(C.rc4(key, C.rc4(key, blob)), blob);
});
