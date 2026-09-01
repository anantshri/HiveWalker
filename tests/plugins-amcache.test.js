// Amcache plugins + hive-type detection, and SECURITY-hive plugins.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { ftBytes } = require('./helpers/ft-bytes');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime, helpers } = RV.plugins;
const text = (name, hive) => RV.ui.viewModel.reportText(runtime.run(name, hive));

// ---------------------------------------------------------------- amcache

test('amcache hive type detected from Root\\File (Win8 shape)', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => {
    r.key('Root', {}, (root) => root.key('File', {}));
  }).toBuffer());
  assert.ok(helpers.guessHiveType(hive).has('amcache'));
});

test('amcache hive type detected from Root\\InventoryApplicationFile (Win10 shape)', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => {
    r.key('Root', {}, (root) => root.key('InventoryApplicationFile', {}));
  }).toBuffer());
  assert.ok(helpers.guessHiveType(hive).has('amcache'));
});

test('amcache_file parses Win8 Root\\File entries (SHA-1 prefix strip, sizes, times)', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => {
    r.key('Root', {}, (root) => root.key('File', {}, (file) => {
      const vol = file.key('{77faa3a2-CTO-95e8-44c5-88c5b7e1f6d5}');
      const f = vol.key('0000a1b2c3d4e5');
      f.value('15', 1, 'C:\\Users\\alice\\AppData\\Temp\\stage.exe');
      f.value('101', 1, '00008899aabbccddeeff00112233445566778899');
      f.value('6', 1, '4a00'); // hex size = 18944
      f.value('11', 3, ftBytes(new Date('2026-07-01T00:00:00Z')));
      f.value('0', 1, 'BadTool Product');
      f.value('1', 1, 'EvilCorp');
    }));
  }).toBuffer());
  const t = text('amcache_file', hive);
  assert.ok(t.includes('stage.exe'));
  assert.ok(t.includes('8899aabbccddeeff00112233445566778899'), 'SHA-1 0000 prefix stripped');
  assert.ok(t.includes('18944'), 'hex size decoded');
  assert.ok(t.includes('2026-07-01'), 'last-modified FILETIME decoded');
  assert.ok(t.includes('EvilCorp'));
});

test('amcache_file parses Win10 InventoryApplicationFile entries', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => {
    r.key('Root', {}, (root) => root.key('InventoryApplicationFile', {}, (iaf) => {
      const f = iaf.key('someapp.exe|61cf2cc5!');
      f.value('LowerCaseLongPath', 1, 'c:\\windows\\system32\\someapp.exe');
      f.value('FileId', 1, '0000deadbeefdeadbeefdeadbeefdeadbeefdead');
      f.value('Size', 4, 2048);
      f.value('Publisher', 1, 'Contoso');
    }));
  }).toBuffer());
  const t = text('amcache_file', hive);
  assert.ok(t.includes('c:\\windows\\system32\\someapp.exe'));
  assert.ok(t.includes('deadbeefdeadbeefdeadbeefdeadbeefdead'));
  assert.ok(t.includes('2048'));
});

test('amcache_app parses Win10 InventoryApplication', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => {
    r.key('Root', {}, (root) => root.key('InventoryApplication', {}, (ia) => {
      const a = ia.key('App1');
      a.value('Name', 1, 'Remote Admin Tool');
      a.value('Version', 1, '9.9');
      a.value('InstallDate', 1, '2026-01-01');
    }));
  }).toBuffer());
  const t = text('amcache_app', hive);
  assert.ok(t.includes('Remote Admin Tool'));
  assert.ok(t.includes('9.9'));
});

test('amcache plugins degrade on a non-amcache hive', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => r.key('Nothing')).toBuffer());
  assert.ok(text('amcache_file', hive).includes('not found'));
  assert.ok(text('amcache_app', hive).includes('not found'));
});

// ---------------------------------------------------------------- SECURITY

function securityHive(build) {
  return RV.reg.openHive(new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SECURITY' }).build((r) => {
    r.key('Policy', {}, (pol) => { if (build) build(pol); });
  }).toBuffer());
}

test('security hive type detected via Policy markers', () => {
  const hive = securityHive((pol) => {
    pol.key('PolAcDmN');
    pol.key('PolAdtEv');
    pol.key('Accounts');
  });
  const types = helpers.guessHiveType(hive);
  assert.ok(types.has('security'), 'detected: ' + [...types].join(','));
});

test('machine_sid: names + SID from PolAcDmN/PolPrDmN/PolMachineAccountS', () => {
  // UNICODE_STRING-style: 8-byte header then UTF-16LE name.
  const nameBlob = (s) => Buffer.concat([Buffer.alloc(8), Buffer.from(s + '\0', 'utf16le')]);
  // revision 1, 5 sub-auths, authority 5 → S-1-5-21-13417386-16772829-2241348-500
  const le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
  const sidBytes = Buffer.concat([
    Buffer.from([1, 5, 0, 0, 0, 0, 0, 5]),
    le(21), le(0x00ccbbaa), le(0x00ffeedd), le(0x00223344), le(500),
  ]);
  const hive = securityHive((pol) => {
    pol.key('PolAcDmN', {}).value('', 3, nameBlob('WORKGROUP'));
    pol.key('PolPrDmN', {}).value('', 3, nameBlob('CORP'));
    pol.key('PolMachineAccountS', {}).value('', 3, sidBytes);
  });
  const t = text('machine_sid', hive);
  assert.ok(t.includes('WORKGROUP'));
  assert.ok(t.includes('CORP'));
  assert.ok(t.includes('S-1-5-21-13417386-16772829-2241348-500'), 'machine SID rendered');
});

test('machine_sid: REG_DWORD → not domain-joined', () => {
  const hive = securityHive((pol) => {
    pol.key('PolMachineAccountS', {}).value('', 4, 0);
  });
  assert.ok(text('machine_sid', hive).includes('not domain-joined'));
});

test('auditpol: per-category settings + high-value-off note', () => {
  const raw = Buffer.alloc(0x0c + 60 * 2);
  raw.writeUInt32LE(0x0201, 0); // version header
  const dv = new DataView(raw.buffer);
  dv.setUint16(0x0c + 5 * 2, 3, true);  // Logon (idx 5) → both
  dv.setUint16(0x0c + 30 * 2, 0, true); // Process Creation (idx 30) → off
  const hive = securityHive((pol) => pol.key('PolAdtEv', {}).value('', 3, raw));
  const t = text('auditpol', hive);
  assert.ok(t.includes('Success+Failure'));
  assert.ok(t.includes('Process Creation'));
  assert.ok(t.includes('NO auditing'), 'high-value-off note present');
});

test('lsasecrets: enumeration + classification without decryption', () => {
  const hive = securityHive((pol) => {
    const s = pol.key('Secrets');
    s.key('_SC_myservice', {}).key('CurrVal', {}).value('', 3, Buffer.alloc(64, 0x41));
    s.key('DefaultPassword', {}).key('CurrVal', {}).value('', 3, Buffer.from('p@ss\0', 'utf16le'));
    s.key('NL$KM', {}).key('CurrVal', {}).value('', 3, Buffer.alloc(48, 0x22));
  });
  const t = text('lsasecrets', hive);
  assert.ok(t.includes('_SC_myservice'));
  assert.ok(t.includes('Service account password'));
  assert.ok(t.includes('DefaultPassword'));
  assert.ok(t.includes('Autologon'));
  assert.ok(t.includes('NL$KM'));
  assert.ok(t.includes('out of scope'));
});

test('lsasecrets degrades when Secrets is absent', () => {
  const hive = securityHive();
  assert.ok(text('lsasecrets', hive).includes('not found'));
});
