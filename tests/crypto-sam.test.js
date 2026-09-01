// samhashes end-to-end: encrypt with our own crypto, plant in a synthetic
// SAM hive + session-attached SYSTEM (bootkey), verify decryption.
// Also covers samparse F/V decoding and the no-SYSTEM degraded output.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { makeDom } = require('./helpers/dom-stub');
makeDom();
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { ftBytes } = require('./helpers/ft-bytes');

const RV = loadSrc();
const { runtime, helpers, session } = RV.plugins;
const C = RV.crypto;
const D = RV.decoders;

const NT_PASSWORD = C.hexToBytes('8846f7eaee8fb117ad06bdd830b7586c'); // MD4("password")
const NT_EMPTY = '31d6cfe0d16ae931b73c59d7e0c089c0';
const LM_EMPTY_BYTES = C.hexToBytes('aad3b435b51404eeaad3b435b51404ee');

// --- fixture builders -------------------------------------------------------

function buildV({ username, lm, nt }) {
  const regions = [];
  const put = (off, data) => { if (data != null) regions.push({ off, data: Buffer.from(data) }); };
  put(0x0c, Buffer.from(username, 'utf16le'));
  put(0x18, Buffer.from('Test Full Name', 'utf16le'));
  put(0x9c, lm);
  put(0xa8, nt);
  const total = 0xcc + regions.reduce((n, r) => n + r.data.length, 0);
  const v = Buffer.alloc(total);
  let cur = 0;
  for (const r of regions) {
    v.writeUInt32LE(cur, r.off);
    v.writeUInt32LE(r.data.length, r.off + 4);
    r.data.copy(v, 0xcc + cur);
    cur += r.data.length;
  }
  return v;
}

function buildF(rid, opts = {}) {
  const f = Buffer.alloc(0x50);
  ftBytes(new Date('2026-08-01T10:00:00Z')).copy(f, 0x08); // last logon
  ftBytes(new Date('2026-01-15T08:00:00Z')).copy(f, 0x18); // pwd last set
  f.writeUInt32LE(rid, 0x30);
  f.writeUInt16LE(opts.flags ?? 0x0210, 0x38);
  f.writeUInt16LE(opts.failed ?? 1, 0x40);
  f.writeUInt16LE(opts.logons ?? 7, 0x42);
  return f;
}

/** XP-generation encrypted hash: DES under the per-RID key schedule. */
function xpEncrypt(hashBytes, rid) {
  const [k1, k2] = C.ridToDesKeys(rid);
  return C.concatBytes(
    C.desEncryptBlock(k1, hashBytes.subarray(0, 8)),
    C.desEncryptBlock(k2, hashBytes.subarray(8, 16)),
  );
}

function samHiveWith({ username = 'Administrator', rid = 500, lm, nt, namesValue = true }) {
  return RV.reg.openHive(new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SAM' }).build((r) => {
    r.key('SAM', {}, (s) => s.key('Domains', {}, (d) => d.key('Account', {}, (a) => {
      a.key('Users', {}, (users) => {
        users.key('Names', {}, (names) => {
          const n = names.key(username);
          if (namesValue) n.value('', rid, Buffer.alloc(0)); // default value TYPE = RID
        });
        const ridHex = rid.toString(16).padStart(8, '0').toUpperCase();
        const u = users.key(ridHex);
        u.value('F', 3, buildF(rid));
        u.value('V', 3, buildV({ username, lm, nt }));
      });
    })));
  }).toBuffer());
}

function systemHiveWithBootkey() {
  const PBOX = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7];
  const BOOTKEY = C.hexToBytes('0f1e2d3c4b5a69788796a5b4c3d2e1f0');
  const scrambled = new Uint8Array(16);
  for (let i = 0; i < 16; i++) scrambled[PBOX[i]] = BOOTKEY[i];
  const parts = C.bytesToHex(scrambled).match(/.{8}/g);
  const buf = new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SYSTEM' }).build((r) => {
    r.key('Select', {}, (sel) => sel.value('Current', 4, 1));
    r.key('ControlSet001', {}, (cs) => cs.key('Control', {}, (c) => {
      c.key('Lsa', {}, (lsa) => {
        lsa.key('JD', { className: parts[0] });
        lsa.key('Skew1', { className: parts[1] });
        lsa.key('GBG', { className: parts[2] });
        lsa.key('Data', { className: parts[3] });
      });
    }));
  }).toBuffer();
  return { hive: RV.reg.openHive(buf), bootKey: BOOTKEY };
}

// --- tests ------------------------------------------------------------------

test('samhashes without SYSTEM: encrypted blobs + attach note', () => {
  session.clear();
  const lmEnc = xpEncrypt(LM_EMPTY_BYTES, 500);
  const ntEnc = xpEncrypt(NT_PASSWORD, 500);
  const hive = samHiveWith({ lm: lmEnc, nt: ntEnc });
  const res = runtime.run('samhashes', hive, { session });
  assert.strictEqual(res.error, null);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes(C.bytesToHex(ntEnc)), 'encrypted NT blob shown');
  assert.ok(text.includes('Attach the SYSTEM hive'));
});

test('samhashes with SYSTEM session: decrypts XP-generation hashes', () => {
  session.clear();
  const { hive: sysHive } = systemHiveWithBootkey();
  session.attach(sysHive, 'SYSTEM');
  const hive = samHiveWith({ lm: xpEncrypt(LM_EMPTY_BYTES, 500), nt: xpEncrypt(NT_PASSWORD, 500) });
  session.attach(hive, 'SAM');
  // NOTE: samhashes runs against the SAM hive; ctx.session.byType('system') works.

  const res = runtime.run('samhashes', hive, { session });
  assert.strictEqual(res.error, null);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('8846f7eaee8fb117ad06bdd830b7586c'), 'NT hash decrypted: ' + text);
  assert.ok(text.includes('aad3b435b51404eeaad3b435b51404ee'), 'LM hash decrypted');
  assert.ok(text.includes('2000/XP/2003'), 'generation labelled');
  assert.ok(text.includes('BLANK password'), 'empty-hash note flagged');
});

test('samhashes flags non-16-byte Vista+ blobs as undecrypted generation', () => {
  session.clear();
  const { hive: sysHive } = systemHiveWithBootkey();
  session.attach(sysHive, 'SYSTEM');
  const weirdBlob = new Uint8Array(28).fill(0xab); // AES-era length
  const hive = samHiveWith({ lm: weirdBlob, nt: weirdBlob });
  const res = runtime.run('samhashes', hive, { session });
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('undecrypted generation'), text);
  assert.ok(!text.includes('decrypted: 8846'), 'never fabricates plaintext');
});

test('samhashes survives corrupt/absent values', () => {
  session.clear();
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => {
    r.key('SAM', {}, (s) => s.key('Domains', {}, (d) => d.key('Account', {}, (a) => {
      a.key('Users', {}, (u) => {
        u.key('000003E8'); // RID 1000, no F/V values at all
      });
    })));
  }).toBuffer());
  const res = runtime.run('samhashes', hive, { session });
  assert.strictEqual(res.error, null);
  assert.ok(RV.ui.viewModel.reportText(res).includes('no hashes stored'));
  // users key entirely absent
  const empty = RV.reg.openHive(new HiveBuilder().build((r) => r.key('Nothing')).toBuffer());
  const res2 = runtime.run('samhashes', empty, { session });
  assert.strictEqual(res2.error, null);
});

test('samparse decodes F timestamps/flags and V strings via the plugin', () => {
  const hive = samHiveWith({ lm: null, nt: null });
  const res = runtime.run('samparse', hive);
  assert.strictEqual(res.error, null);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('Administrator'));
  assert.ok(text.includes('2026-08-01'), 'last logon decoded');
  assert.ok(text.includes('2026-01-15'), 'pwd last set decoded');
  assert.ok(text.includes('Normal User Account'));
  assert.ok(text.includes('Password Never Expires'));
  assert.ok(text.includes('Test Full Name'), 'V fullname decoded');
});

test('RID↔name mapping via Names default-value type', () => {
  const hive = samHiveWith({ username: 'bob', rid: 1010, lm: null, nt: null });
  const res = runtime.run('samparse', hive);
  const text = RV.ui.viewModel.reportText(res);
  assert.ok(text.includes('bob'));
  assert.ok(text.includes('1010'));
});
