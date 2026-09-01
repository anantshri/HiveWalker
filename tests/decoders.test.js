// Decoder unit tests: SID, security descriptor, shimcache formats, SAM F/V.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /decoders\/03-samfv/ });
const D = RV.decoders;
const C = RV.crypto;

// ---------- SID ----------

test('parseSid decodes a well-known SID', () => {
  // S-1-5-32-544 (Administrators): revision 1, 2 sub-auths after authority 5
  const bytes = new Uint8Array([0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00]);
  const sid = D.parseSid(bytes);
  assert.strictEqual(sid.text, 'S-1-5-32-544');
  assert.strictEqual(D.sidLabel('S-1-5-32-544'), 'Administrators');
  assert.strictEqual(D.sidLabel('S-1-5-21-1-2-3-4'), 'S-1-5-21-1-2-3-4');
});

test('parseSid rejects short/garbage input', () => {
  assert.strictEqual(D.parseSid(null), null);
  assert.strictEqual(D.parseSid(new Uint8Array(4)), null);
  // claims 8 sub-auths but only carries 1
  assert.strictEqual(D.parseSid(new Uint8Array([1, 8, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0])), null);
});

// ---------- security descriptor ----------

/** Build a minimal self-relative SD: revision 1, owner SID, DACL with one ACE. */
function buildSd({ ownerSid, aceType = 0x00, accessMask, aceSid }) {
  const sidBytes = (sidText) => {
    const parts = sidText.split('-').map(Number);
    const subs = parts.slice(3);
    const out = [1, subs.length, 0, 0, 0, 0, 0, parts[2]];
    for (const s of subs) {
      out.push(s & 0xff, (s >>> 8) & 0xff, (s >>> 16) & 0xff, (s >>> 24) & 0xff);
    }
    return out;
  };
  const owner = sidBytes(ownerSid);
  const ace = sidBytes(aceSid);
  // layout: header(20) owner acl
  const aclOff = 20 + owner.length;
  const aceOff = aclOff + 8;
  const total = aceOff + 8 + ace.length;
  const b = new Uint8Array(total);
  const dv = new DataView(b.buffer);
  b[0] = 1; // revision
  dv.setUint16(2, 0x8000, true); // self-relative
  dv.setUint32(4, 20, true); // owner offset
  dv.setUint32(16, aclOff, true); // dacl offset
  b.set(owner, 20);
  b[aclOff] = 2; // ACL revision
  dv.setUint16(aclOff + 4, 1, true); // ace count
  b[aceOff] = aceType;
  dv.setUint32(aceOff + 4, accessMask, true);
  b.set(ace, aceOff + 8);
  return b;
}

test('parseSecurityDescriptor reads owner + allow ACE', () => {
  const sd = buildSd({ ownerSid: 'S-1-5-18', accessMask: 0xf003f, aceSid: 'S-1-5-32-544' });
  const parsed = D.parseSecurityDescriptor(sd);
  assert.ok(!parsed.unknown);
  assert.strictEqual(parsed.ownerSid, 'S-1-5-18');
  assert.strictEqual(parsed.dacl.aces.length, 1);
  assert.strictEqual(parsed.dacl.aces[0].type, 'allow');
  assert.strictEqual(parsed.dacl.aces[0].sid, 'S-1-5-32-544');
  assert.strictEqual(D.aceGrantsWrite(parsed.dacl.aces[0]), true);
});

test('aceGrantsWrite ignores read-only and deny ACEs', () => {
  const sd = buildSd({ ownerSid: 'S-1-5-18', accessMask: 0x0001 /* KEY_QUERY_VALUE */, aceSid: 'S-1-1-0' });
  const parsed = D.parseSecurityDescriptor(sd);
  assert.strictEqual(D.aceGrantsWrite(parsed.dacl.aces[0]), false);
  const deny = buildSd({ ownerSid: 'S-1-5-18', aceType: 0x01, accessMask: 0xf003f, aceSid: 'S-1-1-0' });
  const parsedDeny = D.parseSecurityDescriptor(deny);
  assert.strictEqual(D.aceGrantsWrite(parsedDeny.dacl.aces[0]), false);
});

test('parseSecurityDescriptor degrades on garbage', () => {
  assert.strictEqual(D.parseSecurityDescriptor(null).unknown, true);
  assert.strictEqual(D.parseSecurityDescriptor(new Uint8Array(5)).unknown, true);
  assert.strictEqual(D.parseSecurityDescriptor(new Uint8Array(20).fill(9)).unknown, true);
});

// ---------- shimcache ----------

function ftBytes(dateMs) {
  const ns = BigInt(dateMs) * 10000n + 116444736000000000n;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(ns);
  return buf;
}

test('shimcache detects and parses a synthetic Win7 64-bit blob', () => {
  // magic, count; then a 0x30 entry; path lives at a known offset.
  const path = Buffer.from('C:\\Windows\\System32\\evil.exe\0', 'utf16le');
  const HEADER = 0x80;
  const ENTRY = 0x30;
  const PATH_OFF = HEADER + ENTRY; // one entry then the path data
  const buf = Buffer.alloc(HEADER + ENTRY + path.length);
  buf.writeUInt32LE(0xbadc0fee, 0);
  buf.writeUInt32LE(1, 4);
  // entry 0 at 0x80
  const e = HEADER;
  buf.writeUInt16LE(path.length, e);            // wLength
  buf.writeUInt16LE(path.length + 2, e + 2);    // wMaximumLength (64-bit probe: diff 2, next u32 = 0)
  buf.writeUInt32LE(0, e + 4);                  // padding (64-bit)
  buf.writeUInt32LE(PATH_OFF, e + 8);           // offset
  ftBytes(Date.UTC(2026, 0, 15)).copy(buf, e + 16);
  buf.writeUInt32LE(0x2, e + 28);               // file flags: CSRSS executed
  path.copy(buf, PATH_OFF);
  const parsed = D.parseShimcache(new Uint8Array(buf));
  assert.strictEqual(parsed.os, 'win7');
  assert.strictEqual(parsed.entries.length, 1);
  assert.strictEqual(parsed.entries[0].path, 'C:\\Windows\\System32\\evil.exe');
  assert.strictEqual(parsed.entries[0].execFlag, true);
});

test('shimcache handles Win10 magic + creators offset', () => {
  const path = Buffer.from('C:\\tmp\\a.dll\0', 'utf16le');
  // Win10: header 0x30 bytes, '10ts', then entry stream.
  const stats = 0x30;
  const entryBody = Buffer.alloc(2 + path.length + 8);
  entryBody.writeUInt16LE(path.length, 0);
  path.copy(entryBody, 2);
  ftBytes(Date.UTC(2025, 5, 1)).copy(entryBody, 2 + path.length);
  const buf = Buffer.alloc(stats + 4 + 12 + entryBody.length);
  buf.write('10ts', stats, 'latin1');
  buf.write('10ts', stats + 4, 'latin1');
  buf.writeUInt32LE(0, stats + 8); // crc
  buf.writeUInt32LE(entryBody.length, stats + 12);
  entryBody.copy(buf, stats + 16);
  const parsed = D.parseShimcache(new Uint8Array(buf));
  assert.strictEqual(parsed.os, 'win10');
  assert.strictEqual(parsed.entries.length, 1);
  assert.strictEqual(parsed.entries[0].path, 'C:\\tmp\\a.dll');
});

test('shimcache unknown magic degrades gracefully', () => {
  const buf = new Uint8Array(64).fill(0x41);
  const parsed = D.parseShimcache(buf);
  assert.strictEqual(parsed.os, 'unknown');
  assert.deepStrictEqual(parsed.entries, []);
});

// ---------- SAM F/V ----------

function padV(stringsAndHashes) {
  // Build a minimal valid V value: header to 0xCC then data regions.
  const regions = [];
  const putField = (pairOff, data) => {
    if (data == null) return;
    regions.push({ data: Buffer.from(data), headerOffset: pairOff });
  };
  putField(0x0c, Buffer.from(stringsAndHashes.username ?? '', 'utf16le'));
  putField(0x18, Buffer.from(stringsAndHashes.fullname ?? '', 'utf16le'));
  putField(0x9c, stringsAndHashes.lm ?? null);
  putField(0xa8, stringsAndHashes.nt ?? null);
  const total = 0xcc + regions.reduce((n, r) => n + r.data.length, 0);
  const v = Buffer.alloc(total);
  let off = 0;
  for (const r of regions) {
    v.writeUInt32LE(off, r.headerOffset);
    v.writeUInt32LE(r.data.length, r.headerOffset + 4);
    r.data.copy(v, 0xcc + off);
    off += r.data.length;
  }
  return v;
}

test('parseSamFValue extracts timestamps, RID and flags', () => {
  const f = Buffer.alloc(0x50);
  ftBytes(Date.UTC(2026, 7, 20)).copy(f, 0x08);
  ftBytes(Date.UTC(2026, 0, 2)).copy(f, 0x18);
  f.writeUInt32LE(500, 0x30);
  f.writeUInt16LE(0x0210, 0x38); // Normal User + Password Never Expires
  f.writeUInt16LE(2, 0x40);
  f.writeUInt16LE(41, 0x42);
  const parsed = D.parseSamFValue(new Uint8Array(f));
  assert.strictEqual(parsed.rid, 500);
  assert.strictEqual(parsed.loginCount, 41);
  assert.strictEqual(parsed.failedLoginCount, 2);
  const names = D.parseAccountFlags(parsed.accountFlags);
  assert.ok(names.includes('Normal User Account'));
  assert.ok(names.includes('Password Never Expires'));
});

test('parseSamFValue nulls on short input', () => {
  assert.strictEqual(D.parseSamFValue(new Uint8Array(20)), null);
  assert.strictEqual(D.parseSamFValue(null), null);
});

test('parseSamVValue extracts strings and hash regions', () => {
  const lm = C.hexToBytes('aad3b435b51404eeaad3b435b51404ee');
  const nt = C.hexToBytes('8846f7eaee8fb117ad06bdd830b7586c');
  const v = padV({ username: 'Administrator', fullname: 'The Admin', lm, nt });
  const parsed = D.parseSamVValue(new Uint8Array(v));
  assert.strictEqual(parsed.fields.username, 'Administrator');
  assert.strictEqual(parsed.fields.fullname, 'The Admin');
  assert.strictEqual(C.bytesToHex(parsed.lmHashBlob), 'aad3b435b51404eeaad3b435b51404ee');
  assert.strictEqual(C.bytesToHex(parsed.ntHashBlob), '8846f7eaee8fb117ad06bdd830b7586c');
});

// ---------- parser integration: sk descriptor round-trip ----------

test('HiveBuilder security: option → NkKey.getSecurityDescriptor round-trip', () => {
  const sd = buildSd({ ownerSid: 'S-1-5-18', accessMask: 0xf003f, aceSid: 'S-1-5-11' });
  const hiveBuf = new HiveBuilder().build((r) => {
    r.key('SYSTEM', {}, (sys) => {
      sys.key('Services', {}, (svc) => {
        svc.key('weaksvc', { security: Buffer.from(sd) });
        svc.key('normal', {});
      });
    });
  });
  const hive = RV.reg.openHive(hiveBuf.toBuffer());
  const weak = hive.getKey('SYSTEM\\Services\\weaksvc');
  assert.ok(weak);
  const desc = weak.getSecurityDescriptor();
  assert.ok(desc, 'descriptor should parse');
  assert.strictEqual(desc.ownerSid, 'S-1-5-18');
  assert.strictEqual(desc.dacl.aces[0].sid, 'S-1-5-11');
  assert.strictEqual(D.aceGrantsWrite(desc.dacl.aces[0]), true);
  const normal = hive.getKey('SYSTEM\\Services\\normal');
  assert.strictEqual(normal.getSecurityDescriptor(), null);
});
