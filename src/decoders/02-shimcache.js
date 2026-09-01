// rv.decoders — AppCompatCache ("ShimCache") binary formats, reimplemented
// from the Mandiant-published format documentation (ShimCacheParser.py,
// Apache 2.0 — format facts only) and libyal's AppCompatCache pages.
// Entry points: detectShimcacheVersion(bytes) → {os, bits?} and
// parseShimcache(bytes) → {os, label, entries:[{path, lastModified?, size?,
// execFlag?}]}. Defensive throughout: bad data shortens the list, never throws.
(function (RV) {
  'use strict';

  const C = RV.crypto;

  const MAGIC_NT5_2 = 0xbadc0ffe;   // Server 2003 / Vista / 2008
  const MAGIC_NT6_1 = 0xbadc0fee;   // Win7 / 2008 R2
  const MAGIC_XP = 0xdeadbeef;      // XP 32-bit
  const WIN8_STATS = 0x80;          // stats header size for Win8/8.1
  const WIN10_STATS = 0x30;         // stats header size for Win10
  const MAGIC_WIN8 = '00ts';
  const MAGIC_WIN81 = '10ts';
  const MAGIC_WIN10 = '10ts';
  const CSRSS_FLAG = 0x2;

  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function ascii(b, o, n) { let s = ''; for (let i = 0; i < n; i++) s += String.fromCharCode(b[o + i]); return s; }

  function utf16(b, o, byteLen) {
    let s = '';
    const end = Math.min(o + byteLen, b.length - 1);
    for (let i = o; i + 1 <= end; i += 2) {
      const c = b[i] | (b[i + 1] << 8);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  function filetime(b, o) {
    if (o + 8 > b.length) return null;
    const lo = u32(b, o), hi = u32(b, o + 4);
    if (lo === 0 && hi === 0) return null;
    const ns = BigInt(hi) * 0x100000000n + BigInt(lo);
    if (ns <= 0 || ns > 0x8000000000000000n) return null;
    return ns;
  }

  function detectShimcacheVersion(b) {
    if (!b || b.length < 16) return { os: 'unknown' };
    const magic = u32(b, 0);
    if (magic === MAGIC_XP) return { os: 'xp' };
    if (magic === MAGIC_NT5_2) return { os: '2003', bits: probe64Nt5(b, 8) ? 64 : 32 };
    if (magic === MAGIC_NT6_1) return { os: 'win7', bits: probe64Nt5(b, 0x80) ? 64 : 32 };
    if (b.length > WIN8_STATS && ascii(b, WIN8_STATS, 4) === MAGIC_WIN8) return { os: 'win8' };
    if (b.length > WIN8_STATS && ascii(b, WIN8_STATS, 4) === MAGIC_WIN81) return { os: 'win8.1' };
    if (b.length > WIN10_STATS && ascii(b, WIN10_STATS, 4) === MAGIC_WIN10) return { os: 'win10' };
    if (b.length > WIN10_STATS + 4 && ascii(b, WIN10_STATS + 4, 4) === MAGIC_WIN10) return { os: 'win10', creators: true };
    return { os: 'unknown' };
  }

  // 64-bit entries serialise UNICODE_STRINGs with u64 pointers, so a valid
  // size is followed by a NULL dword (published Mandiant probe).
  function probe64Nt5(b, headerSize) {
    if (b.length < headerSize + 8) return false;
    const testSize = u16(b, headerSize);
    const testMax = u16(b, headerSize + 2);
    return (testMax - testSize === 2 && u32(b, headerSize + 4) === 0);
  }

  function parseShimcache(b) {
    const v = detectShimcacheVersion(b);
    const out = { os: v.os, label: '', entries: [] };
    if (v.os === 'unknown') return out;
    if (v.os === 'xp') { out.label = 'Windows XP (last-modified + file size)'; readXp(b, out.entries); }
    else if (v.os === '2003') { out.label = `Server 2003/Vista/2008 (${v.bits}-bit)`; readNt5(b, v.bits === 64 ? 0x20 : 0x18, 8, out.entries); }
    else if (v.os === 'win7') { out.label = `Windows 7/2008 R2 (${v.bits}-bit, exec flag)`; readNt6(b, v.bits === 64 ? 0x30 : 0x20, out.entries); }
    else if (v.os === 'win8' || v.os === 'win8.1') { out.label = v.os === 'win8' ? 'Windows 8/2012 (exec flag)' : 'Windows 8.1/2012 R2 (exec flag)'; readWin8(b, WIN8_STATS, out.entries); }
    else if (v.os === 'win10') {
      out.label = v.creators
        ? 'Windows 10 Creators+ (insertion order only)'
        : 'Windows 10 (insertion order only)';
      readWin10(b, v.creators ? WIN10_STATS + 4 : WIN10_STATS, out.entries);
    }
    return out;
  }

  function readXp(b, entries) {
    const num = u32(b, 8);
    const ENTRY = 0x228, HEADER = 0x190, MAX_PATH = 520;
    const count = Math.min(num, 10000);
    for (let i = 0; i < count; i++) {
      const off = HEADER + i * ENTRY;
      if (off + ENTRY > b.length) break;
      // No size field; scan for the UTF-16 terminator.
      let pathLen = 0;
      const scanEnd = Math.min(off + MAX_PATH + 8, b.length - 1);
      for (let p = off; p + 1 < scanEnd; p += 2) {
        if (b[p] === 0 && b[p + 1] === 0) { pathLen = p - off; break; }
      }
      if (pathLen === 0) continue;
      const path = utf16(b, off, pathLen + 2);
      const d = off + MAX_PATH + 8;
      const lastModified = filetime(b, d);
      const size = u32(b, d + 8);
      const execTime = filetime(b, d + 16);
      entries.push({ path, lastModified, size: size === 0 ? null : size, execTime });
    }
  }

  function readNt5(b, entrySize, headerSize, entries) {
    const num = u32(b, 4);
    const count = Math.min(num, 10000);
    for (let i = 0; i < count; i++) {
      const off = headerSize + i * entrySize;
      if (off + entrySize > b.length) break;
      const wLength = u16(b, off);
      const offset = u32(b, off + (entrySize === 0x18 ? 6 : 8)); // 32-bit: no pad after the 2 u16s
      const lastModified = filetime(b, off + (entrySize === 0x18 ? 12 : 16));
      const sizeLow = u32(b, off + (entrySize === 0x18 ? 20 : 28));
      if (offset + wLength > b.length) continue;
      const path = utf16(b, offset, wLength);
      entries.push({ path, lastModified, size: sizeLow === 0 ? null : sizeLow });
    }
  }

  function readNt6(b, entrySize, entries) {
    const num = u32(b, 4);
    const HEADER = 0x80;
    const count = Math.min(num, 10000);
    for (let i = 0; i < count; i++) {
      const off = HEADER + i * entrySize;
      if (off + entrySize > b.length) break;
      const wLength = u16(b, off);
      const offset = u32(b, off + (entrySize === 0x20 ? 6 : 8));
      const lastModified = filetime(b, off + (entrySize === 0x20 ? 12 : 16));
      const fileFlags = u32(b, off + (entrySize === 0x20 ? 20 : 28));
      if (offset + wLength > b.length) continue;
      const path = utf16(b, offset, wLength);
      entries.push({ path, lastModified, execFlag: (fileFlags & CSRSS_FLAG) !== 0 });
    }
  }

  function readWin8(b, statsSize, entries) {
    const magic = ascii(b, statsSize, 4);
    let p = statsSize + 4;
    while (p + 12 <= b.length) {
      const tag = ascii(b, p, 4);
      if (tag !== magic) break;
      const entryLen = u32(b, p + 8);
      p += 12;
      if (p + entryLen > b.length) break;
      const e = b.subarray(p, p + entryLen);
      const pathLen = u16(e, 0);
      const path = pathLen > 0 ? utf16(e, 2, pathLen) : '(none)';
      let q = 2 + pathLen;
      const packageLen = u16(e, q); q += 2 + packageLen;
      if (q + 20 <= e.length) {
        const flags = u32(e, q);
        const lastModified = filetime(e, q + 8);
        entries.push({ path, lastModified, execFlag: (flags & CSRSS_FLAG) !== 0 });
      } else {
        entries.push({ path });
      }
      p += entryLen;
    }
  }

  function readWin10(b, statsSize, entries) {
    const magic = ascii(b, statsSize, 4);
    let p = statsSize + 4;
    while (p + 12 <= b.length) {
      const tag = ascii(b, p, 4);
      if (tag !== magic) break;
      const entryLen = u32(b, p + 8);
      p += 12;
      if (p + entryLen > b.length) break;
      const e = b.subarray(p, p + entryLen);
      const pathLen = u16(e, 0);
      const path = pathLen > 0 ? utf16(e, 2, pathLen) : '(none)';
      const lastModified = filetime(e, 2 + pathLen);
      // Win10 skips Microsoft-signed entries (both timestamp words zero).
      entries.push({ path, lastModified });
      p += entryLen;
    }
  }

  RV.decoders = RV.decoders || {};
  Object.assign(RV.decoders, { detectShimcacheVersion, parseShimcache });
})(window.RV);
