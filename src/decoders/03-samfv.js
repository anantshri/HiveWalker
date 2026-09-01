// rv.decoders — SAM F and V value binary structures. Offsets validated
// against the MIT-licensed regipy samparse plugin as a format reference
// (reimplemented; layout facts documented in docs/crypto-notes.md).
(function (RV) {
  'use strict';

  // ACB account-control bits (public flag table; see crypto-notes.md).
  const ACCOUNT_FLAGS = Object.freeze([
    [0x0001, 'Account Disabled'],
    [0x0002, 'Home Directory Required'],
    [0x0004, 'Password Not Required'],
    [0x0008, 'Temp Duplicate Account'],
    [0x0010, 'Normal User Account'],
    [0x0020, 'MNS Logon Account'],
    [0x0040, 'Interdomain Trust Account'],
    [0x0080, 'Workstation Trust Account'],
    [0x0100, 'Server Trust Account'],
    [0x0200, 'Password Never Expires'],
    [0x0400, 'Account Auto Locked'],
    [0x0800, 'Encrypted Text Password Allowed'],
    [0x1000, 'Smartcard Required'],
    [0x2000, 'Trusted For Delegation'],
    [0x4000, 'Not Delegated'],
    [0x8000, 'Use DES Key Only'],
    [0x10000, 'Preauth Not Required'],
    [0x20000, 'Password Expired'],
    [0x40000, 'Trusted To Auth For Delegation'],
    [0x80000, 'No Auth Data Required'],
    [0x100000, 'Partial Secrets Account'],
  ]);

  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function u64Big(b, o) {
    if (o + 8 > b.length) return null;
    return BigInt(u32(b, o + 4)) * 0x100000000n + BigInt(u32(b, o));
  }

  /**
   * Parse the F value (account metadata). Returns null when too short.
   * FILETIMEs are BigInt ns-since-1601 or null (0 / never / out of range).
   */
  function parseSamFValue(data) {
    if (!data || data.length < 0x48) return null;
    const ft = (o) => {
      const v = u64Big(data, o);
      if (v === null || v === 0n || v === 0x7fffffffffffffffn) return { raw: v, never: true };
      if (v > 0x8000000000000000n) return { raw: v, never: false, invalid: true };
      return { raw: v, never: false };
    };
    return {
      lastLogon: ft(0x08),
      passwordLastSet: ft(0x18),
      accountExpires: ft(0x20),
      lastFailedLogon: ft(0x28),
      rid: u32(data, 0x30),
      accountFlags: u16(data, 0x38),
      failedLoginCount: u16(data, 0x40),
      loginCount: u16(data, 0x42),
      // Raw F bytes are also needed for the Vista+ hash decryption key
      // derivation (the key-material slice), so keep a reference.
      raw: data,
    };
  }

  /** Decode ACB flag bits to their names (unknown bits rendered as hex). */
  function parseAccountFlags(flags) {
    const names = [];
    let known = 0;
    for (const [bit, name] of ACCOUNT_FLAGS) {
      if (flags & bit) { names.push(name); known |= bit; }
    }
    const unknown = flags & ~known & 0xffffff;
    if (unknown) names.push(`unknown-0x${unknown.toString(16)}`);
    return names;
  }

  // V value: header of (offset u32, length u32) pairs relative to 0xCC.
  const V_FIELDS = Object.freeze([
    ['username', 0x0c],
    ['fullname', 0x18],
    ['comment', 0x24],
    ['userComment', 0x30],
    ['homeDirectory', 0x48],
    ['homeDirectoryConnect', 0x54],
    ['scriptPath', 0x60],
    ['profilePath', 0x6c],
    ['workstations', 0x78],
  ]);
  const LM_REGION = 0x9c;  // (offset, length) pair location for the LM hash blob
  const NT_REGION = 0xa8;  // ... and for the NT hash blob

  /**
   * Parse the V value. String fields become UTF-16LE text when present;
   * hash regions are exposed as byte slices for the samhashes plugin.
   */
  function parseSamVValue(data) {
    if (!data || data.length < 0xcc) return null;
    const out = { fields: {}, lmHashBlob: null, ntHashBlob: null, passwordHistoryBlob: null };
    const readRegion = (pairOff) => {
      const off = u32(data, pairOff);
      const len = u32(data, pairOff + 4);
      if (len === 0 || off + 0xcc + len > data.length) return null;
      return data.subarray(off + 0xcc, off + 0xcc + len);
    };
    for (const [name, pairOff] of V_FIELDS) {
      const blob = readRegion(pairOff);
      if (blob) {
        let s = '';
        for (let i = 0; i + 1 < blob.length; i += 2) {
          const c = blob[i] | (blob[i + 1] << 8);
          if (c === 0) break;
          s += String.fromCharCode(c);
        }
        out.fields[name] = s;
      }
    }
    out.lmHashBlob = readRegion(LM_REGION);
    out.ntHashBlob = readRegion(NT_REGION);
    return out;
  }

  RV.decoders = RV.decoders || {};
  Object.assign(RV.decoders, {
    parseSamFValue, parseSamVValue, parseAccountFlags, ACCOUNT_FLAGS,
  });
})(window.RV);
