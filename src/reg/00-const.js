// rv.reg — constants: signatures, value types, flags, nk layout tables, limits.
// Format references: docs/regf-format.md (offsets + provenance).
(function (RV) {
  'use strict';

  const SIG = Object.freeze({
    REGF: 'regf',
    HBIN: 'hbin',
    NK: 'nk',
    VK: 'vk',
    SK: 'sk',
    LF: 'lf',
    LH: 'lh',
    LI: 'li',
    RI: 'ri',
    DB: 'db',
    CM_KEY_NODE: 'CM_KEY_NODE',
    CM_KEY_VALUE: 'CM_KEY_VALUE',
    CM_KEY_SECURITY: 'CM_KEY_SECURITY',
    CM_KEY_INDEX: 'CM_KEY_INDEX',
    CM_KEY_FAST_INDEX: 'CM_KEY_FAST_INDEX',
    CM_KEY_FAST_LEAF: 'CM_KEY_FAST_LEAF',
    CM_KEY_HASH_LEAF: 'CM_KEY_HASH_LEAF',
    CM_KEY_INDEX_LEAF: 'CM_KEY_INDEX_LEAF',
  });

  // Subkey-list signatures that carry (u32 offset, u32 hash) pairs.
  const HASHED_LIST_SIGS = new Set([SIG.LF, SIG.LH, SIG.CM_KEY_FAST_INDEX, SIG.CM_KEY_FAST_LEAF, SIG.CM_KEY_HASH_LEAF]);
  // Subkey-list signatures that carry plain u32 offsets to nk records.
  const INDEX_LIST_SIGS = new Set([SIG.LI, SIG.CM_KEY_INDEX_LEAF, SIG.DB]);
  // ri: entries point at *other* list records (indirection).
  const INDIRECT_LIST_SIGS = new Set([SIG.RI, SIG.CM_KEY_INDEX]);

  const REG_NONE = 0;
  const REG_SZ = 1;
  const REG_EXPAND_SZ = 2;
  const REG_BINARY = 3;
  const REG_DWORD = 4;
  const REG_DWORD_BIG_ENDIAN = 5;
  const REG_LINK = 6;
  const REG_MULTI_SZ = 7;
  const REG_RESOURCE_LIST = 8;
  const REG_FULL_RESOURCE_DESCRIPTOR = 9;
  const REG_RESOURCE_REQUIREMENTS_LIST = 10;
  const REG_QWORD = 11;

  const VALUE_TYPE_NAMES = Object.freeze({
    [REG_NONE]: 'REG_NONE',
    [REG_SZ]: 'REG_SZ',
    [REG_EXPAND_SZ]: 'REG_EXPAND_SZ',
    [REG_BINARY]: 'REG_BINARY',
    [REG_DWORD]: 'REG_DWORD (32-bit)',
    [REG_DWORD_BIG_ENDIAN]: 'REG_DWORD_BIG_ENDIAN',
    [REG_LINK]: 'REG_LINK',
    [REG_MULTI_SZ]: 'REG_MULTI_SZ',
    [REG_RESOURCE_LIST]: 'REG_RESOURCE_LIST',
    [REG_FULL_RESOURCE_DESCRIPTOR]: 'REG_FULL_RESOURCE_DESCRIPTOR',
    [REG_RESOURCE_REQUIREMENTS_LIST]: 'REG_RESOURCE_REQUIREMENTS_LIST',
    [REG_QWORD]: 'REG_QWORD (64-bit)',
  });

  // Binary-flavoured types render through the hex viewer.
  const BINARY_TYPES = new Set([
    REG_NONE, REG_BINARY, REG_RESOURCE_LIST,
    REG_FULL_RESOURCE_DESCRIPTOR, REG_RESOURCE_REQUIREMENTS_LIST,
  ]);

  // nk flag bits.
  const KEY_VOLATILE = 0x0001;
  const KEY_HIVE_EXIT = 0x0002;
  const KEY_HIVE_ENTRY = 0x0004;
  const KEY_NO_DELETE = 0x0008;
  const KEY_SYM_LINK = 0x0010;
  const KEY_COMP_NAME = 0x0020;
  const KEY_PREDEF_HANDLE = 0x0040;
  const KEY_VIRT_MIRRORED = 0x0080;
  const KEY_VIRT_TARGET = 0x0100;
  const KEY_VIRTUAL_STORE = 0x0200;
  const KEY_NAME_FOLD = 0x0400;

  // vk flag bits.
  const VALUE_COMP_NAME = 0x0001;

  // Sentinel used across the format for "no offset".
  const NO_OFFSET = 0xffffffff;

  // Field offset tables per key-node signature. Name bytes follow the fixed
  // header at `nameAt`; lengths are u16 unless noted.
  const NK_LAYOUTS = Object.freeze({
    // Classic pre-1709 layout, 2-byte signature.
    nk: Object.freeze({
      sig: SIG.NK,
      sigLen: 2,
      flags: 0x02, // u16
      timestamp: 0x04, // u64 FILETIME
      accessBits: 0x0c,
      parent: 0x10,
      subkeyCount: 0x14,
      volSubkeyCount: 0x18,
      subkeyList: 0x1c,
      volValueCount: 0x20,
      valueCount: 0x24,
      valueList: 0x28,
      sk: 0x2c,
      className: 0x30,
      maxSubkeyLen: 0x34,
      maxClassLen: 0x38,
      maxValNameLen: 0x3c,
      maxValDataLen: 0x40,
      nameLen: 0x48, // u16
      classLen: 0x4a, // u16
      nameAt: 0x4c,
    }),
    // Windows 10 1709+ layout, 11-byte ASCII signature. Fixed fields shift by
    // 9 bytes (sig grows 2→11); provenance in docs/regf-format.md.
    CM_KEY_NODE: Object.freeze({
      sig: SIG.CM_KEY_NODE,
      sigLen: 11,
      flags: 0x0b, // u16
      timestamp: 0x0d, // u64 FILETIME
      accessBits: 0x15,
      parent: 0x19,
      subkeyCount: 0x1d,
      volSubkeyCount: 0x21,
      subkeyList: 0x25,
      volValueCount: 0x29,
      valueCount: 0x2d,
      valueList: 0x31,
      sk: 0x35,
      className: 0x39,
      maxSubkeyLen: 0x3d,
      maxClassLen: 0x41,
      maxValNameLen: 0x45,
      maxValDataLen: 0x49,
      nameLen: 0x51, // u16
      classLen: 0x53, // u16
      nameAt: 0x55,
    }),
  });

  // vk field offsets per signature.
  const VK_LAYOUTS = Object.freeze({
    vk: Object.freeze({
      sig: SIG.VK,
      sigLen: 2,
      nameLen: 0x02, // u16
      dataLen: 0x04, // u32 (high bit set => inline data)
      dataOffset: 0x08, // u32 (or inline bytes when high bit set)
      type: 0x0c, // u32
      flags: 0x10, // u16
      nameAt: 0x14,
    }),
    CM_KEY_VALUE: Object.freeze({
      sig: SIG.CM_KEY_VALUE,
      sigLen: 12,
      nameLen: 0x0c, // u16
      dataLen: 0x0e, // u32
      dataOffset: 0x12,
      type: 0x16,
      flags: 0x1a, // u16
      nameAt: 0x1e,
    }),
  });

  // sk field offsets (classic; CM_KEY_SECURITY mirrors them shifted by 9).
  const SK_LAYOUTS = Object.freeze({
    sk: Object.freeze({ sig: SIG.SK, sigLen: 2, prev: 0x04, next: 0x08, refCount: 0x0c, descriptorLen: 0x10 }),
    CM_KEY_SECURITY: Object.freeze({ sig: SIG.CM_KEY_SECURITY, sigLen: 11, prev: 0x0d, next: 0x11, refCount: 0x15, descriptorLen: 0x19 }),
  });

  // Safety limits for untrusted input.
  const LIMITS = Object.freeze({
    MAX_SUBKEYS_PER_NODE: 1 << 20,
    MAX_VALUES_PER_NODE: 1 << 20,
    MAX_LIST_ENTRIES: 1 << 20,
    MAX_DEPTH: 64,
    MAX_STRING_CHARS: 1 << 20,
    MAX_SEARCH_RESULTS: 5000,
    MAX_WALK_KEYS: 5_000_000,
    REGF_BLOCK_SIZE: 4096,
    HBIN_SIZE: 4096,
  });

  RV.reg.consts = {
    SIG, HASHED_LIST_SIGS, INDEX_LIST_SIGS, INDIRECT_LIST_SIGS,
    REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN,
    REG_LINK, REG_MULTI_SZ, REG_RESOURCE_LIST, REG_FULL_RESOURCE_DESCRIPTOR,
    REG_RESOURCE_REQUIREMENTS_LIST, REG_QWORD,
    VALUE_TYPE_NAMES, BINARY_TYPES,
    KEY_VOLATILE, KEY_HIVE_EXIT, KEY_HIVE_ENTRY, KEY_NO_DELETE, KEY_SYM_LINK,
    KEY_COMP_NAME, KEY_PREDEF_HANDLE, KEY_VIRT_MIRRORED, KEY_VIRT_TARGET,
    KEY_VIRTUAL_STORE, KEY_NAME_FOLD, VALUE_COMP_NAME,
    NO_OFFSET, NK_LAYOUTS, VK_LAYOUTS, SK_LAYOUTS, LIMITS,
  };
})(window.RV);
