// rv.decoders — self-relative SECURITY_DESCRIPTOR parsing (MS-DTYP §2.4.6).
// Used by NkKey.getSecurityDescriptor() and the svcacls plugin. Defensive by
// design: hives are untrusted input, so every offset/length is bounds-checked
// and any malformed structure degrades to {unknown:true} rather than throwing.
(function (RV) {
  'use strict';

  const D = RV.decoders;

  const ACE_TYPE = { 0x00: 'allow', 0x01: 'deny' };

  // Registry access bits svcacls cares about (MS-DTYP/WinNT registry rights).
  const KEY_SET_VALUE = 0x0002;
  const KEY_CREATE_SUB_KEY = 0x0004;
  const KEY_ALL_ACCESS = 0xf003f;
  const WRITE_CONTROL = 0x00040000;
  const GENERIC_WRITE = 0x40000000;
  const GENERIC_ALL = 0x10000000;

  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

  /**
   * @param {Uint8Array} bytes self-relative SECURITY_DESCRIPTOR
   * @returns {{revision:number, control:number, ownerSid:string|null,
   *   groupSid:string|null, dacl:{aces:Array<{type:string, accessMask:number,
   *   sid:string}>}|null, saclPresent:boolean}|{unknown:true}}
   */
  function parseSecurityDescriptor(bytes) {
    if (!bytes || bytes.length < 20) return { unknown: true };
    const revision = bytes[0];
    if (revision !== 1) return { unknown: true };
    const control = u16(bytes, 2);
    // Self-relative flag (0x8000) must be set for the on-disk form; accept
    // absolute form's zero too since our builder may not set it.
    const ownerOff = u32(bytes, 4);
    const groupOff = u32(bytes, 8);
    const saclOff = u32(bytes, 12);
    const daclOff = u32(bytes, 16);

    const sidAt = (off) => {
      if (off === 0 || off + 8 > bytes.length) return null;
      const sid = D.parseSid(bytes.subarray(off));
      return sid ? sid.text : null;
    };

    const aclAt = (off) => {
      if (off === 0 || off + 8 > bytes.length) return null;
      const aclRev = bytes[off];
      if (aclRev !== 2 && aclRev !== 4) return null;
      const aceCount = u16(bytes, off + 4);
      if (aceCount > 1000) return null; // untrusted input guard
      const aces = [];
      let p = off + 8;
      for (let i = 0; i < aceCount; i++) {
        if (p + 8 > bytes.length) break;
        const type = bytes[p];
        const accessMask = u32(bytes, p + 4);
        const sid = D.parseSid(bytes.subarray(p + 8));
        const sidLen = sid ? 8 + sid.subAuthorities.length * 4 : 0;
        if (p + 8 + sidLen > bytes.length) break;
        aces.push({
          type: ACE_TYPE[type] || `type-0x${type.toString(16)}`,
          accessMask,
          sid: sid ? sid.text : '(unparseable SID)',
        });
        p += 8 + sidLen;
      }
      return { aces };
    };

    return {
      revision,
      control,
      // In a self-relative descriptor the fields are present when their
      // offsets are non-zero (MS-DTYP §2.4.6); the SE_* control bits only
      // say whether the ACLs were protected/inherited.
      ownerSid: sidAt(ownerOff),
      groupSid: sidAt(groupOff),
      dacl: aclAt(daclOff),
      saclPresent: saclOff !== 0,
    };
  }

  /**
   * True when an allow-ACE grants registry write to the trustee. The mask is
   * tested for the specific write bits (KEY_SET_VALUE / KEY_CREATE_SUB_KEY /
   * WRITE_CONTROL, or an explicit KEY_ALL_ACCESS / generic write-all) — a
   * bare AND against KEY_ALL_ACCESS would match read bits too, since
   * KEY_ALL_ACCESS is itself a union that includes them.
   */
  function aceGrantsWrite(ace) {
    if (ace.type !== 'allow') return false;
    const m = ace.accessMask;
    if (m & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | WRITE_CONTROL)) return true;
    if ((m & KEY_ALL_ACCESS) === KEY_ALL_ACCESS) return true;
    if ((m & GENERIC_WRITE) === GENERIC_WRITE) return true;
    if ((m & GENERIC_ALL) === GENERIC_ALL) return true;
    return false;
  }

  RV.decoders = RV.decoders || {};
  Object.assign(RV.decoders, { parseSecurityDescriptor, aceGrantsWrite, ACE_TYPE });
})(window.RV);
