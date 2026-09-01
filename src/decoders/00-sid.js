// rv.decoders — SID parsing/formatting (MS-DTYP §2.4.2) and the well-known
// trustee map used by the svcacls weak-ACL audit.
(function (RV) {
  'use strict';

  /**
   * Parse a binary SID. Never throws on plausible input; returns null when
   * the bytes are too short or the sub-authority count is absurd.
   * @returns {{revision:number, authority:string, subAuthorities:number[],
   *   text:string}|null}
   */
  function parseSid(bytes) {
    if (!bytes || bytes.length < 8) return null;
    const revision = bytes[0];
    const count = bytes[1];
    if (count > 8 || bytes.length < 8 + count * 4) return null;
    // IdentifierAuthority: 6 bytes, big-endian, conventionally rendered as a
    // single decimal (values > 2^32 keep full precision here).
    let auth = 0;
    for (let i = 2; i < 8; i++) auth = auth * 256 + bytes[i];
    const subs = [];
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let i = 0; i < count; i++) subs.push(dv.getUint32(8 + i * 4, true));
    return { revision, authority: String(auth), subAuthorities: subs, text: formatSid({ authority: String(auth), subAuthorities: subs }) };
  }

  function formatSid(sid) {
    return `S-1-${sid.authority}-${sid.subAuthorities.join('-')}`;
  }

  // Trustees that regular (non-admin) processes run as — the "writable by
  // the wrong people" set the svcacls plugin flags (T1574.011).
  const WELL_KNOWN_SIDS = Object.freeze({
    'S-1-1-0': 'Everyone',
    'S-1-5-4': 'Interactive',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'Local Service',
    'S-1-5-20': 'Network Service',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
  });

  /** Friendly name for a SID when well-known, else the SID text. */
  function sidLabel(sidText) {
    return WELL_KNOWN_SIDS[sidText] || sidText;
  }

  RV.decoders = RV.decoders || {};
  Object.assign(RV.decoders, { parseSid, formatSid, sidLabel, WELL_KNOWN_SIDS });
})(window.RV);
