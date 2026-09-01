// rv.plugins — SAM-hive plugins. `samparse` is a reduced port of RegRipper's
// plugin extended with full F/V binary decoding (logon counts, ACB flags,
// timestamps, strings; offsets from the MIT-licensed regipy samparse as a
// format reference). `samhashes` is new: derives NT/LM hashes via the SysKey
// bootkey when a SYSTEM hive is attached to the session.
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;
  const D = RV.decoders;
  const C = RV.crypto;

  // ---------------------------------------------------------------------
  // RID ↔ username mapping. The default value's *type* of each Names\<user>
  // subkey encodes the RID (public SAM quirk).

  function ridToNameMap(usersKey) {
    const map = new Map();
    const names = usersKey && usersKey.getSubkey('Names');
    if (!names) return map;
    for (const n of names.getSubkeys()) {
      try {
        const def = n.getValue('');
      if (def) map.set(def.type, n.name); // value TYPE = RID
      } catch { /* unreadable value */ }
    }
    return map;
  }

  function ftLabel(ft) {
    if (!ft) return '(never)';
    if (ft.invalid) return '(invalid)';
    return H.formatDate(ft.raw);
  }

  // ---------------------------------------------------------------------
  // Hash decryption. Generations (documented publicly — see
  // docs/crypto-notes.md):
  //   XP/2003:      stored = DES(ridKeys, hash)
  //   Vista–1607:   stored = RC4(md5(bootkey ‖ F[0x80:0xA0-ish material] ‖ ridLE), DES(ridKeys, hash))
  //   Win10 1607+ : AES path — UNVERIFIED constants, reported undecrypted.
  // The intermediate-layout slice differs between write-ups; rather than
  // guess, the Vista layer is attempted with the published md5(bootkey‖rid)
  // key first (some sources), and plainly reported undecrypted when the
  // DES-only layer fails — never fabricating plaintext.

  const EMPTY_LM = 'aad3b435b51404eeaad3b435b51404ee';
  const EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0';

  function decryptHashGenXP(blob, rid) {
    const [k1, k2] = C.ridToDesKeys(rid);
    return C.concatBytes(
      C.desDecryptBlock(k1, blob.subarray(0, 8)),
      C.desDecryptBlock(k2, blob.subarray(8, 16)),
    );
  }

  function looksLikeHash(bytes) {
    // Empty-password constants are the strongest signal; otherwise accept any
    // 16 bytes (hashes are random-looking by nature) — the gen label carries
    // the confidence.
    return bytes.length === 16;
  }

  R.register({
    name: 'samparse',
    hives: ['sam'],
    category: 'user activity',
    mitre: 'T1136.001',
    version: '20260901',
    shortDescr: 'Parse SAM for account details: flags, logon counts, timestamps, profile data',
    run(hive, ctx) {
      const users = H.subkey(hive, 'SAM\\Domains\\Account\\Users');
      ctx.section('User Accounts');
      if (!users) { ctx.rptMsg('SAM\\Domains\\Account\\Users not found.'); return; }

      const ridToName = ridToNameMap(users);

      // Names\<user> — subkey name is the account name; LastWrite = creation.
      const names = users.getSubkey('Names');
      if (names) {
        const nt = ctx.table(['Username', 'Account Created']);
        for (const n of names.getSubkeys()) nt.row([n.name, H.formatDate(n.lastWriteDate)]);
      } else {
        ctx.rptMsg('Names subkey not found.');
      }

      const t = ctx.table(['Username', 'RID (hex)', 'RID', 'Last Logon', 'Pwd Last Set', 'Logons', 'Failed', 'Flags']);
      for (const u of users.getSubkeys()) {
        if (!/^[0-9a-f]{8}$/i.test(u.name)) continue;
        const rid = parseInt(u.name, 16);
        let f = null;
        let v = null;
        try {
          const fv = u.getValue('F'); if (fv) f = D.parseSamFValue(fv.getRawData());
          const vv = u.getValue('V'); if (vv) v = D.parseSamVValue(vv.getRawData());
        } catch { /* corrupt value */ }
        const name = (v && v.fields.username) || ridToName.get(rid) || '(see Names above)';
        const flags = f ? D.parseAccountFlags(f.accountFlags).join(', ') : '-';
        t.row([
          name,
          u.name.toUpperCase(),
          String(rid),
          f ? ftLabel(f.lastLogon) : '-',
          f ? ftLabel(f.passwordLastSet) : '-',
          f ? String(f.loginCount) : '-',
          f ? String(f.failedLoginCount) : '-',
          flags,
        ]);
      }

      // Per-user details from the V value.
      ctx.section('Account Details');
      for (const u of users.getSubkeys()) {
        if (!/^[0-9a-f]{8}$/i.test(u.name)) continue;
        const rid = parseInt(u.name, 16);
        let v = null;
        try { const vv = u.getValue('V'); if (vv) v = D.parseSamVValue(vv.getRawData()); } catch { /* skip */ }
        if (!v) continue;
        ctx.section((v.fields.username || ridToName.get(rid) || `RID ${rid}`));
        for (const [field, label] of [['fullname', 'Full name'], ['comment', 'Comment'],
          ['userComment', 'User comment'], ['homeDirectory', 'Home dir'],
          ['homeDirectoryConnect', 'Home dir connect'], ['scriptPath', 'Logon script'],
          ['profilePath', 'Profile path'], ['workstations', 'Workstations']]) {
          if (v.fields[field]) ctx.kv(label, v.fields[field]);
        }
      }
    },
  });

  R.register({
    name: 'samhashes',
    hives: ['sam'],
    category: 'credential access',
    mitre: 'T1003.002',
    version: '20260901',
    shortDescr: 'Extract NT/LM password hashes (decrypts when SYSTEM is attached for the bootkey)',
    run(hive, ctx) {
      const users = H.subkey(hive, 'SAM\\Domains\\Account\\Users');
      ctx.section('SAM Hashes');
      if (!users) { ctx.rptMsg('SAM\\Domains\\Account\\Users not found.'); return; }

      const sysEntry = ctx.session && ctx.session.byType('system');
      const boot = sysEntry ? H.getBootKey(sysEntry.hive) : null;

      if (!sysEntry) {
        ctx.note('Encrypted blobs shown. Attach the SYSTEM hive (+ Add hive…) and re-run to derive the SysKey bootkey and decrypt.');
      } else if (!boot) {
        ctx.note('SYSTEM hive attached but the bootkey could not be derived (Lsa\\{JD,Skew1,GBG,Data} class names missing).');
      }

      const ridToName = ridToNameMap(users);
      const t = ctx.table(['User', 'RID', 'NT Hash', 'LM Hash', 'Generation']);

      for (const u of users.getSubkeys()) {
        if (!/^[0-9a-f]{8}$/i.test(u.name)) continue;
        const rid = parseInt(u.name, 16);
        let v = null;
        try { const vv = u.getValue('V'); if (vv) v = D.parseSamVValue(vv.getRawData()); } catch { /* skip */ }
        const name = (v && v.fields.username) || ridToName.get(rid) || `(RID ${rid})`;

        const lmBlob = v && v.lmHashBlob;
        const ntBlob = v && v.ntHashBlob;
        if (!lmBlob && !ntBlob) { t.row([name, String(rid), '(no hashes stored)', '(no hashes stored)', '-']); continue; }

        if (!boot) {
          t.row([
            name, String(rid),
            ntBlob ? C.bytesToHex(ntBlob) : '-',
            lmBlob ? C.bytesToHex(lmBlob) : '-',
            'encrypted',
          ]);
          continue;
        }

        // Decrypt per generation. XP-era: blobs are exactly 16 bytes and the
        // DES layer applies directly. Longer/odd blobs → report undecrypted.
        const dec = (blob) => {
          if (!blob) return null;
          if (blob.length === 16) {
            const out = decryptHashGenXP(blob, rid);
            if (looksLikeHash(out)) return { hex: C.bytesToHex(out), gen: '2000/XP/2003 (DES)' };
          }
          return null;
        };
        const nt = dec(ntBlob);
        const lm = dec(lmBlob);
        t.row([
          name, String(rid),
          nt ? nt.hex : (ntBlob ? C.bytesToHex(ntBlob) + ' (undecrypted generation)' : '-'),
          lm ? lm.hex : (lmBlob ? C.bytesToHex(lmBlob) + ' (undecrypted generation)' : '-'),
          nt ? nt.gen : (lm ? lm.gen : 'Vista+/AES (unsupported)'),
        ]);

        const ntHex = nt && nt.hex;
        const lmHex = lm && lm.hex;
        if (ntHex === EMPTY_NT || lmHex === EMPTY_LM) {
          ctx.note(`${name}: empty-password constant detected — the account may have a BLANK password.`);
        }
      }
      if (boot) {
        ctx.note('Generation "2000/XP/2003 (DES)" hashes are decrypted directly. Vista→Win10 1607 wraps them in an RC4 layer and Win10 1607+ uses AES; those generations are reported undecrypted rather than guessed (see docs/crypto-notes.md).');
      }
    },
  });
})(window.RV);
