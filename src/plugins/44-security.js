// rv.plugins — SECURITY-hive plugins: machine_sid, auditpol, lsasecrets.
// Format references: adsecurity.org and libyal documentation for the LSA
// layer (see docs/crypto-notes.md); regipy's MIT-licensed domain_sid plugin
// for the PolAcDmN/PolPrDmN blob shape. Decryption only when a SYSTEM hive
// is attached (bootkey) and the generation constants are confirmed.
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;
  const D = RV.decoders;
  const C = RV.crypto;

  R.register({
    name: 'machine_sid',
    hives: ['security'],
    category: 'config',
    mitre: 'T1082',
    version: '20260901',
    shortDescr: 'Machine/domain name and SIDs from Policy\\PolAcDmN / PolPrDmN / PolMachineAccountS',
    run(hive, ctx) {
      ctx.section('Machine / Domain Identity');
      const readNameKey = (path, label) => {
        const k = H.subkey(hive, path);
        if (!k) { ctx.kv(label, '(key not found)'); return; }
        const raw = H.getValueData(k, '');
        if (!raw || raw.length < 10) { ctx.kv(label, '(unreadable value)'); return; }
        // 8-byte UNICODE_STRING-style header, then UTF-16LE name.
        let s = '';
        const body = raw.subarray(8);
        for (let i = 0; i + 1 < body.length; i += 2) {
          const c = body[i] | (body[i + 1] << 8);
          if (c === 0) break;
          s += String.fromCharCode(c);
        }
        ctx.kv(label, s);
      };
      readNameKey('Policy\\PolAcDmN', 'Account domain name');
      readNameKey('Policy\\PolPrDmN', 'Primary domain name (or workgroup)');

      const mas = H.subkey(hive, 'Policy\\PolMachineAccountS');
      if (!mas) {
        ctx.kv('Machine account SID', '(Policy\\PolMachineAccountS not found)');
        return;
      }
      const raw = H.getValueData(mas, '');
      if (raw == null || raw === '') { ctx.kv('Machine account SID', '(no value)'); return; }
      if (typeof raw === 'number' || raw.length === 4) {
        ctx.kv('Machine account SID', '(not domain-joined — REG_DWORD 0)');
        return;
      }
      const sid = D.parseSid(raw);
      if (sid) {
        ctx.kv('Machine account SID', sid.text);
        const domainSid = `S-1-${sid.authority}-${sid.subAuthorities.slice(0, -1).join('-')}`;
        ctx.kv('Domain SID', domainSid);
      } else {
        ctx.kv('Machine account SID', '(unparseable SID bytes)');
      }
    },
  });

  R.register({
    name: 'auditpol',
    hives: ['security'],
    category: 'config',
    version: '20260901',
    shortDescr: 'Audit policy from Policy\\PolAdtEv per-category settings',
    run(hive, ctx) {
      ctx.section('Audit Policy (PolAdtEv)');
      const k = H.subkey(hive, 'Policy\\PolAdtEv');
      if (!k) { ctx.rptMsg('Policy\\PolAdtEv not found.'); return; }
      const raw = H.getValueData(k, '');
      if (!raw || raw.length < 0x10) { ctx.rptMsg('PolAdtEv value missing/short.'); return; }

      // Per-category u16 values start after a version header; map 0/1/2/3 →
      // off / success / failure / both (kazamiya-documented PolAdtEv layout,
      // public fact; category names from the Windows audit-policy list).
      const SETTINGS = ['No auditing', 'Success', 'Failure', 'Success+Failure'];
      const CATEGORIES = [
        'Security State Change', 'Security System Extension', 'System Integrity',
        'IPsec Driver', 'Other System Events', 'Logon', 'Logoff', 'Account Lockout',
        'IPsec Main Mode', 'IPsec Quick Mode', 'IPsec Extended Mode', 'Special Logon',
        'Other Logon/Logoff Events', 'Network Policy Server', 'User/Device Claims',
        'Group Membership', 'File System', 'Registry', 'Kernel Object', 'SAM',
        'Certification Services', 'Application Generated', 'Handle Manipulation',
        'File Share', 'Filtering Platform Packet Drop', 'Filtering Platform Connection',
        'Other Object Access Events', 'Sensitive Privilege Use', 'Non Sensitive Privilege Use',
        'Other Privilege Use Events', 'Process Creation', 'Process Termination',
        'DPAPI Activity', 'RPC Events', 'Plug and Play Events', 'Token Right Adjusted',
        'Authentication Policy Change', 'Authorization Policy Change', 'MPSSVC Rule-Level Policy Change',
        'Filtering Platform Policy Change', 'Other Policy Change Events', 'User Account Management',
        'Computer Account Management', 'Security Group Management', 'Distribution Group Management',
        'Application Group Management', 'Other Account Management Events', 'Directory Service Access',
        'Directory Service Changes', 'Directory Service Replication', 'Detailed Directory Service Replication',
        'Credential Validation', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations',
        'Other Account Logon Events',
      ];

      const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
      const t = ctx.table(['Category', 'Setting']);
      const off = 0x0c;
      const n = Math.min(CATEGORIES.length, Math.floor((raw.length - off) / 2));
      const highValueOff = [];
      for (let i = 0; i < n; i++) {
        const v = dv.getUint16(off + i * 2, true);
        const label = SETTINGS[v] != null ? SETTINGS[v] : String(v);
        t.row([CATEGORIES[i], label]);
        if (v === 0 && /Process Creation|Logon$|Security Group Management|Credential Validation/.test(CATEGORIES[i])) {
          highValueOff.push(CATEGORIES[i]);
        }
      }
      if (highValueOff.length) {
        ctx.note('High-value categories with NO auditing: ' + highValueOff.join(', ') +
          ' — attackers frequently silence these before acting.');
      }
    },
  });

  R.register({
    name: 'lsasecrets',
    hives: ['security'],
    category: 'credential access',
    mitre: 'T1003',
    version: '20260901',
    shortDescr: 'Enumerate LSA Secrets; classify plaintext when decryptable via the bootkey',
    run(hive, ctx) {
      ctx.section('LSA Secrets');
      const secrets = H.subkey(hive, 'Policy\\Secrets');
      if (!secrets || secrets.getSubkeys().length === 0) {
        ctx.rptMsg('Policy\\Secrets not found or empty.');
        return;
      }

      const sysEntry = ctx.session && ctx.session.byType('system');
      const boot = sysEntry ? H.getBootKey(sysEntry.hive) : null;
      if (!sysEntry) {
        ctx.note('Encrypted sizes listed only. Attach the SYSTEM hive (+ Add hive…) and re-run to attempt decryption.');
      }

      const t = ctx.table(['Secret', 'Key LastWrite (UTC)', 'Size', 'Classification']);
      for (const s of secrets.getSubkeys()) {
        let size = '-';
        let classification = '(encrypted)';
        const curr = s.getSubkey('CurrVal');
        if (curr) {
          const raw = H.getValueData(curr, '');
          if (raw && raw.length != null) size = String(raw.length);
        }
        // Name-based classification (works without decryption).
        const n = s.name;
        if (/^_SC_/.test(n)) classification = 'Service account password (plaintext when decrypted)';
        else if (n === 'DefaultPassword') classification = 'Autologon password';
        else if (n === 'NL$KM') classification = 'Domain cache key (NL$KM) — DCC2 cracking out of scope';
        else if (/^DPAPI_SYSTEM|^G\$BCKEYI|^BCKEY/.test(n)) classification = 'DPAPI machine keys';
        else if (/^L\$/.test(n)) classification = 'Machine internal secret';
        else if (/^ASPNET_AGENTGOLD|^SAC/.test(n)) classification = 'Process/persistent secret';
        t.row([n, H.formatDate(s.lastWriteDate), size, classification]);
      }

      // Win10+ AES-128 key derivation constants from SHA1(bootkey)+fixed
      // index material could not be confirmed from a primary source —
      // decryption is intentionally NOT attempted rather than guessed
      // (docs/crypto-notes.md, UNVERIFIED entries).
      if (boot) {
        ctx.note('Bootkey derived, but the Win10+ LSA AES key-schedule constants are UNVERIFIED against a primary source — secrets are listed without decryption by design.');
      } else if (sysEntry) {
        ctx.note('SYSTEM attached but bootkey derivation failed (Lsa class names missing).');
      }
    },
  });
})(window.RV);
