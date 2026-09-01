// rv.plugins — SYSTEM-hive plugins. Ports of RegRipper's compname, timezone,
// shutdown, services, usbstor, ips, mountdev. All resolve the current control
// set first (helpers.getControlSet), mirroring the Perl ::getCCS idiom.
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  // Signed interpretation of a 32-bit DWORD (TimeZone Bias values).
  const toSigned32 = (n) => (n > 0x7fffffff ? n - 0x100000000 : n);

  R.register({
    name: 'compname',
    hives: ['system'],
    category: 'config',
    mitre: 'T1082',
    version: '20201021',
    shortDescr: 'Gets ComputerName, Hostname, and domain values from System hive',
    run(hive, ctx) {
      ctx.section('ComputerName');
      const { name: ccs } = H.getControlSet(hive);
      if (!ccs) { ctx.rptMsg('Select / ControlSet not found.'); return; }
      const cn = H.subkey(hive, ccs + '\\Control\\ComputerName\\ComputerName');
      if (cn) ctx.kv('ComputerName', H.getValueString(cn, 'ComputerName'));
      else ctx.rptMsg(ccs + '\\Control\\ComputerName\\ComputerName not found.');
      const acn = H.subkey(hive, ccs + '\\Control\\ComputerName\\ActiveComputerName');
      if (acn) ctx.kv('ActiveComputerName', H.getValueString(acn, 'ComputerName'));

      const tcp = H.subkey(hive, ccs + '\\Services\\Tcpip\\Parameters');
      if (tcp) {
        for (const n of ['Hostname', 'NV Hostname']) {
          const v = H.getValueString(tcp, n, ''); if (v) ctx.kv(n, v);
        }
        for (const n of ['Domain', 'ICSDomain', 'DhcpDomain', 'NV Domain']) {
          const v = H.getValueString(tcp, n, ''); if (v) ctx.kv(n, v);
        }
      }
    },
  });

  R.register({
    name: 'timezone',
    hives: ['system'],
    category: 'config',
    version: '20201005',
    shortDescr: 'Get TimeZoneInformation key contents',
    run(hive, ctx) {
      const { name: ccs } = H.getControlSet(hive);
      const path = (ccs || 'ControlSet001') + '\\Control\\TimeZoneInformation';
      const tz = H.subkey(hive, path);
      ctx.section('TimeZoneInformation');
      if (!tz) { ctx.rptMsg(path + ' could not be found.'); return; }
      ctx.rptMsg(path);
      ctx.rptMsg('LastWrite Time: ' + H.formatDate(tz.lastWriteDate));
      ctx.kv('DaylightName', H.getValueString(tz, 'DaylightName'));
      ctx.kv('StandardName', H.getValueString(tz, 'StandardName'));
      const bias = H.getValueDword(tz, 'Bias', null);
      if (bias != null) { const s = toSigned32(bias); ctx.kv('Bias', `${s} (${s / 60} hours)`); }
      const atb = H.getValueDword(tz, 'ActiveTimeBias', null);
      if (atb != null) { const s = toSigned32(atb); ctx.kv('ActiveTimeBias', `${s} (${s / 60} hours)`); }
      const tzk = H.getValueString(tz, 'TimeZoneKeyName', '');
      if (tzk) ctx.kv('TimeZoneKeyName', tzk);
    },
  });

  R.register({
    name: 'shutdown',
    hives: ['system'],
    category: 'config',
    version: '20201005',
    shortDescr: 'Gets ShutdownTime value from System hive',
    run(hive, ctx) {
      const { name: ccs } = H.getControlSet(hive);
      const path = (ccs || 'ControlSet001') + '\\Control\\Windows';
      const win = H.subkey(hive, path);
      ctx.section('ShutdownTime');
      if (!win) { ctx.rptMsg(path + ' not found.'); return; }
      ctx.rptMsg(path + ' key, ShutdownTime value');
      ctx.rptMsg('LastWrite time: ' + H.formatDate(win.lastWriteDate));
      const raw = H.getValueData(win, 'ShutdownTime', null);
      if (raw instanceof Uint8Array) ctx.kv('ShutdownTime', H.formatDate(H.filetimeFromBinary(raw)));
      else ctx.rptMsg('ShutdownTime value not found.');
    },
  });

  const SVC_TYPES = {
    0x001: 'Kernel driver', 0x002: 'File system driver', 0x010: 'Own_Process',
    0x020: 'Share_Process', 0x100: 'Interactive',
  };
  const SVC_STARTS = {
    0: 'Boot Start', 1: 'System Start', 2: 'Auto Start', 3: 'Manual', 4: 'Disabled',
  };

  R.register({
    name: 'services',
    hives: ['system'],
    category: 'persistence',
    mitre: 'T1547',
    version: '20200831',
    shortDescr: 'Lists services/drivers in Services key by LastWrite times',
    run(hive, ctx) {
      const { name: ccs } = H.getControlSet(hive);
      const path = (ccs || 'ControlSet001') + '\\Services';
      const svc = H.subkey(hive, path);
      ctx.section('Services');
      if (!svc) { ctx.rptMsg(path + ' not found.'); return; }
      ctx.rptMsg(path);
      const subs = svc.getSubkeys().slice().sort((a, b) => (b.lastWrite > a.lastWrite ? 1 : b.lastWrite < a.lastWrite ? -1 : 0));
      const t = ctx.table(['LastWrite', 'Name', 'DisplayName', 'ImagePath', 'Type', 'Start', 'ObjectName']);
      for (const s of subs) {
        const typeNum = H.getValueDword(s, 'Type', null);
        const type = typeNum == null ? '' : (SVC_TYPES[typeNum] || `0x${typeNum.toString(16)}`);
        const startNum = H.getValueDword(s, 'Start', null);
        const start = startNum == null ? '' : (SVC_STARTS[startNum] != null ? SVC_STARTS[startNum] : String(startNum));
        t.row([
          H.formatDate(s.lastWriteDate), s.name,
          H.getValueString(s, 'DisplayName', ''), H.getValueString(s, 'ImagePath', ''),
          type, start, H.getValueString(s, 'ObjectName', ''),
        ]);
      }
    },
  });

  // Device Properties timestamps: Properties\{83da6326-...}\00XX\(Default), each
  // an 8-byte FILETIME. 0064=First Install, 0065=First Inserted, 0066=Last
  // Inserted, 0067=Last Removal.
  const USB_PROP_GUID = 'Properties\\{83da6326-97a6-4088-9453-a1923f573b29}';
  const USB_PROP_TIMES = [['0064', 'First Install'], ['0065', 'First Inserted'], ['0066', 'Last Inserted'], ['0067', 'Last Removal']];

  R.register({
    name: 'usbstor',
    hives: ['system'],
    category: 'devices',
    version: '20220524',
    shortDescr: 'Parses Enum\\USBStor key',
    run(hive, ctx) {
      const { name: ccs } = H.getControlSet(hive);
      const path = (ccs || 'ControlSet001') + '\\Enum\\USBStor';
      const key = H.subkey(hive, path);
      ctx.section('USBStor');
      if (!key) { ctx.rptMsg(path + ' not found.'); return; }
      const devices = key.getSubkeys();
      if (devices.length === 0) { ctx.rptMsg(path + ' has no subkeys.'); return; }
      for (const dev of devices) {
        ctx.rptMsg(dev.name);
        for (const inst of dev.getSubkeys()) {
          ctx.rptMsg('  ' + inst.name);
          for (const v of ['DeviceDesc', 'Mfg', 'Service', 'FriendlyName']) {
            const val = H.getValueString(inst, v, ''); if (val) ctx.kv('    ' + v, val);
          }
          const props = H.subkey(hive, path + '\\' + dev.name + '\\' + inst.name + '\\' + USB_PROP_GUID);
          if (props) {
            for (const [sk, label] of USB_PROP_TIMES) {
              const p = props.getSubkey(sk);
              if (p) {
                const raw = H.getValueData(p, '', null);
                if (raw instanceof Uint8Array) ctx.kv('    ' + label, H.formatDate(H.filetimeFromBinary(raw)));
              }
            }
          }
        }
      }
    },
  });

  R.register({
    name: 'ips',
    hives: ['system'],
    category: 'config',
    version: '20200911',
    shortDescr: 'Get IP Addresses and domains (DHCP, static)',
    run(hive, ctx) {
      const { name: ccs } = H.getControlSet(hive);
      const path = (ccs || 'ControlSet001') + '\\Services\\Tcpip\\Parameters\\Interfaces';
      const key = H.subkey(hive, path);
      ctx.section('Network Interfaces');
      if (!key) { ctx.rptMsg(path + ' not found.'); return; }
      const t = ctx.table(['Interface', 'DhcpIPAddress', 'IPAddress', 'Domain']);
      const emit = (iface) => {
        const dhcp = H.getValueString(iface, 'DhcpIPAddress', '');
        let ip = H.getValueData(iface, 'IPAddress', '');
        if (Array.isArray(ip)) ip = ip.filter(Boolean).join(', ');
        const dom = H.getValueString(iface, 'Domain', '') || H.getValueString(iface, 'DhcpDomain', '');
        if (dhcp || ip || dom) t.row([iface.name, dhcp, ip, dom]);
      };
      for (const s1 of key.getSubkeys()) {
        emit(s1);
        for (const s2 of s1.getSubkeys()) emit(s2);
      }
    },
  });

  // MountedDevices value decoders (mirror mountdev.pl).
  const hexByte = (b) => b.toString(16).padStart(2, '0');
  function driveSignature(bytes) {
    // Perl _translateBinary: reverse the 4 bytes, space-join hex.
    const out = [];
    for (let i = 3; i >= 0; i--) out.push(hexByte(bytes[i]));
    return out.join(' ');
  }
  function parseGUID(b) {
    const u32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
    const u16 = (o) => b[o] | (b[o + 1] << 8);
    const hx = (o, n) => { let s = ''; for (let i = 0; i < n; i++) s += hexByte(b[o + i]); return s; };
    return `{${u32(0).toString(16).padStart(8, '0')}-${u16(4).toString(16).padStart(4, '0')}-` +
      `${u16(6).toString(16).padStart(4, '0')}-${hx(8, 2)}-${hx(10, 6)}}`;
  }

  R.register({
    name: 'mountdev',
    hives: ['system'],
    category: 'devices',
    version: '20221129',
    shortDescr: 'Return contents of HKLM\\System\\MountedDevices key',
    run(hive, ctx) {
      const key = H.subkey(hive, 'MountedDevices');
      if (!key) { ctx.section('MountedDevices'); ctx.rptMsg('MountedDevices not found.'); return; }
      const drives = []; const volumes = []; const devices = [];
      for (const v of key.getValues()) {
        const raw = v.getRawData();
        const len = raw ? raw.length : 0;
        if (len === 12) drives.push([v.name, 'Drive Signature: ' + driveSignature(raw)]);
        else if (len === 24) volumes.push([v.name, 'Volume GUID: ' + parseGUID(raw.subarray(8, 24))]);
        else if (len > 0x50) devices.push([v.name, RV.reg.decodeUtf16LE(raw).replace(/\u0000/g, "")]);
      }
      ctx.section('Drives');
      if (drives.length) { const t = ctx.table(['Value', 'Signature']); drives.forEach((r) => t.row(r)); }
      else ctx.rptMsg('(none)');
      ctx.section('Devices');
      if (devices.length) { const t = ctx.table(['Value', 'Device']); devices.forEach((r) => t.row(r)); }
      else ctx.rptMsg('(none)');
      ctx.section('Volumes');
      if (volumes.length) { const t = ctx.table(['Value', 'GUID']); volumes.forEach((r) => t.row(r)); }
      else ctx.rptMsg('(none)');
    },
  });

  // ---------------------------------------------------------------------------
  // New bespoke plugins (not from the RR corpus — see docs/regripper-plugins.md):
  // bootkey, shimcache, bam, wpdbusenum, svcacls.

  R.register({
    name: 'bootkey',
    hives: ['system'],
    category: 'credential access',
    mitre: 'T1003.002',
    version: '20260901',
    shortDescr: 'Derive the SysKey bootkey from Lsa class names (needed to decrypt SAM/SECURITY)',
    run(hive, ctx) {
      ctx.section('SysKey Bootkey');
      const got = H.getBootKey(hive);
      if (!got) {
        ctx.rptMsg('Control\\Lsa\\{JD,Skew1,GBG,Data} class names not found or incomplete.');
        ctx.note('Without the bootkey, SAM hashes and LSA secrets cannot be decrypted.');
        return;
      }
      for (const nm of ['JD', 'Skew1', 'GBG', 'Data']) {
        ctx.kv(nm, got.parts[nm] || '(missing)');
      }
      const C = RV.crypto;
      ctx.kv('Bootkey (hex)', C.bytesToHex(got.bootKey));
      ctx.note('Attach the SAM or SECURITY hive (+ Add hive…) and re-run its hash/secrets plugin to decrypt.');
    },
  });

  R.register({
    name: 'shimcache',
    hives: ['system'],
    category: 'program execution',
    version: '20260901',
    shortDescr: 'Parse AppCompatCache (ShimCache) file-execution traces',
    run(hive, ctx) {
      ctx.section('AppCompatCache');
      const { name: ccs } = H.getControlSet(hive);
      const base = (ccs || 'ControlSet001') + '\\Control\\Session Manager\\AppCompatCache';
      const key = H.subkey(hive, base);
      if (!key) { ctx.rptMsg(base + ' not found.'); return; }
      const raw = H.getValueData(key, 'AppCompatCache');
      if (!raw || raw.length < 16) { ctx.rptMsg('AppCompatCache value missing or empty.'); return; }
      const parsed = RV.decoders.parseShimcache(raw);
      if (parsed.os === 'unknown') {
        ctx.rptMsg('Unrecognised cache format (first 8 bytes: ' +
          RV.crypto.bytesToHex(raw.subarray(0, 8)) + ').');
        return;
      }
      ctx.kv('Detected format', parsed.label);
      ctx.rptMsg('Source: ' + base);
      const t = ctx.table(['#', 'Path', 'Last Modified (UTC)', 'Size', 'Executed?']);
      parsed.entries.slice(0, H.MAX_PLUGIN_ROWS).forEach((e, i) => {
        const ft = e.lastModified ? RV.reg.filetime.filetimeToDate(e.lastModified) : null;
        t.row([String(i + 1), e.path, ft ? H.formatDate(ft) : '-',
          e.size != null ? String(e.size) : '-',
          e.execFlag === undefined ? '-' : (e.execFlag ? 'yes' : 'no')]);
      });
      if (parsed.entries.length > H.MAX_PLUGIN_ROWS) {
        ctx.note(`Truncated to ${H.MAX_PLUGIN_ROWS} of ${parsed.entries.length} entries.`);
      }
      if (parsed.os === 'win10') {
        ctx.note('Windows 10 caches record insertion order only — timestamps are file last-modified times, not execution times.');
      }
    },
  });

  R.register({
    name: 'bam',
    hives: ['system'],
    category: 'program execution',
    mitre: 'T1059',
    version: '20260901',
    shortDescr: 'Background Activity Moderator per-SID program execution times (Win10+)',
    run(hive, ctx) {
      ctx.section('BAM / DAM');
      const { name: ccs } = H.getControlSet(hive);
      const base = ccs || 'ControlSet001';
      let found = false;
      for (const svc of ['bam', 'dam']) {
        const su = H.subkey(hive, base + '\\Services\\' + svc + '\\State\\UserSettings');
        if (!su) continue;
        found = true;
        ctx.section(svc.toUpperCase() + ' — ' + svc + '\\State\\UserSettings');
        for (const sidKey of su.getSubkeys()) {
          ctx.rptMsg('SID: ' + sidKey.name);
          const t = ctx.table(['Program', 'Last Execution (UTC)']);
          let rows = 0;
          for (const v of sidKey.getValues()) {
            if (v.name === 'SequenceNumber' || v.name === 'Version') {
              ctx.kv(v.name, String(v.getData().value));
              continue;
            }
            const raw = v.getRawData();
            if (!raw || raw.length < 8) continue;
            const d = H.filetimeFromBinary(raw, 0);
            t.row([v.name, d ? H.formatDate(d) : '(invalid)']);
            rows++;
            if (rows >= H.MAX_PLUGIN_ROWS) { ctx.note('(truncated)'); break; }
          }
          if (rows === 0) ctx.rptMsg('(no program entries)');
        }
      }
      if (!found) ctx.rptMsg('Services\\bam\\State\\UserSettings / dam equivalent not found (pre-Win10 or key absent).');
    },
  });

  R.register({
    name: 'wpdbusenum',
    hives: ['system'],
    category: 'devices',
    version: '20260901',
    shortDescr: 'MTP/PTP portable devices (phones, tablets) from WPDBUSENUM enumeration',
    run(hive, ctx) {
      ctx.section('WPDBUSENUM (portable devices)');
      const { name: ccs } = H.getControlSet(hive);
      const base = (ccs || 'ControlSet001') + '\\Enum\\SWD\\WPDBUSENUM';
      const key = H.subkey(hive, base);
      if (!key) { ctx.rptMsg(base + ' not found.'); return; }
      const t = ctx.table(['Device GUID', 'Instance', 'LastWrite (UTC)']);
      let rows = 0;
      for (const dev of key.getSubkeys()) {
        for (const inst of dev.getSubkeys()) {
          t.row([dev.name, inst.name, H.formatDate(inst.lastWriteDate)]);
          rows++;
          if (rows >= H.MAX_PLUGIN_ROWS) { ctx.note('(truncated)'); return; }
        }
        if (dev.getSubkeys().length === 0) t.row([dev.name, '(no instances)', H.formatDate(dev.lastWriteDate)]);
      }
      if (rows === 0) ctx.rptMsg('(no enumerated devices)');
      ctx.note('Modern phones/tablets connect via MTP and do NOT appear in USBSTOR — check also SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices (portabledevices plugin).');
    },
  });

  R.register({
    name: 'svcacls',
    hives: ['system'],
    category: 'persistence',
    mitre: 'T1574.011',
    version: '20260901',
    shortDescr: 'Audit service-key DACLs for non-admin write access (offline accesschk)',
    run(hive, ctx) {
      ctx.section('Service registry-key ACLs');
      const { name: ccs } = H.getControlSet(hive);
      const base = (ccs || 'ControlSet001') + '\\Services';
      const services = H.subkey(hive, base);
      if (!services) { ctx.rptMsg(base + ' not found.'); return; }
      const D = RV.decoders;
      const nonAdminTrustees = new Set(['S-1-1-0', 'S-1-5-4', 'S-1-5-11', 'S-1-5-32-545']);
      const findings = [];
      let checked = 0;
      let noDescriptor = 0;
      for (const svc of services.getSubkeys()) {
        let desc = null;
        try { desc = svc.getSecurityDescriptor(); } catch { desc = null; }
        if (!desc) { noDescriptor++; continue; }
        checked++;
        for (const ace of (desc.dacl ? desc.dacl.aces : [])) {
          if (D.aceGrantsWrite(ace) && nonAdminTrustees.has(ace.sid)) {
            findings.push([svc.name, D.sidLabel(ace.sid), '0x' + ace.accessMask.toString(16), ace.type]);
          }
        }
      }
      ctx.rptMsg(`Checked ${checked} service keys with descriptors (${noDescriptor} expose no sk descriptor — common in truncated hives).`);
      if (findings.length === 0) {
        ctx.rptMsg('No service key grants write access to non-admin trustees.');
        return;
      }
      ctx.section('Weak ACLs (writable by non-admins → T1574.011 ImagePath hijack)');
      const t = ctx.table(['Service', 'Trustee', 'Access mask', 'ACE type']);
      findings.forEach((f) => t.row(f));
      ctx.note('A service whose registry key is writable by Authenticated Users/Users/Interactive can have its ImagePath redirected to a hostile binary (accesschk-equivalent finding).');
    },
  });
})(window.RV);
