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
})(window.RV);
