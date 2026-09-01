// rv.plugins — SOFTWARE-hive plugins (plus run/uninstall which also apply to
// NTUSER.DAT). Ports of RegRipper's winver, uninstall, run, profilelist,
// networkcards.
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  R.register({
    name: 'winver',
    hives: ['software'],
    category: 'config',
    version: '20200916',
    shortDescr: 'Get Windows version & build info',
    run(hive, ctx) {
      const key = H.subkey(hive, 'Microsoft\\Windows NT\\CurrentVersion');
      ctx.section('Windows Version');
      if (!key) { ctx.rptMsg('Microsoft\\Windows NT\\CurrentVersion not found.'); return; }
      const fields = ['ProductName', 'ReleaseID', 'DisplayVersion', 'CurrentVersion', 'CurrentBuild',
        'CurrentBuildNumber', 'CSDVersion', 'BuildLab', 'BuildLabEx', 'CompositionEditionID',
        'RegisteredOrganization', 'RegisteredOwner'];
      for (const f of fields) {
        const v = H.getValueString(key, f, ''); if (v) ctx.kv(f, v);
      }
      // InstallDate is a DWORD of unix-epoch seconds; InstallTime an 8-byte FILETIME.
      const install = H.getValueDword(key, 'InstallDate', null);
      if (install != null) ctx.kv('InstallDate', H.formatDate(H.unixToDate(install)));
      const it = H.getValueData(key, 'InstallTime', null);
      if (it instanceof Uint8Array) ctx.kv('InstallTime', H.formatDate(H.filetimeFromBinary(it)));
    },
  });

  const UNINSTALL_PATHS = [
    'Microsoft\\Windows\\CurrentVersion\\Uninstall',
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',            // NTUSER.DAT
    'Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall', // NTUSER.DAT
  ];

  R.register({
    name: 'uninstall',
    hives: ['software', 'ntuser'],
    category: 'config',
    version: '20200916',
    shortDescr: 'Gets contents of Uninstall keys from Software, NTUSER.DAT hives',
    run(hive, ctx) {
      let found = false;
      for (const path of UNINSTALL_PATHS) {
        const key = H.subkey(hive, path);
        if (!key) continue;
        found = true;
        ctx.section(path);
        const subs = key.getSubkeys().slice().sort((a, b) => (b.lastWrite > a.lastWrite ? 1 : b.lastWrite < a.lastWrite ? -1 : 0));
        const t = ctx.table(['LastWrite', 'DisplayName', 'Version', 'Publisher']);
        for (const s of subs) {
          let display = H.getValueString(s, 'DisplayName', '');
          if (display === '') display = s.name;
          t.row([H.formatDate(s.lastWriteDate), display,
            H.getValueString(s, 'DisplayVersion', ''), H.getValueString(s, 'Publisher', '')]);
        }
      }
      if (!found) { ctx.section('Uninstall'); ctx.rptMsg('No Uninstall keys found.'); }
    },
  });

  // Autostart "Run" locations across both Software and NTUSER.DAT layouts. We
  // simply probe every path and report the ones that exist (the paths are
  // distinct per hive, so no hive-type branching is needed).
  const RUN_PATHS = [
    // Software hive
    'Microsoft\\Windows\\CurrentVersion\\Run',
    'Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'Microsoft\\Windows\\CurrentVersion\\RunServices',
    'Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
    // NTUSER.DAT
    'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
    'Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
  ];

  R.register({
    name: 'run',
    hives: ['software', 'ntuser'],
    category: 'persistence',
    mitre: 'T1547.001',
    version: '20220706',
    shortDescr: 'Get autostart key contents from Software/user hives',
    run(hive, ctx) {
      let found = false;
      for (const path of RUN_PATHS) {
        const key = H.subkey(hive, path);
        if (!key) continue;
        const vals = key.getValues();
        if (vals.length === 0) continue;
        found = true;
        ctx.section(path);
        ctx.rptMsg('LastWrite: ' + H.formatDate(key.lastWriteDate));
        const t = ctx.table(['Name', 'Data']);
        for (const v of vals) t.row([v.displayName, v.getDisplay().text]);
      }
      if (!found) { ctx.section('Run'); ctx.rptMsg('No autostart Run keys with values found.'); }
    },
  });

  R.register({
    name: 'profilelist',
    hives: ['software'],
    category: 'config',
    version: '20200922',
    shortDescr: 'Get content of ProfileList key',
    run(hive, ctx) {
      const key = H.subkey(hive, 'Microsoft\\Windows NT\\CurrentVersion\\ProfileList');
      ctx.section('ProfileList');
      if (!key) { ctx.rptMsg('ProfileList not found.'); return; }
      const t = ctx.table(['SID', 'ProfileImagePath', 'LastWrite']);
      for (const s of key.getSubkeys()) {
        t.row([s.name, H.getValueString(s, 'ProfileImagePath', ''), H.formatDate(s.lastWriteDate)]);
      }
    },
  });

  R.register({
    name: 'networkcards',
    hives: ['software'],
    category: 'config',
    version: '20200921',
    shortDescr: 'Get NetworkCards info',
    run(hive, ctx) {
      const key = H.subkey(hive, 'Microsoft\\Windows NT\\CurrentVersion\\NetworkCards');
      ctx.section('NetworkCards');
      if (!key) { ctx.rptMsg('NetworkCards not found.'); return; }
      const t = ctx.table(['Description', 'ServiceName', 'LastWrite']);
      for (const s of key.getSubkeys()) {
        const desc = H.getValueString(s, 'Description', '');
        if (desc) t.row([desc, H.getValueString(s, 'ServiceName', ''), H.formatDate(s.lastWriteDate)]);
      }
    },
  });

  // ---------------------------------------------------------------------------
  // New bespoke plugins (not from the RR corpus — see docs/regripper-plugins.md):
  // taskcache, networklist, emdmgmt, portabledevices.

  R.register({
    name: 'taskcache',
    hives: ['software'],
    category: 'persistence',
    mitre: 'T1053.005',
    version: '20260901',
    shortDescr: 'Scheduled tasks from TaskCache: actions, authors, run times; flags hidden (SD-less) tasks',
    run(hive, ctx) {
      ctx.section('Scheduled Tasks (TaskCache)');
      const base = 'Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache';
      const root = H.subkey(hive, base);
      if (!root) { ctx.rptMsg(base + ' not found.'); return; }
      const tree = root.getSubkey('Tree');
      const tasks = root.getSubkey('Tasks');
      const byId = new Map();
      if (tasks) {
        for (const t of tasks.getSubkeys()) byId.set(t.name.toLowerCase(), t);
      }

      const collect = (key, prefix) => {
        const out = [];
        for (const k of key.getSubkeys()) {
          const path = prefix ? prefix + '\\' + k.name : k.name;
          const hasValues = k.getValues().length > 0 || k.getValue('Id');
          if (hasValues) out.push([path, k]);
          out.push(...collect(k, path));
        }
        return out;
      };

      const rows = tree ? collect(tree, '') : [];
      if (rows.length === 0) { ctx.rptMsg('TaskCache\\Tree has no task entries.'); }

      const hidden = [];
      const orphans = [];
      const t = ctx.table(['Task', 'Id', 'Author', 'Action', 'Last Run (UTC)', 'Flags']);
      for (const [path, k] of rows.slice(0, H.MAX_PLUGIN_ROWS)) {
        const id = H.getValueString(k, 'Id', '');
        const author = H.getValueString(k, 'Author', '');
        const actionXml = H.getValueString(k, 'Action', '');
        let action = actionXml ? actionXml.split('\n')[0].slice(0, 120) : '';
        let lastRun = '-';
        let flags = [];
        // Correlate with Tasks\<guid> for DynamicInfo + Actions.
        const def = id ? byId.get(id.toLowerCase()) : null;
        if (def) {
          const dynRaw = H.getValueData(def, 'DynamicInfo');
          if (dynRaw && (dynRaw.length === 0x1c || dynRaw.length === 0x24)) {
            const d = H.filetimeFromBinary(dynRaw, 4);
            if (d) lastRun = H.formatDate(d);
          }
          const actRaw = H.getValueData(def, 'Actions');
          if (actRaw && actRaw.length > 6) {
            try {
              // u16 magic 0x03, u32 len + UTF-16 user, tag 0x6666/0x7777 follows.
              let p = 2;
              const userLen = actRaw[p] | (actRaw[p + 1] << 8); p += 2;
              let user = '';
              for (let i = 0; i < userLen; i += 2) user += String.fromCharCode(actRaw[p + i] | (actRaw[p + i + 1] << 8));
              p += userLen;
              if (p + 2 <= actRaw.length) {
                const tag = actRaw[p] | (actRaw[p + 1] << 8);
                if (tag === 0x6666 && p + 6 <= actRaw.length) {
                  const plen = actRaw[p + 2] | (actRaw[p + 3] << 8);
                  let prog = '';
                  for (let i = 0; i < plen; i += 2) prog += String.fromCharCode(actRaw[p + 4 + i] | (actRaw[p + 4 + i + 1] << 8));
                  if (prog) action = `${prog}${user ? ' (as ' + user + ')' : ''}`;
                } else if (tag === 0x7777) {
                  action = action || 'COM handler (see Actions blob)';
                }
              }
            } catch { /* malformed Actions */ }
          }
        } else if (id) {
          orphans.push(path);
        }
        if (!k.getValue('SD')) hidden.push(path);
        t.row([path, id || '-', author || '-', action || '-', lastRun, flags.join(', ') || '-']);
      }
      if (hidden.length) {
        ctx.section('Hidden tasks (no SD value — Tarrask-style)');
        const ht = ctx.table(['Task']);
        hidden.forEach((h) => ht.row([h]));
        ctx.note('TaskCache\\Tree entries without an SD security value are hidden from `schtasks /query` — classic Tarrask-style defence evasion.');
      }
      if (orphans.length) {
        ctx.section('Orphan Tree entries');
        const ot = ctx.table(['Task']);
        orphans.forEach((o) => ot.row([o]));
      }
    },
  });

  R.register({
    name: 'networklist',
    hives: ['software'],
    category: 'config',
    mitre: 'T1016',
    version: '20260901',
    shortDescr: 'Network profiles: names, category, first/last connection times, gateway MACs',
    run(hive, ctx) {
      ctx.section('Network Profiles');
      const base = 'Microsoft\\Windows NT\\CurrentVersion\\NetworkList';
      const root = H.subkey(hive, base);
      if (!root) { ctx.rptMsg(base + ' not found.'); return; }

      const CATEGORIES = { 0: 'Public', 1: 'Private', 2: 'Domain' };
      const NAMETYPES = { 0x06: 'Wired', 0x17: 'Broadband', 0x47: 'Wireless' };

      const sigs = new Map(); // profile guid -> {gwMac, dnsSuffix, source}
      for (const src of ['Managed', 'Unmanaged']) {
        const sk = root.getSubkey('Signatures') && root.getSubkey('Signatures').getSubkey(src);
        if (!sk) continue;
        for (const s of sk.getSubkeys()) {
          const guid = H.getValueString(s, 'ProfileGuid', '') || s.name;
          const mac = H.getValueData(s, 'DefaultGateWayMac');
          let macStr = '';
          if (mac && mac.length >= 6) {
            macStr = Array.from(mac.subarray(0, 6)).map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
          }
          sigs.set(guid.toLowerCase(), {
            gwMac: macStr,
            dnsSuffix: H.getValueString(s, 'DnsSuffix', ''),
            first: H.getValueData(s, 'FirstNetwork'),
            source: src,
          });
        }
      }

      const profiles = root.getSubkey('Profiles');
      if (!profiles) { ctx.rptMsg('Profiles key not found (signatures only, below).'); }
      const t = ctx.table(['Profile GUID', 'Name', 'Category', 'Type', 'Date Created', 'Last Connected', 'Gateway MAC', 'DNS suffix', 'Signature']);
      if (profiles) {
        for (const p of profiles.getSubkeys()) {
          const dcRaw = H.getValueData(p, 'DateCreated');
          const lcRaw = H.getValueData(p, 'DateLastConnected');
          const ft = (raw) => {
            if (!raw) return null;
            if (raw.length === 12) return H.filetimeFromBinary(raw, 4); // Win10 quirk: FT in last 8 of 12
            return H.filetimeFromBinary(raw, 0);
          };
          const cat = H.getValueDword(p, 'Category', null);
          const ntype = H.getValueDword(p, 'NameType', null);
          const sig = sigs.get(p.name.toLowerCase()) || {};
          t.row([
            p.name,
            H.getValueString(p, 'ProfileName', '(unnamed)'),
            cat != null ? (CATEGORIES[cat] || String(cat)) : '-',
            ntype != null ? (NAMETYPES[ntype] || '0x' + ntype.toString(16)) : '-',
            ft(dcRaw) ? H.formatDate(ft(dcRaw)) : '-',
            ft(lcRaw) ? H.formatDate(ft(lcRaw)) : '-',
            sig.gwMac || '-',
            sig.dnsSuffix || '-',
            sig.source || '-',
          ]);
        }
      }
      if (sigs.size > 0 && (!profiles || profiles.getSubkeys().length === 0)) {
        const st = ctx.table(['Profile GUID', 'First Network', 'Gateway MAC', 'DNS suffix', 'Source']);
        for (const [guid, s] of sigs) st.row([guid, s.first || '-', s.gwMac || '-', s.dnsSuffix || '-', s.source]);
      }
    },
  });

  R.register({
    name: 'emdmgmt',
    hives: ['software'],
    category: 'devices',
    version: '20260901',
    shortDescr: 'EMDMgmt volume serial numbers — correlates USB/removable media across machines',
    run(hive, ctx) {
      ctx.section('EMDMgmt (volume serials)');
      const base = 'Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt';
      const key = H.subkey(hive, base);
      if (!key) { ctx.rptMsg(base + ' not found.'); return; }
      const t = ctx.table(['Volume key name', 'Label', 'VSN', 'Last Tested (UTC)']);
      let rows = 0;
      for (const k of key.getSubkeys()) {
        // Key names embed the volume serial as the last '_'-separated hex token
        // (8 hex chars → XXXX-XXXX), the label second-to-last.
        const parts = k.name.split('_');
        let vsn = '-';
        let label = '-';
        if (parts.length >= 2) {
          const last = parts[parts.length - 1];
          if (/^[0-9a-f]{8}$/i.test(last)) {
            const h = last.toUpperCase();
            vsn = `${h.slice(0, 4)}-${h.slice(4)}`;
            label = parts[parts.length - 2] || 'Unknown Volume';
          }
        }
        const lt = H.getValueData(k, 'LastTestedTime');
        const d = lt && lt.length >= 8 ? H.filetimeFromBinary(lt, 0) : null;
        t.row([k.name, label, vsn, d ? H.formatDate(d) : '-']);
        rows++;
        if (rows >= H.MAX_PLUGIN_ROWS) { ctx.note('(truncated)'); break; }
      }
      if (rows === 0) ctx.rptMsg('(no volume entries)');
    },
  });

  R.register({
    name: 'portabledevices',
    hives: ['software'],
    category: 'devices',
    version: '20260901',
    shortDescr: 'MTP/PTP portable devices (phones, tablets) — FriendlyName, model, firmware',
    run(hive, ctx) {
      ctx.section('Portable Devices');
      const base = 'Microsoft\\Windows Portable Devices\\Devices';
      const key = H.subkey(hive, base);
      if (!key) { ctx.rptMsg(base + ' not found.'); return; }
      const t = ctx.table(['FriendlyName', 'Manufacturer', 'Model', 'Firmware', 'LastWrite (UTC)']);
      let rows = 0;
      for (const d of key.getSubkeys()) {
        const name = H.getValueString(d, 'FriendlyName', '') || d.name;
        t.row([
          name,
          H.getValueString(d, 'Manufacturer', '-') || '-',
          H.getValueString(d, 'ModelName', '-') || '-',
          H.getValueString(d, 'FirmwareVersion', '-') || '-',
          H.formatDate(d.lastWriteDate),
        ]);
        rows++;
        if (rows >= H.MAX_PLUGIN_ROWS) { ctx.note('(truncated)'); break; }
      }
      if (rows === 0) ctx.rptMsg('(no devices)');
      ctx.note('Correlate with SYSTEM\\...\\Enum\\SWD\\WPDBUSENUM (wpdbusenum plugin) for device GUIDs and times.');
    },
  });
})(window.RV);
