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
})(window.RV);
