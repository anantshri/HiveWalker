// rv.plugins — user-hive execution & initial-access evidence:
//   appcompatlayers — per-exe compatibility shims incl. RUNASADMIN (elevation)
//   officetrust     — Office Trusted Documents: files where macros were enabled
//   officemru       — Office File/Place MRU: recently opened documents + times
//   comhijack       — user-hive COM servers (InprocServer32/TreatAs) hijacks
//   pcaexec         — Program Compatibility Assistant execution evidence
// Pure-registry (NTUSER / UsrClass / SOFTWARE). Key layouts are public format
// facts. Proposed in issue #6.
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;
  const { filetime } = RV.reg;

  const WRITABLE_RE = /\\users\\|\\appdata\\|\\temp\\|\\tmp\\|\\programdata\\|\\public\\|\\downloads\\|%appdata%|%temp%|%userprofile%/i;
  const PRIV_LAYER_RE = /\bRUNAS(ADMIN|HIGHEST|INVOKER)\b/i;

  // ---------------------------------------------------------------------------
  // appcompatlayers — AppCompatFlags\Layers. Value name = exe path, data = a
  // space-separated token list (e.g. "~ RUNASADMIN HIGHDPIAWARE WIN7RTM").
  // RUNASADMIN forces elevation on launch — persistence/UAC-relevant.

  const LAYER_BASES = [
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers', // NTUSER
    'Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers',           // SOFTWARE
  ];

  R.register({
    name: 'appcompatlayers',
    hives: ['ntuser', 'software'],
    category: 'privilege escalation (audit)',
    mitre: 'T1546.011',
    version: '20260902',
    shortDescr: 'Application compatibility layers per executable; flags RUNASADMIN elevation and writable paths',
    run(hive, ctx) {
      ctx.section('AppCompat Layers');
      const t = ctx.table(['Executable', 'Layers', 'Flags']);
      let count = 0;
      let elevated = 0;
      for (const base of LAYER_BASES) {
        const key = H.subkey(hive, base);
        if (!key) continue;
        for (const v of key.getValues()) {
          if (t.count() >= H.MAX_PLUGIN_ROWS) break;
          const layers = String(v.getData().value || '').trim();
          const flags = [];
          if (PRIV_LAYER_RE.test(layers)) { flags.push('ELEVATION'); elevated++; }
          if (WRITABLE_RE.test(v.name)) flags.push('writable-path');
          t.row([v.name, layers, flags.join(', ')]);
          count++;
        }
      }
      if (count === 0) { ctx.rptMsg('No AppCompatFlags\\Layers entries found in this hive.'); return; }
      ctx.note(`${count} shimmed executable(s); ${elevated} request elevation (RUNASADMIN/RUNASHIGHEST). A RUNASADMIN layer on a user-writable binary is an auto-elevate persistence/UAC vector (T1546.011 / T1548.002).`);
    },
  });

  // ---------------------------------------------------------------------------
  // officetrust — Trusted Documents\TrustRecords. Value name = document path,
  // data = FILETIME (bytes 0-7) + a trailing DWORD flag; 0x7FFFFFFF means the
  // user clicked "Enable Content" (macros/active content) — prime phishing
  // execution evidence (T1204.002).

  function decodeTrust(raw) {
    if (!raw || raw.length < 4) return null;
    const when = raw.length >= 8 ? H.filetimeFromBinary(raw, 0) : null;
    const o = raw.length - 4;
    const flag = (raw[o] | (raw[o + 1] << 8) | (raw[o + 2] << 16) | (raw[o + 3] << 24)) >>> 0;
    return { when, macros: flag === 0x7fffffff };
  }

  function decodeDocPath(name) {
    try { return decodeURIComponent(name); } catch { return name; }
  }

  /** Iterate Office <version>\<app> subkeys, calling fn(app, appPath). */
  function eachOfficeApp(hive, fn) {
    const office = H.subkey(hive, 'Software\\Microsoft\\Office');
    if (!office) return;
    for (const ver of office.getSubkeys()) {
      if (!/^\d+\.\d+$/.test(ver.name)) continue;
      for (const app of ver.getSubkeys()) {
        fn(app.name, 'Software\\Microsoft\\Office\\' + ver.name + '\\' + app.name);
      }
    }
  }

  R.register({
    name: 'officetrust',
    hives: ['ntuser'],
    category: 'initial access',
    mitre: 'T1204.002',
    version: '20260902',
    shortDescr: 'Office Trusted Documents — files where the user enabled macros/active content',
    run(hive, ctx) {
      ctx.section('Office Trusted Documents');
      const t = ctx.table(['Enabled (UTC)', 'Content', 'Document']);
      let macroCount = 0;
      let total = 0;
      eachOfficeApp(hive, (appName, appPath) => {
        const tr = H.subkey(hive, appPath + '\\Security\\Trusted Documents\\TrustRecords');
        if (!tr) return;
        for (const v of tr.getValues()) {
          if (t.count() >= H.MAX_PLUGIN_ROWS) break;
          const d = decodeTrust(v.getRawData());
          if (!d) continue;
          if (d.macros) macroCount++;
          t.row([d.when ? H.formatDate(d.when) : '-', d.macros ? 'MACROS/CONTENT ENABLED' : 'editing only', appName + ': ' + decodeDocPath(v.name)]);
          total++;
        }
      });
      if (total === 0) { ctx.rptMsg('No Office Trusted Documents found (no macro-enable history in this hive).'); return; }
      ctx.note(`${total} trusted document(s); ${macroCount} had macros/active content enabled by the user — direct evidence of user execution of a document payload (T1204.002).`);
    },
  });

  // ---------------------------------------------------------------------------
  // officemru — File MRU / Place MRU. Value data looks like
  // "[F00000000][T01D7A…][O00000000]*C:\path\doc.docx"; the [T…] token is an
  // 8-byte FILETIME in hex, the path follows the '*'.

  function parseMru(str) {
    const s = String(str);
    let ft = null;
    const m = /\[T([0-9A-Fa-f]{16})\]/.exec(s);
    if (m) { try { ft = filetime.filetimeToDate(BigInt('0x' + m[1])); } catch { ft = null; } }
    const star = s.indexOf('*');
    return { date: ft, path: star >= 0 ? s.slice(star + 1) : s };
  }

  R.register({
    name: 'officemru',
    hives: ['ntuser'],
    category: 'program execution',
    mitre: 'T1204',
    version: '20260902',
    shortDescr: 'Office File/Place MRU — recently opened documents with last-opened times',
    run(hive, ctx) {
      ctx.section('Office MRU');
      const rows = [];
      eachOfficeApp(hive, (appName, appPath) => {
        for (const leaf of ['File MRU', 'Place MRU']) {
          const mru = H.subkey(hive, appPath + '\\' + leaf);
          if (!mru) continue;
          for (const v of mru.getValues()) {
            if (v.name === 'Max Display') continue;
            const p = parseMru(v.getData().value);
            rows.push({ date: p.date, app: appName, kind: leaf.replace(' MRU', ''), path: p.path });
          }
        }
      });
      if (rows.length === 0) { ctx.rptMsg('No Office MRU entries found in this hive.'); return; }
      rows.sort((a, b) => (a.date && b.date ? b.date - a.date : a.date ? -1 : 1));
      const t = ctx.table(['Last Opened (UTC)', 'App', 'Type', 'Document']);
      for (const r of rows.slice(0, H.MAX_PLUGIN_ROWS)) {
        t.row([r.date ? H.formatDate(r.date) : '-', r.app, r.kind, r.path]);
      }
      if (rows.length > H.MAX_PLUGIN_ROWS) ctx.note(`Truncated to ${H.MAX_PLUGIN_ROWS} of ${rows.length} entries.`);
      ctx.note('MRU entries show documents opened by this user — useful for data-access timelines and phishing-lure correlation.');
    },
  });

  // ---------------------------------------------------------------------------
  // comhijack — COM servers defined in a *user* hive. HKCU\Software\Classes
  // (and UsrClass.dat) override HKLM, so a CLSID server pointing at a writable
  // path is a per-user COM hijack persistence primitive (T1546.015).

  const CLSID_BASES = [
    'Software\\Classes\\CLSID',           // NTUSER
    'Software\\Classes\\Wow6432Node\\CLSID',
    'CLSID',                              // UsrClass.dat root
    'Wow6432Node\\CLSID',
  ];
  const SERVER_KINDS = ['InprocServer32', 'InprocServer', 'LocalServer32'];

  R.register({
    name: 'comhijack',
    hives: ['ntuser', 'usrclass'],
    category: 'persistence',
    mitre: 'T1546.015',
    version: '20260902',
    shortDescr: 'User-hive COM servers (InprocServer32/LocalServer32/TreatAs); flags writable-path hijacks',
    run(hive, ctx) {
      ctx.section('User COM Servers');
      const t = ctx.table(['CLSID', 'Type', 'Server', 'Threading', 'Note']);
      let total = 0;
      let flagged = 0;
      for (const base of CLSID_BASES) {
        const root = H.subkey(hive, base);
        if (!root) continue;
        for (const clsid of root.getSubkeys()) {
          if (t.count() >= H.MAX_PLUGIN_ROWS) break;
          for (const kind of SERVER_KINDS) {
            const srv = clsid.getSubkey(kind);
            if (!srv) continue;
            const path = H.getValueString(srv, '', '');
            if (!path) continue;
            const thread = H.getValueString(srv, 'ThreadingModel', '');
            const flag = WRITABLE_RE.test(path) ? 'writable-path (hijack?)' : '';
            if (flag) flagged++;
            t.row([clsid.name, kind, path, thread, flag]);
            total++;
          }
          const treat = clsid.getSubkey('TreatAs');
          if (treat) {
            const to = H.getValueString(treat, '', '');
            if (to) { t.row([clsid.name, 'TreatAs', to, '', 'redirect']); total++; }
          }
        }
      }
      if (total === 0) { ctx.rptMsg('No COM servers defined in this user hive (normal — most live in HKLM/SOFTWARE).'); return; }
      ctx.note(`${total} user-defined COM server(s); ${flagged} reference a writable path. Per-user CLSID entries shadow HKLM and are a common userland persistence/hijack technique (T1546.015).`);
    },
  });

  // ---------------------------------------------------------------------------
  // pcaexec — Program Compatibility Assistant remembers executables it saw run.
  // The Store/Persisted value names are the executable paths — execution
  // evidence that survives even when the binary is gone.

  const PCA_BASES = [
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant', // NTUSER
    'Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant',           // SOFTWARE
  ];

  R.register({
    name: 'pcaexec',
    hives: ['ntuser', 'software'],
    category: 'program execution',
    mitre: 'T1059',
    version: '20260902',
    shortDescr: 'Program Compatibility Assistant (Store/Persisted) executables — execution evidence',
    run(hive, ctx) {
      ctx.section('Program Compatibility Assistant');
      const t = ctx.table(['Executable', 'Source']);
      let total = 0;
      for (const base of PCA_BASES) {
        for (const leaf of ['Store', 'Persisted']) {
          const key = H.subkey(hive, base + '\\' + leaf);
          if (!key) continue;
          for (const v of key.getValues()) {
            if (t.count() >= H.MAX_PLUGIN_ROWS) break;
            t.row([v.name, leaf]);
            total++;
          }
        }
      }
      if (total === 0) { ctx.rptMsg('No Compatibility Assistant Store/Persisted entries found in this hive.'); return; }
      ctx.note(`${total} executable(s) recorded by PCA — each ran on this system at least once (execution evidence, T1059). PCA does not stamp a reliable per-entry time here.`);
    },
  });
})(window.RV);
