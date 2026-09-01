// rv.plugins — NTUSER.DAT-hive plugins. Ports of RegRipper's userassist,
// recentdocs, typedpaths, runmru. (run/uninstall are registered in
// 41-software.js and also apply to NTUSER.DAT.)
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  const EXPLORER = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer';
  const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

  R.register({
    name: 'userassist',
    hives: ['ntuser'],
    category: 'program execution',
    mitre: 'T1204',
    version: '20230710',
    shortDescr: 'Displays contents of UserAssist subkeys',
    run(hive, ctx) {
      const key = H.subkey(hive, EXPLORER + '\\UserAssist');
      ctx.section('UserAssist');
      if (!key) { ctx.rptMsg('UserAssist not found.'); return; }
      ctx.rptMsg('LastWrite: ' + H.formatDate(key.lastWriteDate));

      const noLog = H.getValueDword(H.subkey(hive, EXPLORER + '\\UserAssist\\Settings'), 'NoLog', null);
      if (noLog === 1) ctx.note('Settings\\NoLog = 1 — creation of new entries disabled (XP).');

      for (const guid of key.getSubkeys()) {
        if (guid.name.toLowerCase() === 'settings') continue;
        const count = guid.getSubkey('Count');
        if (!count) continue;
        ctx.section(guid.name);
        const timed = [];
        const noTime = [];
        for (const v of count.getValues()) {
          const name = H.rot13(v.name);
          const raw = v.getRawData();
          const len = raw ? raw.length : 0;
          if (len === 16) {
            let runs = u32le(raw, 4);
            if (runs > 5) runs -= 5;
            const date = H.filetimeFromBinary(raw, 8);
            if (date) timed.push({ date, text: `${name} (${runs})` });
            else noTime.push(name);
          } else if (len === 72) {
            const runs = u32le(raw, 4);
            const date = H.filetimeFromBinary(raw, 60);
            if (date) timed.push({ date, text: `${name} (${runs})` });
            else noTime.push(name);
          } else {
            noTime.push(name);
          }
        }
        timed.sort((a, b) => b.date - a.date);
        if (timed.length) {
          const t = ctx.table(['Last Run', 'Value (run count)']);
          for (const e of timed) t.row([H.formatDate(e.date), e.text]);
        }
        if (noTime.length) {
          ctx.rptMsg('Value names with no time stamps:');
          for (const n of noTime) ctx.rptMsg('  ' + n);
        }
      }
    },
  });

  // Decode a RecentDocs-style key's values into ordered {order, map}.
  function mruEntries(key) {
    const vals = key.getValues();
    if (vals.length === 0) return null;
    const map = new Map();
    let order = null;
    for (const v of vals) {
      const name = v.name;
      const raw = v.getRawData();
      if (name === "MRUListEx") {
        const seq = [];
        for (let o = 0; o + 4 <= raw.length; o += 4) {
          const n = u32le(raw, o);
          if (n === 0xffffffff) break;
          seq.push(n);
        }
        order = seq.map(String);
      } else if (name === "MRUList") {
        // REG_SZ of single-char indices, in order.
        order = String(v.getData().value).split("").filter((c) => c !== "\u0000");
      } else {
        // Filename is the leading UTF-16LE string before the shell-item blob.
        const file = RV.reg.decodeUtf16LE(raw).split("\u0000")[0];
        map.set(name, file);
      }
    }
    return { order: order || [...map.keys()], map };
  }

  R.register({
    name: 'recentdocs',
    hives: ['ntuser'],
    category: 'user activity',
    version: '20200924',
    shortDescr: "Gets contents of user's RecentDocs key",
    run(hive, ctx) {
      const key = H.subkey(hive, EXPLORER + '\\RecentDocs');
      ctx.section('RecentDocs');
      if (!key) { ctx.rptMsg('RecentDocs not found.'); return; }
      ctx.rptMsg('**All values printed in MRUListEx order.');
      ctx.rptMsg('LastWrite: ' + H.formatDate(key.lastWriteDate));
      const top = mruEntries(key);
      if (top) {
        const t = ctx.table(['Index', 'Entry']);
        for (const i of top.order) if (top.map.has(i)) t.row([i, top.map.get(i)]);
      }
      for (const s of key.getSubkeys()) {
        ctx.section('RecentDocs\\' + s.name);
        ctx.rptMsg('LastWrite: ' + H.formatDate(s.lastWriteDate));
        const e = mruEntries(s);
        if (e) {
          const t = ctx.table(['Index', 'Entry']);
          for (const i of e.order) if (e.map.has(i)) t.row([i, e.map.get(i)]);
        }
      }
    },
  });

  R.register({
    name: 'typedpaths',
    hives: ['ntuser'],
    category: 'user activity',
    version: '20201005',
    shortDescr: "Gets contents of user's TypedPaths key",
    run(hive, ctx) {
      const key = H.subkey(hive, EXPLORER + '\\TypedPaths');
      ctx.section('TypedPaths');
      if (!key) { ctx.rptMsg('TypedPaths not found.'); return; }
      ctx.rptMsg('LastWrite: ' + H.formatDate(key.lastWriteDate));
      const rows = key.getValues().map((v) => [v.name, H.getValueString(key, v.name, '')]);
      // Sort by the numeric suffix of "urlN".
      rows.sort((a, b) => (parseInt(a[0].replace(/^url/i, ''), 10) || 0) - (parseInt(b[0].replace(/^url/i, ''), 10) || 0));
      if (rows.length) { const t = ctx.table(['Name', 'Path']); rows.forEach((r) => t.row(r)); }
      else ctx.rptMsg('TypedPaths has no values.');
    },
  });

  R.register({
    name: 'runmru',
    hives: ['ntuser'],
    category: 'execution',
    mitre: 'T1204',
    version: '20201005',
    shortDescr: "Gets contents of user's RunMRU key",
    run(hive, ctx) {
      const key = H.subkey(hive, EXPLORER + '\\RunMRU');
      ctx.section('RunMRU');
      if (!key) { ctx.rptMsg('RunMRU not found.'); return; }
      ctx.rptMsg('LastWrite: ' + H.formatDate(key.lastWriteDate));
      let mru = '';
      const rows = [];
      for (const v of key.getValues()) {
        if (v.name === 'MRUList') mru = H.getValueString(key, 'MRUList', '');
        else rows.push([v.name, H.getValueString(key, v.name, '')]);
      }
      ctx.kv('MRUList', mru);
      rows.sort((a, b) => a[0].localeCompare(b[0]));
      if (rows.length) { const t = ctx.table(['Name', 'Command']); rows.forEach((r) => t.row(r)); }
    },
  });

  // ---------------------------------------------------------------------------
  // New bespoke plugins (not from the RR corpus — see docs/regripper-plugins.md):
  // tsclient, wordwheelquery, mountpoints2, opensavepidl.

  R.register({
    name: 'tsclient',
    hives: ['ntuser'],
    category: 'lateral movement',
    mitre: 'T1021.001',
    version: '20260901',
    shortDescr: 'Outbound RDP history: MRU servers + per-host username hints',
    run(hive, ctx) {
      ctx.section('Terminal Server Client (outbound RDP)');
      const base = 'Software\\Microsoft\\Terminal Server Client';
      const root = H.subkey(hive, base);
      if (!root) { ctx.rptMsg(base + ' not found.'); return; }

      const def = root.getSubkey('Default');
      if (def) {
        ctx.section('MRU servers');
        const entries = [];
        for (const v of def.getValues()) {
          const m = /^MRU(\d+)$/.exec(v.name);
          if (m) entries.push([Number(m[1]), v.name, String(v.getData().value)]);
        }
        entries.sort((a, b) => a[0] - b[0]);
        const t = ctx.table(['Order', 'Value', 'Server']);
        entries.forEach(([n, name, val]) => t.row([String(n), name, val]));
        if (entries.length === 0) ctx.rptMsg('(no MRU entries)');
      }
      const servers = root.getSubkey('Servers');
      if (servers) {
        ctx.section('Per-server history');
        const t = ctx.table(['Server', 'Username hint', 'Key LastWrite (UTC)']);
        for (const s of servers.getSubkeys()) {
          const hint = H.getValueString(s, 'UsernameHint', '');
          t.row([s.name, hint || '-', H.formatDate(s.lastWriteDate)]);
        }
      }
    },
  });

  R.register({
    name: 'wordwheelquery',
    hives: ['ntuser'],
    category: 'user activity',
    version: '20260901',
    shortDescr: 'Explorer search box terms in MRU order',
    run(hive, ctx) {
      ctx.section('WordWheelQuery (Explorer searches)');
      const path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery';
      const key = H.subkey(hive, path);
      if (!key) { ctx.rptMsg(path + ' not found.'); return; }
      ctx.rptMsg('Key LastWrite: ' + H.formatDate(key.lastWriteDate));
      const mruRaw = H.getValueData(key, 'MRUListEx');
      let order = [];
      if (mruRaw && mruRaw.length >= 4) {
        const dv = new DataView(mruRaw.buffer, mruRaw.byteOffset, mruRaw.byteLength);
        for (let i = 0; i + 4 <= mruRaw.length; i += 4) {
          const n = dv.getInt32(i, true);
          if (n === -1) break;
          order.push(n);
        }
      } else {
        // numeric-named values without MRUListEx: fall back to numeric order
        const idx = [];
        for (const v of key.getValues()) {
          const m = /^\d+$/.exec(v.name);
          if (m) idx.push(Number(v.name));
        }
        order = idx.sort((a, b) => a - b);
      }
      const t = ctx.table(['Order', 'Index', 'Search term']);
      order.forEach((n, i) => {
        const v = key.getValue(String(n));
        if (!v) return;
        const raw = v.getRawData();
        let s = '';
        if (raw) {
          for (let j = 0; j + 1 < raw.length; j += 2) {
            const c = raw[j] | (raw[j + 1] << 8);
            if (c === 0) break;
            s += String.fromCharCode(c);
          }
        }
        t.row([String(i), String(n), s]);
      });
      if (order.length === 0) ctx.rptMsg('(empty)');
    },
  });

  R.register({
    name: 'mountpoints2',
    hives: ['ntuser'],
    category: 'user activity',
    version: '20260901',
    shortDescr: 'Drive letters, UNC shares and CSP volumes mounted by this user',
    run(hive, ctx) {
      ctx.section('MountPoints2');
      const path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2';
      const key = H.subkey(hive, path);
      if (!key) { ctx.rptMsg(path + ' not found.'); return; }
      const t = ctx.table(['Mount', 'Type', 'Label', 'LastWrite (UTC)']);
      let rows = 0;
      for (const k of key.getSubkeys()) {
        let type = 'unknown';
        let label = '';
        if (/^##/.test(k.name)) type = 'UNC share';
        else if (/^[A-Za-z]:$/.test(k.name)) type = 'Drive letter';
        else if (/^\{[0-9a-f-]+\}$/i.test(k.name)) type = 'Volume (CSP/BitLocker)';
        else if (/^_/.test(k.name)) type = 'OneDrive/sync';
        if (type === 'Drive letter') {
          label = H.getValueString(k, '_LabelFromReg', '') || H.getValueString(k, 'Label', '');
        }
        t.row([k.name, type, label || '-', H.formatDate(k.lastWriteDate)]);
        rows++;
        if (rows >= H.MAX_PLUGIN_ROWS) { ctx.note('(truncated)'); break; }
      }
      if (rows === 0) ctx.rptMsg('(no mount points)');
    },
  });

  R.register({
    name: 'opensavepidl',
    hives: ['ntuser'],
    category: 'user activity',
    version: '20260901',
    shortDescr: 'Open/Save dialog MRUs: paths + launching programs (string extraction)',
    run(hive, ctx) {
      ctx.section('ComDlg32 OpenSave / LastVisited MRUs');
      const base = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32';
      const root = H.subkey(hive, base);
      if (!root) { ctx.rptMsg(base + ' not found.'); return; }

      const dumpExtKey = (key, title) => {
        ctx.section(title);
        const mruRaw = H.getValueData(key, 'MRUListEx');
        let order = [];
        if (mruRaw && mruRaw.length >= 4) {
          const dv = new DataView(mruRaw.buffer, mruRaw.byteOffset, mruRaw.byteLength);
          for (let i = 0; i + 4 <= mruRaw.length; i += 4) {
            const n = dv.getInt32(i, true);
            if (n === -1) break;
            order.push(n);
          }
        }
        const t = ctx.table(['Order', 'Index', 'Extracted strings']);
        order.forEach((n, i) => {
          const v = key.getValue(String(n));
          if (!v) return;
          const runs = H.utf16Runs(v.getRawData(), 3);
          t.row([String(i), String(n), runs.join(' | ') || '(binary)']);
        });
        if (order.length === 0) ctx.rptMsg('(empty)');
      };

      const osr = root.getSubkey('OpenSavePidlMRU');
      if (osr) {
        const star = osr.getSubkey('*');
        if (star) dumpExtKey(star, 'OpenSavePidlMRU\\* (all extensions)');
        for (const ext of osr.getSubkeys()) {
          if (ext.name === '*') continue;
          dumpExtKey(ext, 'OpenSavePidlMRU\\' + ext.name);
        }
      } else {
        ctx.rptMsg('OpenSavePidlMRU not found.');
      }
      const lv = root.getSubkey('LastVisitedPidlMRU');
      if (lv) {
        const star = lv.getSubkey('*');
        if (star) dumpExtKey(star, 'LastVisitedPidlMRU\\* (program → last folder)');
      } else {
        ctx.rptMsg('LastVisitedPidlMRU not found.');
      }
      ctx.note('Paths are extracted as UTF-16 strings from shell-item blobs; full shellbag structure parsing is not implemented.');
    },
  });
})(window.RV);
