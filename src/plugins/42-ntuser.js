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
})(window.RV);
