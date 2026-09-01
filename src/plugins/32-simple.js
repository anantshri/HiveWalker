// rv.plugins — descriptor-driven factory for the large set of "simple"
// RegRipper plugins (pure key/value/subkey reads, no bespoke binary decoding).
// A descriptor declares metadata + a read pattern; registerSimple() turns it
// into a normal runtime plugin. Bespoke plugins keep using runtime.register().
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

  // Resolve a descriptor's candidate paths to concrete paths for this hive,
  // applying the current-control-set prefix for System-hive descriptors.
  function resolvePaths(hive, desc) {
    let prefix = '';
    if (desc.ccs) {
      const { name } = H.getControlSet(hive);
      prefix = (name || 'ControlSet001') + '\\';
    }
    return desc.paths.map((p) => prefix + p);
  }

  // --- read modes ------------------------------------------------------------

  function emitValues(ctx, key, names) {
    const vals = names
      ? names.map((n) => key.getValue(n)).filter(Boolean)
      : key.getValues();
    if (vals.length === 0) { ctx.rptMsg('(no matching values)'); return; }
    const t = ctx.table(['Name', 'Data']);
    for (const v of vals) t.row([v.displayName, v.getDisplay().text]);
  }

  function emitSubkeys(ctx, key, names) {
    const subs = key.getSubkeys();
    if (subs.length === 0) { ctx.rptMsg('(no subkeys)'); return; }
    const cols = ['Subkey', 'LastWrite'].concat(names || []);
    const t = ctx.table(cols);
    for (const s of subs) {
      const row = [s.name, H.formatDate(s.lastWriteDate)];
      if (names) for (const n of names) row.push(H.getValueString(s, n, ''));
      t.row(row);
    }
  }

  function emitMru(ctx, key) {
    const vals = key.getValues();
    if (vals.length === 0) { ctx.rptMsg('(no values)'); return; }
    const map = new Map();
    let order = null;
    for (const v of vals) {
      const name = v.name;
      if (name === 'MRUListEx') {
        const raw = v.getRawData();
        const seq = [];
        for (let o = 0; o + 4 <= raw.length; o += 4) {
          const n = u32le(raw, o);
          if (n === 0xffffffff) break;
          seq.push(String(n));
        }
        order = seq;
      } else if (name === 'MRUList') {
        order = String(v.getData().value).split('').filter((c) => c !== '\u0000' && c !== '');
      } else {
        map.set(name, v.getDisplay().text);
      }
    }
    const keys = order && order.length ? order : [...map.keys()];
    const t = ctx.table(['Index', 'Value']);
    for (const k of keys) if (map.has(k)) t.row([k, map.get(k)]);
  }

  function runOne(ctx, key, desc) {
    if (desc.mode === 'subkeys') emitSubkeys(ctx, key, desc.subkeyNames);
    else if (desc.mode === 'named') emitValues(ctx, key, desc.names);
    else if (desc.mode === 'mru') emitMru(ctx, key);
    else emitValues(ctx, key, null); // 'values' (default)
  }

  /** Turn a descriptor into a registered plugin. */
  function registerSimple(desc) {
    if (!desc || !Array.isArray(desc.paths) || desc.paths.length === 0) {
      throw new TypeError(`descriptor ${desc && desc.name}: paths[] required`);
    }
    R.register({
      name: desc.name,
      hives: desc.hives,
      category: desc.category || '',
      mitre: desc.mitre || null,
      version: desc.version || '',
      shortDescr: desc.shortDescr || '',
      simple: true,
      run(hive, ctx) {
        const paths = resolvePaths(hive, desc);
        let found = false;
        for (const path of paths) {
          const key = H.subkey(hive, path);
          if (!key) continue;
          found = true;
          ctx.section(path);
          ctx.rptMsg('LastWrite: ' + H.formatDate(key.lastWriteDate));
          runOne(ctx, key, desc);
        }
        if (!found) {
          ctx.section(desc.name);
          ctx.rptMsg(paths.length === 1 ? paths[0] + ' not found.' : 'None of the target paths were found.');
        }
      },
    });
  }

  /** Register an array of descriptors, tolerating individual bad ones. */
  function registerAll(descriptors) {
    let ok = 0;
    for (const d of descriptors) {
      try { registerSimple(d); ok++; } catch (e) {
        // A malformed descriptor is a data error — skip it, don't abort the batch.
        if (typeof console !== 'undefined') console.warn('skip descriptor', d && d.name, e.message);
      }
    }
    return ok;
  }

  RV.plugins.simple = { registerSimple, registerAll };
})(window.RV);
