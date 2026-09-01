// rv.plugins — shared helpers mirroring RegRipper's framework globals
// (::rptMsg, ::getCCS, ::guessHive, ::getTime/::format8601Date) so ports stay
// close to the original Perl. All reads go through the parser API in RV.reg.
(function (RV) {
  'use strict';

  const { filetime } = RV.reg;

  // Backstop against pathological hives: cap rows emitted from any single
  // enumeration so run-all can't wedge on a corrupt/huge key.
  const MAX_PLUGIN_ROWS = 5000;

  // ---------------------------------------------------------------------------
  // Report builder — the `ctx` handed to each plugin's run(). Accumulates a
  // structured tree of sections → typed blocks. rptMsg/kv coalesce consecutive
  // lines into one block so ports can call them line-by-line like ::rptMsg.

  function makeContext() {
    const _sections = [];
    let cur = null;

    function ensure() {
      if (!cur) { cur = { title: null, blocks: [] }; _sections.push(cur); }
      return cur;
    }
    function lastBlock(kind) {
      const s = ensure();
      const b = s.blocks[s.blocks.length - 1];
      return b && b.kind === kind ? b : null;
    }

    const api = {
      section(title) {
        cur = { title: title == null ? null : String(title), blocks: [] };
        _sections.push(cur);
        return api;
      },
      rptMsg(text) {
        let b = lastBlock('text');
        if (!b) { b = { kind: 'text', lines: [] }; ensure().blocks.push(b); }
        b.lines.push(text == null ? '' : String(text));
        return api;
      },
      kv(label, value) {
        let b = lastBlock('kv');
        if (!b) { b = { kind: 'kv', pairs: [] }; ensure().blocks.push(b); }
        b.pairs.push([String(label), value == null ? '' : String(value)]);
        return api;
      },
      table(columns) {
        const b = { kind: 'table', columns: columns.map(String), rows: [] };
        ensure().blocks.push(b);
        const t = {
          row(cells) {
            if (b.rows.length < MAX_PLUGIN_ROWS) {
              b.rows.push(cells.map((c) => (c == null ? '' : String(c))));
            } else if (b.rows.length === MAX_PLUGIN_ROWS) {
              b.rows.push(['(truncated)']);
            }
            return t;
          },
          count() { return b.rows.length; },
        };
        return t;
      },
      note(text) {
        ensure().blocks.push({ kind: 'note', text: String(text) });
        return api;
      },
      sections() { return _sections; },
    };
    return api;
  }

  // ---------------------------------------------------------------------------
  // Hive-type detection — mirrors rr.pl guessHive(): embedded-filename basename
  // plus structural marker-key probes. Returns a Set of lowercase tags.

  function guessHiveType(hive) {
    const tags = new Set();
    try {
      const fn = hive.meta && hive.meta.fileName;
      if (fn) {
        const base = String(fn).split(/[\\/]/).pop().split('.')[0].toLowerCase();
        if (base) tags.add(base);
      }
    } catch { /* embedded name is best-effort */ }

    const has = (p) => { try { return hive.getKey(p) != null; } catch { return false; } };
    if (has('SAM\\Domains\\Account\\Users')) tags.add('sam');
    if (has('Microsoft\\Windows\\CurrentVersion') && has('Microsoft\\Windows NT\\CurrentVersion')) tags.add('software');
    if (has('MountedDevices') && has('Select')) tags.add('system');
    if (has('Policy\\Accounts') && has('Policy\\PolAdtEv')) tags.add('security');
    if (has('Software\\Microsoft\\Windows\\CurrentVersion') && has('Software\\Microsoft\\Windows NT\\CurrentVersion')) tags.add('ntuser');
    if (has('Local Settings\\Software') && has('lnkfile')) tags.add('usrclass');
    // Amcache.hve — Win8/8.1 shape (Root\File) or Win10/11 shape
    // (Root\InventoryApplicationFile); embedded filename 'Amcache' also tags.
    if (has('Root\\File') || has('Root\\InventoryApplicationFile') || has('Root\\InventoryApplication')) tags.add('amcache');
    if (tags.size === 0) tags.add('unknown');
    return tags;
  }

  // ---------------------------------------------------------------------------
  // Current control set — read Select\Current → ControlSetNNN, with fallbacks.
  // Mirrors rr_helper.pl getCCS() but robust to a missing/garbage Select key.

  function getControlSet(hive) {
    let name = null;
    const sel = subkey(hive, 'Select');
    if (sel) {
      const n = getValueDword(sel, 'Current', null);
      if (n != null) {
        const cand = 'ControlSet' + String(n).padStart(3, '0');
        if (subkey(hive, cand)) name = cand;
      }
    }
    if (!name && subkey(hive, 'ControlSet001')) name = 'ControlSet001';
    if (!name) {
      try {
        const cs = hive.getRootKey().getSubkeys().find((k) => /^ControlSet\d{3}$/i.test(k.name));
        if (cs) name = cs.name;
      } catch { /* unreadable root */ }
    }
    return { name, key: name ? subkey(hive, name) : null };
  }

  // ---------------------------------------------------------------------------
  // Safe getters — the null-tolerant style RegRipper achieves with eval {}.

  function subkey(hive, path) {
    try { return hive.getKey(path); } catch { return null; }
  }

  function getValueData(key, name, def) {
    if (!key) return def === undefined ? null : def;
    try {
      const v = key.getValue(name);
      if (!v) return def === undefined ? null : def;
      const d = v.getData();
      return d ? d.value : (def === undefined ? null : def);
    } catch { return def === undefined ? null : def; }
  }

  function getValueString(key, name, def) {
    const v = getValueData(key, name, def === undefined ? '' : def);
    return v == null ? (def === undefined ? '' : def) : String(v);
  }

  function getValueDword(key, name, def) {
    const v = getValueData(key, name, undefined);
    if (v == null) return def === undefined ? null : def;
    const n = Number(v);
    return Number.isNaN(n) ? (def === undefined ? null : def) : n;
  }

  // ---------------------------------------------------------------------------
  // Time helpers.

  /** Read 8 bytes little-endian from a binary value as a FILETIME → Date|null. */
  function filetimeFromBinary(bytes, offset) {
    const o = offset || 0;
    if (!bytes || bytes.length < o + 8) return null;
    let ft = 0n;
    for (let i = 7; i >= 0; i--) ft = (ft << 8n) | BigInt(bytes[o + i]);
    return filetime.filetimeToDate(ft);
  }

  /** DWORD unix-epoch seconds → Date|null (e.g. CurrentVersion\InstallDate). */
  function unixToDate(sec) {
    if (!sec) return null;
    return new Date(Number(sec) * 1000);
  }

  /** RegRipper-style "YYYY-MM-DD HH:MM:SS UTC" from a Date|bigint FILETIME|null. */
  function formatDate(d) {
    let date = d;
    if (typeof date === 'bigint') date = filetime.filetimeToDate(date);
    if (date == null) return '(never)';
    const p = (n, w) => String(n).padStart(w || 2, '0');
    return (
      `${p(date.getUTCFullYear(), 4)}-${p(date.getUTCMonth() + 1)}-${p(date.getUTCDate())} ` +
      `${p(date.getUTCHours())}:${p(date.getUTCMinutes())}:${p(date.getUTCSeconds())} UTC`
    );
  }

  // ROT13 — UserAssist value names are ROT13-encoded (letters only). Digits,
  // punctuation and non-Latin code points pass through untouched.
  function rot13(str) {
    return String(str).replace(/[a-zA-Z]/g, (c) => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
  }

  // ---------------------------------------------------------------------------
  // SysKey bootkey — derive the 16-byte bootkey from a SYSTEM hive's
  // Control\Lsa\{JD,Skew1,GBG,Data} key class names (public format fact; see
  // docs/crypto-notes.md). Returns {bootKey:Uint8Array, parts:{}} or null.

  const BOOTKEY_PBOX = Object.freeze([0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]);

  function getBootKey(systemHive) {
    if (!systemHive) return null;
    const { name: ccs } = getControlSet(systemHive);
    const base = ccs ? ccs + '\\Control\\Lsa' : 'ControlSet001\\Control\\Lsa';
    const lsa = subkey(systemHive, base);
    if (!lsa) return null;
    const parts = {};
    for (const nm of ['JD', 'Skew1', 'GBG', 'Data']) {
      const k = lsa.getSubkey(nm);
      parts[nm] = k ? k.className : null;
    }
    const hex = (parts.JD || '') + (parts.Skew1 || '') + (parts.GBG || '') + (parts.Data || '');
    if (!/^[0-9a-fA-F]{32}$/.test(hex)) return null;
    const scrambled = RV.crypto.hexToBytes(hex.toLowerCase());
    const bootKey = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bootKey[i] = scrambled[BOOTKEY_PBOX[i]];
    return { bootKey, parts, lsaPath: base };
  }

  // Extract printable UTF-16LE runs from a binary blob (pidl/shell-item
  // scraping — a documented simplification, not full shellbag parsing).
  function utf16Runs(bytes, minChars) {
    const min = minChars || 2;
    const out = [];
    if (!bytes) return out;
    let cur = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const c = bytes[i] | (bytes[i + 1] << 8);
      const printable = (c >= 0x20 && c <= 0x7e) || ' \\/:._-+@#$%&()[]{}\',~'.includes(String.fromCharCode(c));
      if (printable) cur += String.fromCharCode(c);
      else {
        if (cur.length >= min) out.push(cur);
        cur = '';
      }
    }
    if (cur.length >= min) out.push(cur);
    return out;
  }

  RV.plugins.helpers = {
    MAX_PLUGIN_ROWS,
    makeContext,
    guessHiveType,
    getControlSet,
    subkey,
    getValueData,
    getValueString,
    getValueDword,
    filetimeFromBinary,
    unixToDate,
    formatDate,
    rot13,
    getBootKey,
    utf16Runs,
  };
})(window.RV);
