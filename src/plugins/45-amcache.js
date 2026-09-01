// rv.plugins — Amcache.hve plugins. Win8/8.1 (\Root\File + \Root\Programs)
// and Win10/11 (\Root\InventoryApplication*) shapes; field map confirmed
// against the MIT-licensed regipy amcache plugin as a format reference
// (numeric value-name translations, SHA-1 '0000' prefix stripping).
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  // Win8 numeric value names → meaning (public field map; docs/crypto-notes.md).
  const WIN8_FIELDS = {
    0: 'product', 1: 'company', 3: 'language', 5: 'fileVersion', 6: 'size',
    0xc: 'description', 0xf: 'linkTime', 0x11: 'lastModified', 0x12: 'created',
    0x15: 'path', 0x17: 'lastModified2', 0x101: 'sha1',
  };

  function win8Num(name) {
    if (!/^[0-9a-f]+$/i.test(name)) return null;
    const v = parseInt(name, 16);
    return Object.prototype.hasOwnProperty.call(WIN8_FIELDS, v) ? WIN8_FIELDS[v] : null;
  }

  /** SHA-1 values carry a '0000' prefix to be stripped (public format fact). */
  function cleanSha1(s) {
    if (typeof s !== 'string' || s.length < 4) return s;
    return s.startsWith('0000') ? s.slice(4) : s;
  }

  function ftFromValue(raw) {
    if (!raw || raw.length < 8) return null;
    return H.filetimeFromBinary(raw, 0);
  }

  R.register({
    name: 'amcache_file',
    hives: ['amcache'],
    category: 'program execution',
    version: '20260901',
    shortDescr: 'Amcache file inventory: paths, SHA-1s, sizes, first-use times',
    run(hive, ctx) {
      ctx.section('Amcache File Inventory');
      const win8Root = H.subkey(hive, 'Root\\File');
      const win10Root = H.subkey(hive, 'Root\\InventoryApplicationFile');
      if (!win8Root && !win10Root) {
        ctx.rptMsg('Root\\File / Root\\InventoryApplicationFile not found (not an Amcache.hve?).');
        return;
      }

      let total = 0;
      const t = ctx.table(['Path', 'SHA-1', 'Size', 'Last Modified (UTC)', 'Created (UTC)', 'Company', 'Product']);

      if (win8Root) {
        ctx.note('Detected Windows 8/8.1 Amcache format (Root\\File).');
        for (const vol of win8Root.getSubkeys()) {
          for (const fileKey of vol.getSubkeys()) {
            if (t.count() >= H.MAX_PLUGIN_ROWS) break;
            const f = {};
            for (const v of fileKey.getValues()) {
              const label = win8Num(v.name);
              const data = v.getData().value;
              if (label) f[label] = data;
            }
            // 'size' arrives as a hex string in Win8 hives
            const size = f.size != null ? (/^[0-9a-f]+$/i.test(String(f.size)) ? parseInt(f.size, 16) : f.size) : null;
            t.row([
              f.path || fileKey.name,
              f.sha1 ? cleanSha1(String(f.sha1)) : '-',
              size != null ? String(size) : '-',
              ftFromValue(f.lastModified instanceof Uint8Array ? f.lastModified : null)
                ? H.formatDate(ftFromValue(f.lastModified)) : '-',
              ftFromValue(f.created instanceof Uint8Array ? f.created : null)
                ? H.formatDate(ftFromValue(f.created)) : '-',
              f.company ? String(f.company) : '-',
              f.product ? String(f.product) : '-',
            ]);
            total++;
          }
        }
      }

      if (win10Root) {
        if (win8Root) ctx.note('Also found Root\\InventoryApplicationFile (Win10/11 shape) — listing both.');
        else ctx.note('Detected Windows 10/11 Amcache format (Root\\InventoryApplicationFile).');
        for (const fileKey of win10Root.getSubkeys()) {
          if (t.count() >= H.MAX_PLUGIN_ROWS) break;
          const g = (n) => H.getValueString(fileKey, n, '');
          const size = H.getValueDword(fileKey, 'Size', null);
          t.row([
            g('LowerCaseLongPath') || fileKey.name,
            cleanSha1(g('FileId')) || '-',
            size != null ? String(size) : '-',
            g('LinkDate') || '-',
            '-',
            g('Publisher') || '-',
            g('BinFileVersion') || '-',
          ]);
          total++;
        }
      }

      if (total === 0) ctx.rptMsg('(no file entries)');
      if (total > H.MAX_PLUGIN_ROWS) ctx.note(`Truncated to ${H.MAX_PLUGIN_ROWS} of ${total} entries.`);
    },
  });

  R.register({
    name: 'amcache_app',
    hives: ['amcache'],
    category: 'program execution',
    version: '20260901',
    shortDescr: 'Amcache installed-application inventory (Programs / InventoryApplication)',
    run(hive, ctx) {
      ctx.section('Amcache Applications');
      const win8 = H.subkey(hive, 'Root\\Programs');
      const win10 = H.subkey(hive, 'Root\\InventoryApplication');
      if (!win8 && !win10) {
        ctx.rptMsg('Root\\Programs / Root\\InventoryApplication not found.');
        return;
      }
      const t = ctx.table(['Name', 'Version', 'Category / InstallDate', 'Key LastWrite (UTC)']);
      let total = 0;
      if (win8) {
        for (const p of win8.getSubkeys()) {
          if (t.count() >= H.MAX_PLUGIN_ROWS) break;
          const name = H.getValueString(p, '0', '') || p.name;
          const ver = H.getValueString(p, '1', '');
          const cat = H.getValueString(p, '6', '');
          t.row([name, ver, cat, H.formatDate(p.lastWriteDate)]);
          total++;
        }
      }
      if (win10) {
        for (const p of win10.getSubkeys()) {
          if (t.count() >= H.MAX_PLUGIN_ROWS) break;
          t.row([
            H.getValueString(p, 'Name', '') || p.name,
            H.getValueString(p, 'Version', ''),
            H.getValueString(p, 'InstallDate', ''),
            H.formatDate(p.lastWriteDate),
          ]);
          total++;
        }
      }
      if (total === 0) ctx.rptMsg('(no application entries)');
      if (total > H.MAX_PLUGIN_ROWS) ctx.note(`Truncated to ${H.MAX_PLUGIN_ROWS} of ${total} entries.`);
    },
  });
})(window.RV);
