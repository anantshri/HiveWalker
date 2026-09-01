// rv.ui — pure state → view-model functions. The DOM-free seam the Node
// tests exercise: tree rows, value rows, hex rows, metadata rows.
(function (RV) {
  'use strict';

  /** One row of the key tree (rendered by 22-tree.js). */
  function treeNode(key, expanded) {
    const kids = key.subkeyCount > 0 ? key.getSubkeys() : [];
    return {
      id: key.path,
      name: key.name,
      hasChildren: key.subkeyCount > 0,
      expanded: !!expanded,
      warning: key.warnings.length > 0,
      warningCount: key.warnings.length,
      childrenLoaded: expanded && key.subkeyCount > 0,
      children: expanded ? kids.map((k) => treeNode(k, false)) : null,
    };
  }

  /** The values pane header + rows for a selected key. */
  function valuesPane(key) {
    return {
      keyPath: key.path,
      lastWrite: RV.reg.filetime.formatFiletime(key.lastWrite),
      warningCount: key.warnings.length,
      warnings: key.warnings.slice(),
      columns: ['Name', 'Type', 'Data'],
      rows: key.getValues().map((v) => {
        const d = v.getDisplay();
        return {
          name: v.displayName,
          type: v.typeName,
          data: d.text,
          note: d.note || null,
          binary: v.isBinaryKind(),
          size: v.dataSize,
        };
      }),
    };
  }

  /** Hex-dump rows for a byte array (16 per row), windowed. */
  function hexRows(bytes, opts) {
    const width = (opts && opts.width) || 16;
    const from = (opts && opts.from) || 0;
    const to = Math.min((opts && opts.to) || bytes.length, bytes.length);
    const rows = [];
    for (let off = from; off < to; off += width) {
      const n = Math.min(width, to - off);
      let hex = '';
      let ascii = '';
      for (let i = 0; i < n; i++) {
        const b = bytes[off + i];
        hex += b.toString(16).padStart(2, '0') + ' ';
        ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '·';
      }
      rows.push({
        offset: off,
        offsetHex: '0x' + off.toString(16).padStart(8, '0'),
        hex: hex.trimEnd(),
        ascii,
      });
    }
    return rows;
  }

  /** Hive metadata panel rows. */
  function hiveMeta(hive) {
    const m = hive.meta;
    const f = (b) => (b ? 'yes' : 'no');
    return {
      title: m.fileName || '(unnamed hive)',
      rows: [
        ['Embedded file name', m.fileName || '—'],
        ['Format version', m.majorVersion],
        ['Sequence numbers', `${m.sequence1} / ${m.sequence2}`],
        ['Dirty (logs not applied)', f(m.dirty)],
        ['Checksum valid', f(m.checksumValid)],
        ['Hive bins size', `${m.hiveBinsSize} bytes (${hive.bins.length} bins)`],
        ['Root cell offset', `0x${m.rootCellOffset.toString(16)}`],
        ['Last written', RV.reg.filetime.formatFiletime(m.timestamp)],
        ['Base-block timestamp', m.timestamp.toString()],
      ],
      warnings: hive.warnings.slice(),
    };
  }

  /** Status bar line for the current selection. */
  function statusBar(hive, key, counts) {
    const parts = [];
    if (key) parts.push(key.path);
    if (key) parts.push(`${key.subkeyCount} keys, ${key.valueCount} values`);
    if (counts) parts.push(`total: ${counts.keys} keys, ${counts.values} values`);
    if (hive && hive.warnings.length) parts.push(`⚠ ${hive.warnings.length}`);
    return { text: parts.join('  ·  ') };
  }

  // --- Reports (RegRipper-style plugins) ------------------------------------
  // DOM-free seam: these turn a hive / plugin-run result into render-ready data
  // and plain text, so both the reports panel and the Node tests use them.

  /** Applicable + all plugins for the loaded hive, with detected hive types. */
  function pluginList(hive) {
    const rt = RV.plugins.runtime;
    const detectedTypes = [...RV.plugins.helpers.guessHiveType(hive)];
    const applicable = new Set(rt.applicableTo(hive).map((p) => p.name));
    const plugins = rt.all().map((p) => ({
      name: p.name,
      shortDescr: p.shortDescr || '',
      category: p.category || '',
      mitre: p.mitre || null,
      hiveTypes: p.hives.slice(),
      applicable: applicable.has(p.name),
    }));
    // Applicable plugins first, then by name.
    plugins.sort((a, b) => (b.applicable - a.applicable) || a.name.localeCompare(b.name));
    return { detectedTypes, plugins };
  }

  /** Normalise a runtime.run() result into render-ready data for the panel. */
  function reportView(result) {
    const meta = [['Hive', result.hiveTypes.join(', ')]];
    if (result.category) meta.push(['Category', result.category]);
    if (result.mitre) meta.push(['MITRE', result.mitre]);
    if (result.version) meta.push(['Version', String(result.version)]);
    const hasContent = result.sections.some((s) => s.blocks.length > 0);
    return {
      title: `${result.plugin}${result.shortDescr ? ' — ' + result.shortDescr : ''}`,
      meta,
      error: result.error,
      empty: !hasContent && !result.error,
      sections: result.sections,
    };
  }

  /** RegRipper-style plain text for a single result (copy payload + parity). */
  function reportText(result) {
    const out = [];
    out.push(`${result.plugin} v.${result.version}`);
    out.push(`(${result.hiveTypes.join(', ')}) ${result.shortDescr}`);
    if (result.mitre) out.push(`MITRE: ${result.mitre} (${result.category})`);
    out.push('');
    if (result.error) {
      out.push(`ERROR: ${result.error.name}: ${result.error.message}`);
      return out.join('\n');
    }
    for (const s of result.sections) {
      if (s.title) out.push(s.title);
      for (const b of s.blocks) {
        if (b.kind === 'text') { for (const l of b.lines) out.push(l); }
        else if (b.kind === 'kv') { for (const [k, v] of b.pairs) out.push(`  ${k.padEnd(24)} ${v}`); }
        else if (b.kind === 'note') { out.push(b.text); }
        else if (b.kind === 'table') {
          out.push('  ' + b.columns.join(' | '));
          for (const r of b.rows) out.push('  ' + r.join(' | '));
        }
      }
      out.push('');
    }
    return out.join('\n').replace(/\n+$/, '\n');
  }

  /** Concatenate multiple results for a run-all export. */
  function reportTextAll(results) {
    return results.map(reportText).join('\n' + '-'.repeat(60) + '\n\n');
  }

  /**
   * PDF rendering model for one or more report results — the DOM-free input to
   * RV.ui.pdf.makePdf. Flattens the structured results into styled lines:
   * `{text, style}` where style ∈ title | section | meta | body | note.
   * Keeps one source of truth: the same structured result reportText consumes.
   */
  function reportPdfModel(results) {
    const list = Array.isArray(results) ? results : [results];
    const lines = [];
    let replacedChars = 0;
    const push = (text, style) => lines.push({ text: String(text), style });

    for (let r = 0; r < list.length; r++) {
      const result = list[r];
      if (r > 0) push(' ', 'body'); // visual gap between results
      push(`${result.plugin} v.${result.version}`, 'title');
      push(`(${result.hiveTypes.join(', ')}) ${result.shortDescr}`, 'meta');
      if (result.mitre) push(`MITRE: ${result.mitre}${result.category ? ' (' + result.category + ')' : ''}`, 'meta');
      push(' ', 'body');
      if (result.error) {
        push(`ERROR: ${result.error.name}: ${result.error.message}`, 'note');
        continue;
      }
      for (const s of result.sections) {
        if (s.title) push(s.title, 'section');
        for (const b of s.blocks) {
          if (b.kind === 'text') {
            for (const l of b.lines) push(l, 'body');
          } else if (b.kind === 'kv') {
            for (const [k, v] of b.pairs) push(`  ${k.padEnd(24)} ${v}`, 'body');
          } else if (b.kind === 'note') {
            push(b.text, 'note');
          } else if (b.kind === 'table') {
            push('  ' + b.columns.join(' | '), 'body');
            for (const row of b.rows) push('  ' + row.join(' | '), 'body');
          }
        }
      }
    }
    return { lines, replacedChars };
  }

  RV.ui.viewModel = {
    treeNode, valuesPane, hexRows, hiveMeta, statusBar,
    pluginList, reportView, reportText, reportTextAll, reportPdfModel,
  };
})(window.RV);
