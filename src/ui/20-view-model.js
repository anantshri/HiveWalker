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

  RV.ui.viewModel = { treeNode, valuesPane, hexRows, hiveMeta, statusBar };
})(window.RV);
