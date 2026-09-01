// rv.ui — the values pane: a path bar on top (breadcrumb + copy), LastWrite
// header, and the Name / Type / Data table.
(function (RV) {
  'use strict';

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  /** Path bar: clickable breadcrumb segments + copy button. */
  function renderPathBar(pane, key) {
    const bar = el('div', 'path-bar');

    const crumbs = el('div', 'path-crumbs');
    const segments = key.path.split('\\');
    segments.forEach((seg, i) => {
      if (i > 0) crumbs.appendChild(el('span', 'path-sep', '›'));
      const crumb = el('button', 'path-crumb', seg || '(root)');
      crumb.type = 'button';
      crumb.title = segments.slice(0, i + 1).join('\\');
      // Clicking a crumb navigates to that ancestor.
      crumb.addEventListener('click', () => {
        let target = key;
        for (let up = segments.length - 1 - i; up > 0; up--) {
          if (!target.parent) break;
          target = target.parent;
        }
        RV.ui.app.navigateTo(target);
      });
      crumbs.appendChild(crumb);
    });
    bar.appendChild(crumbs);

    const copy = el('button', 'path-copy', '⧉ Copy');
    copy.type = 'button';
    copy.title = 'Copy full path to clipboard';
    copy.addEventListener('click', async () => {
      const text = key.path;
      try {
        await navigator.clipboard.writeText(text);
        copy.textContent = '✓ Copied';
        setTimeout(() => { copy.textContent = '⧉ Copy'; }, 1200);
      } catch {
        // clipboard may be unavailable (e.g. file:// without permission);
        // select the text so Ctrl+C works manually.
        const range = document.createRange();
        range.selectNodeContents(crumbs);
        const sel = window.getSelection();
        if (sel) { sel.removeAllRanges(); sel.addRange(range); }
        copy.textContent = 'Ctrl+C';
        setTimeout(() => { copy.textContent = '⧉ Copy'; }, 1200);
      }
    });
    bar.appendChild(copy);

    pane.appendChild(bar);
  }

  function render(pane, key) {
    const vm = RV.ui.viewModel.valuesPane(key);
    pane.textContent = '';

    renderPathBar(pane, key);

    const header = el('div', 'values-header');
    header.appendChild(el('div', 'key-ts', `Last write: ${vm.lastWrite}`));
    if (vm.warningCount > 0) {
      header.appendChild(el('div', 'key-warn', `⚠ ${vm.warningCount} parsing warning(s)`));
    }
    pane.appendChild(header);

    if (vm.warningCount > 0) {
      const warn = el('div', 'values-warnings');
      vm.warnings.forEach((w) => warn.appendChild(el('div', null, `⚠ ${w}`)));
      pane.appendChild(warn);
    }

    const table = el('table', 'values-table');
    const thead = el('thead');
    const hr = el('tr');
    vm.columns.forEach((c) => hr.appendChild(el('th', null, c)));
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = el('tbody');
    if (vm.rows.length === 0) {
      const tr = el('tr', 'empty');
      const td = el('td', null, '(no values)');
      td.colSpan = 3;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
    for (const row of vm.rows) {
      const tr = el('tr');
      if (row.binary) tr.classList.add('binary-row');
      tr.appendChild(el('td', 'val-name', row.name));
      tr.appendChild(el('td', 'val-type', row.type));
      const dataTd = el('td', 'val-data', row.data);
      if (row.note) dataTd.title = row.note;
      tr.appendChild(dataTd);
      if (row.binary) {
        tr.addEventListener('click', () => RV.ui.hexview.show(row.name, row));
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    pane.appendChild(table);
  }

  RV.ui.values = { render };
})(window.RV);
