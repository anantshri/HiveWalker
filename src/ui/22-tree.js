// rv.ui — the key tree. Nodes render children lazily on first expand; all
// hive-derived text goes through textContent only.
//
// Interactions:
//  - click a row: select it AND toggle it open/closed when it has children
//  - twisty click: toggle only (stopPropagation)
//  - ArrowUp/ArrowDown: move selection between visible rows
//  - ArrowRight: expand the selected row (or move to first child)
//  - ArrowLeft: collapse the selected row (or move to its parent)
//  - Enter/Space: toggle; Home/End: first/last visible row
(function (RV) {
  'use strict';

  let container = null;
  let onSelect = null;
  let activeKey = null;
  const rowByKey = new Map(); // key.path -> row element
  const keyByRow = new Map(); // row element -> key

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function render(rootEl, hive, selectFn) {
    container = rootEl;
    onSelect = selectFn;
    rowByKey.clear();
    keyByRow.clear();
    activeKey = null;
    container.textContent = '';
    container.tabIndex = 0; // focusable for keyboard nav
    const rootKey = hive.getRootKey();
    const rootRow = rowFor(rootKey, 0);
    container.appendChild(rootRow);
    expand(rootKey);
    activeKey = rootKey;
  }

  function rowFor(key, depth) {
    const vm = RV.ui.viewModel.treeNode(key, false);
    const row = el('div', 'tree-row');
    row.style.paddingLeft = `${8 + depth * 14}px`;
    row.dataset.path = key.path;

    const twisty = el('span', 'twisty' + (vm.hasChildren ? '' : ' leaf'), vm.hasChildren ? '▸' : '');
    row.appendChild(twisty);

    const label = el('span', 'tree-label', vm.name);
    row.appendChild(label);

    if (vm.warning) {
      const badge = el('span', 'badge', '⚠');
      badge.title = `${vm.warningCount} parsing warning(s)`;
      row.appendChild(badge);
    }

    if (vm.hasChildren) {
      twisty.addEventListener('click', (ev) => {
        ev.stopPropagation();
        toggle(key, row, depth);
      });
    }
    // Clicking a row both selects it and (when it has children) opens it —
    // regedit-style disclosure on click.
    row.addEventListener('click', () => {
      selectAndActivate(key);
      if (vm.hasChildren) toggle(key, row, depth);
    });

    rowByKey.set(key.path, row);
    keyByRow.set(row, key);
    return row;
  }

  function selectAndActivate(key) {
    activeKey = key;
    onSelect(key);
  }

  function toggle(key, row, depth) {
    if (row == null) row = rowByKey.get(key.path);
    if (row == null) return;
    if (row.dataset.expanded === 'true') {
      collapse(key, row);
    } else {
      expand(key, row, depth);
    }
  }

  function expand(key, row, depth) {
    if (row == null) row = rowByKey.get(key.path);
    if (row == null || row.dataset.expanded === 'true') return;
    row.dataset.expanded = 'true';
    const twisty = row.querySelector('.twisty');
    if (twisty) twisty.textContent = '▾';
    const kids = key.getSubkeys();
    const parent = row.parentNode;
    let anchor = row.nextSibling;
    for (const kid of kids) {
      const kidRow = rowFor(kid, depth + 1);
      parent.insertBefore(kidRow, anchor);
    }
    if (kids.length === 0 && key.subkeyCount > 0) {
      const empty = el('div', 'tree-row empty', '(unreadable)');
      empty.style.paddingLeft = `${8 + (depth + 1) * 14}px`;
      parent.insertBefore(empty, anchor);
    }
  }

  function collapse(key, row) {
    if (row == null) row = rowByKey.get(key.path);
    if (row == null || row.dataset.expanded !== 'true') return;
    row.dataset.expanded = 'false';
    const twisty = row.querySelector('.twisty');
    if (twisty) twisty.textContent = '▸';
    // If the active key is inside the collapsing branch, move it up.
    const prefix = key.path + '\\';
    if (activeKey && activeKey.path.startsWith(prefix)) activeKey = key;
    // Remove this row's descendants only (paths strictly under this key).
    for (const [path, elRow] of Array.from(rowByKey)) {
      if (path.startsWith(prefix)) {
        elRow.remove();
        rowByKey.delete(path);
        keyByRow.delete(elRow);
      }
    }
  }

  function select(key) {
    for (const [, elRow] of rowByKey) elRow.classList.remove('selected');
    const row = rowByKey.get(key.path);
    if (row) {
      row.classList.add('selected');
      row.scrollIntoView({ block: 'nearest' });
    }
  }

  /** Expand ancestors so the key is visible, then select it. */
  function reveal(key) {
    const chain = [];
    for (let k = key.parent; k; k = k.parent) chain.unshift(k);
    for (const ancestor of chain) expand(ancestor);
    activeKey = key;
    select(key);
  }

  // -- keyboard navigation ---------------------------------------------------

  /** Visible rows in document order (expanded branches only). */
  function visibleRows() {
    const rows = [];
    for (const node of container.querySelectorAll('.tree-row')) {
      if (node.classList.contains('empty')) continue;
      const key = keyByRow.get(node);
      if (key) rows.push({ row: node, key });
    }
    return rows;
  }

  function moveSelection(delta) {
    const rows = visibleRows();
    if (rows.length === 0) return;
    const idx = rows.findIndex((r) => r.key.path === (activeKey && activeKey.path));
    const next = idx === -1
      ? (delta > 0 ? 0 : rows.length - 1)
      : Math.min(rows.length - 1, Math.max(0, idx + delta));
    if (next !== idx) selectAndActivate(rows[next].key);
    else select(activeKey); // ensure visual selection after lazy loads
  }

  function handleKeydown(ev) {
    if (!activeKey) return;
    const row = rowByKey.get(activeKey.path);
    const expanded = row && row.dataset.expanded === 'true';
    const hasKids = activeKey.subkeyCount > 0;

    switch (ev.key) {
      case 'ArrowDown':
        ev.preventDefault();
        moveSelection(1);
        break;
      case 'ArrowUp':
        ev.preventDefault();
        moveSelection(-1);
        break;
      case 'ArrowRight':
        ev.preventDefault();
        if (hasKids && !expanded) {
          expand(activeKey, row);
        } else if (hasKids && expanded) {
          const kids = activeKey.getSubkeys();
          if (kids.length > 0) selectAndActivate(kids[0]);
        }
        break;
      case 'ArrowLeft':
        ev.preventDefault();
        if (hasKids && expanded) {
          collapse(activeKey, row);
        } else if (activeKey.parent) {
          selectAndActivate(activeKey.parent);
        }
        break;
      case 'Enter':
      case ' ':
        ev.preventDefault();
        if (hasKids) toggle(activeKey, row);
        break;
      case 'Home':
        ev.preventDefault();
        moveSelectionTo(0);
        break;
      case 'End':
        ev.preventDefault();
        moveSelectionTo(-1);
        break;
      default:
        break;
    }
  }

  function moveSelectionTo(index) {
    const rows = visibleRows();
    if (rows.length === 0) return;
    const target = index === -1 ? rows.length - 1 : index;
    selectAndActivate(rows[target].key);
  }

  function init() {
    if (container) container.addEventListener('keydown', handleKeydown);
  }

  RV.ui.tree = { render, select, reveal, expand, collapse, init, handleKeydown, visibleRows, moveSelection };
})(window.RV);
