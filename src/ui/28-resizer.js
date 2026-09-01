// rv.ui — draggable divider between the tree and values panes. Width is
// persisted to localStorage when available (file:// may not have it).
(function (RV) {
  'use strict';

  const STORAGE_KEY = 'rv.treeWidth';
  const MIN_PX = 160;
  const MAX_RATIO = 0.8; // of the container width

  let initialised = false;

  function init(container, leftId, rightId) {
    if (!container) return;
    const left = document.getElementById(leftId);
    const right = document.getElementById(rightId);
    if (!left || !right) return;

    // Only inject the handle once the panes are (about to be) visible —
    // otherwise it dangles next to the welcome card before any hive loads.
    // The app state machine lives on #app (empty | loaded | error).
    const appEl = document.getElementById('app');
    if (appEl && appEl.dataset.state !== 'loaded') return;
    if (initialised) return;
    initialised = true;

    const handle = document.createElement('div');
    handle.id = 'pane-resizer';
    handle.title = 'Drag to resize';
    container.insertBefore(handle, right);

    // Restore persisted width.
    let width = null;
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) width = Math.max(MIN_PX, parseInt(saved, 10) || 0);
    } catch { /* localStorage unavailable on some file:// setups */ }
    if (width) apply(width, container);

    let dragging = false;

    handle.addEventListener('mousedown', (ev) => {
      dragging = true;
      ev.preventDefault();
      document.body.classList.add('resizing');
    });

    document.addEventListener('mousemove', (ev) => {
      if (!dragging) return;
      const rect = container.getBoundingClientRect();
      const max = Math.floor(rect.width * MAX_RATIO);
      const w = Math.min(max, Math.max(MIN_PX, ev.clientX - rect.left));
      apply(w, container);
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      document.body.classList.remove('resizing');
      try {
        localStorage.setItem(STORAGE_KEY, String(currentWidth(container)));
      } catch { /* ignore */ }
    });

    // Double-click resets to the default (CSS-driven) width.
    handle.addEventListener('dblclick', () => {
      container.style.gridTemplateColumns = '';
      try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
    });
  }

  function currentWidth(container) {
    const first = container.querySelector('#tree-pane');
    return first ? first.getBoundingClientRect().width : 0;
  }

  function apply(width, container) {
    container.style.gridTemplateColumns = `${Math.round(width)}px 6px 1fr`;
  }

  RV.ui.resizer = { init };
})(window.RV);
