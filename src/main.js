// rv — browser entry: wire the file input, drag-drop, search, panes, and
// keyboard navigation.
(function (RV) {
  'use strict';

  const $ = (id) => document.getElementById(id);

  $('file-input').addEventListener('change', (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (file) RV.ui.app.loadFile(file);
  });

  // Drag-drop anywhere on the page.
  document.addEventListener('dragover', (ev) => {
    ev.preventDefault();
    document.body.classList.add('dragging');
  });
  document.addEventListener('dragleave', () => document.body.classList.remove('dragging'));
  document.addEventListener('drop', (ev) => {
    ev.preventDefault();
    document.body.classList.remove('dragging');
    const file = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
    if (file) RV.ui.app.loadFile(file);
  });

  // Search
  RV.ui.search.init($('search-input'), $('search-results'), (key) => {
    $('search-results').hidden = true;
    RV.ui.app.navigateTo(key);
  });

  // Hive metadata panel (toggle open/closed via the top-bar button)
  $('meta-btn').addEventListener('click', () => RV.ui.hivemeta.toggle());

  // Tree keyboard navigation (tree pane is focusable; also works globally
  // when no input has focus, so arrows work right after a mouse click).
  RV.ui.tree.init();
  document.addEventListener('keydown', (ev) => {
    const t = ev.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
    RV.ui.tree.handleKeydown(ev);
  });

  // Keyboard: Escape closes overlays.
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      RV.ui.hexview.hide();
      RV.ui.hivemeta.hide();
      $('search-results').hidden = true;
    }
  });
})(window.RV);
