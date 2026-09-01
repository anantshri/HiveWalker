// rv — browser entry: wire the file input, drag-drop, search, panes, and
// keyboard navigation.
(function (RV) {
  'use strict';

  const $ = (id) => document.getElementById(id);

  function filesOf(ev) {
    if (!ev.target.files && !ev.dataTransfer) return [];
    const list = ev.target.files || (ev.dataTransfer && ev.dataTransfer.files);
    return list ? Array.from(list) : [];
  }

  $('file-input').addEventListener('change', (ev) => {
    const files = filesOf(ev);
    if (files.length > 0) RV.ui.app.loadFiles(files);
    ev.target.value = ''; // allow re-selecting the same file later
  });

  // Attach additional hives to the running session (cross-hive reports).
  $('add-file-input').addEventListener('change', (ev) => {
    const files = filesOf(ev);
    if (files.length > 0) RV.ui.app.addHives(files);
    ev.target.value = '';
  });

  // Show the + Add button once a session exists.
  const app = RV.ui.app;
  const syncAddBtn = () => { $('add-btn').hidden = app.state.hives.length === 0; };
  RV.plugins.session.onAttach(syncAddBtn);
  RV.plugins.session.onDetach(syncAddBtn);

  // Switch the viewed (primary) hive from the dropdown.
  $('hive-select').addEventListener('change', (ev) => {
    if (ev.target.value) app.setPrimaryHive(ev.target.value);
  });

  // Drag-drop anywhere on the page: several files at once replace the
  // session; a single file appends when a session is already open.
  document.addEventListener('dragover', (ev) => {
    ev.preventDefault();
    document.body.classList.add('dragging');
  });
  document.addEventListener('dragleave', () => document.body.classList.remove('dragging'));
  document.addEventListener('drop', (ev) => {
    ev.preventDefault();
    document.body.classList.remove('dragging');
    const files = ev.dataTransfer && ev.dataTransfer.files ? Array.from(ev.dataTransfer.files) : [];
    if (files.length === 0) return;
    if (files.length > 1 || RV.plugins.session.hives().length === 0) {
      RV.ui.app.loadFiles(files);
    } else {
      RV.ui.app.addHives(files);
    }
  });

  // Search
  RV.ui.search.init($('search-input'), $('search-results'), (key) => {
    $('search-results').hidden = true;
    RV.ui.app.navigateTo(key);
  });

  // Hive metadata panel (toggle open/closed via the top-bar button)
  $('meta-btn').addEventListener('click', () => RV.ui.hivemeta.toggle());

  // Workspace tabs: Viewer / Reports.
  $('tab-viewer').addEventListener('click', () => RV.ui.app.setTab('viewer'));
  $('tab-reports').addEventListener('click', () => RV.ui.app.setTab('reports'));

  // Tree keyboard navigation (tree pane is focusable; also works globally
  // when no input has focus, so arrows work right after a mouse click).
  RV.ui.tree.init();
  document.addEventListener('keydown', (ev) => {
    const t = ev.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
    RV.ui.tree.handleKeydown(ev);
  });

  // Keyboard: Escape closes overlays (and returns from Reports to Viewer).
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      RV.ui.hexview.hide();
      RV.ui.hivemeta.hide();
      if (RV.ui.app.currentTab() === 'reports') {
        RV.ui.app.setTab('viewer');
      } else {
        $('search-results').hidden = true;
      }
    }
  });

  // Keyboard: Ctrl/Cmd+1 → Viewer, Ctrl/Cmd+2 → Reports.
  document.addEventListener('keydown', (ev) => {
    if (!(ev.ctrlKey || ev.metaKey)) return;
    if (ev.key === '1') { ev.preventDefault(); RV.ui.app.setTab('viewer'); }
    if (ev.key === '2') { ev.preventDefault(); RV.ui.app.setTab('reports'); }
  });
})(window.RV);
