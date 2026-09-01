// rv.ui — app orchestration: file loading, selection state, pane wiring.
// Supports a multi-hive session (e.g. SAM + SYSTEM together) for plugins
// that need cross-hive data; the viewer/search panes always bind to the
// primary hive, switchable from the topbar dropdown.
(function (RV) {
  'use strict';

  const app = {
    hive: null,        // primary RegfHive (what the viewer shows)
    hives: [],         // session entries: {id, hive, fileName, types}
    fileName: '',
    selectedKey: null,
    counts: null,
  };

  const session = RV.plugins.session;

  function $(id) { return document.getElementById(id); }

  function setState(state) {
    document.getElementById('app').dataset.state = state;
  }

  function showPanes() {
    for (const id of ['tree-pane', 'values-pane', 'statusbar']) $(id).hidden = false;
    $('meta-btn').hidden = false;
    $('tabbar').hidden = false;
    $('search-input').disabled = false;
    $('welcome').hidden = true;
    $('error-card').hidden = true;
    RV.ui.reports.render(); // populate the Reports tab workspace for this hive
  }

  function showError(message) {
    setState('error');
    $('error-card').hidden = false;
    $('error-card').textContent = message;
  }

  /** App state machine: 'empty' (welcome) | 'loaded' | 'error'. */
  function currentState() {
    return document.getElementById('app').dataset.state;
  }

  /** Active workspace tab: 'viewer' | 'reports'. */
  function currentTab() {
    const t = document.getElementById('app').dataset.tab;
    return t === 'reports' ? 'reports' : 'viewer';
  }

  /**
   * Switch the main workspace tab. Both tabs stay in the DOM (hidden via CSS)
   * so viewer state — expansion, selection, scroll — persists across switches.
   */
  function setTab(name) {
    const tab = name === 'reports' ? 'reports' : 'viewer';
    document.getElementById('app').dataset.tab = tab;
    const active = document.getElementById('tab-' + tab);
    if (active) active.setAttribute('aria-selected', 'true');
    const other = document.getElementById(tab === 'viewer' ? 'tab-reports' : 'tab-viewer');
    if (other) other.setAttribute('aria-selected', 'false');
    // Topbar search is viewer-scoped; the Reports rail has its own filter.
    document.getElementById('search-input').disabled = currentState() !== 'loaded' || tab === 'reports';
    if (tab === 'reports') RV.ui.reports.render();
  }

  // ---- topbar session dropdown ------------------------------------------------

  function labelFor(entry) {
    const types = Array.from(entry.types).filter((t) => t !== 'unknown');
    const type = types.length ? types.join('/').toUpperCase() : 'HIVE';
    return `${type} — ${entry.fileName}`;
  }

  function refreshHiveSelect() {
    const select = $('hive-select');
    if (!select) return;
    select.textContent = '';
    for (const entry of app.hives) {
      const opt = document.createElement('option');
      opt.value = entry.id;
      opt.textContent = labelFor(entry);
      if (session.primary() && entry.id === session.primary().id) opt.selected = true;
      select.appendChild(opt);
    }
    select.hidden = app.hives.length === 0;
  }

  // ---- loading -----------------------------------------------------------------

  async function readBytes(file) {
    return file instanceof Uint8Array ? file : new Uint8Array(await file.arrayBuffer());
  }

  /**
   * Open one or more hive files. `{add:true}` appends to the session (the
   * "+ Add hive…" affordance); the default replaces it. The first entry of
   * the resulting session becomes the primary (viewed) hive. Returns the
   * entries that opened successfully; on total failure with replace-semantics
   * shows the error card as before.
   */
  async function loadFiles(files, opts) {
    const add = !!(opts && opts.add);
    const list = Array.isArray(files) ? files : [files];
    const opened = [];
    const failures = [];
    if (!add) session.clear();
    for (const file of list) {
      try {
        const buf = await readBytes(file);
        const hive = RV.reg.openHive(buf);
        const name = file instanceof Uint8Array ? '(buffer)' : file.name;
        opened.push(session.attach(hive, name));
      } catch (e) {
        failures.push(`${file instanceof Uint8Array ? '(buffer)' : file.name}: ${e.name}: ${e.message}`);
      }
    }
    if (opened.length === 0 && !add) {
      app.hive = null;
      app.hives = [];
      app.fileName = '';
      showError(failures.join('\n') || 'no hive could be opened');
      return [];
    }
    syncFromSession();
    const primary = session.primary();
    if (primary) {
      const wasEmpty = currentState() === 'empty';
      app.hive = primary.hive;
      app.fileName = primary.fileName;
      app.counts = null;
      setState('loaded');
      if (wasEmpty || !$('tree-pane') || $('tree-pane').hidden) showPanes();
      RV.ui.resizer.init($('panes'), 'tree-pane', 'values-pane');
      RV.ui.tree.render($('tree-pane'), app.hive, selectKey);
      selectKey(app.hive.getRootKey());
      RV.ui.statusbar.update(app);
    }
    RV.ui.reports.invalidate();
    return opened;
  }

  /** Back-compat single-file entry point (used by existing tests + e2e sim). */
  async function loadFile(file) {
    return loadFiles([file]);
  }

  /** Append hives to the session (the + Add hive… button / multi-drop). */
  function addHives(files) {
    return loadFiles(files, { add: true });
  }

  function syncFromSession() {
    app.hives = session.hives();
    refreshHiveSelect();
  }

  function removeHive(entryOrId) {
    session.remove(entryOrId);
    syncFromSession();
    const primary = session.primary();
    if (primary) {
      setPrimaryHive(primary.id);
    } else {
      app.hive = null;
      app.hives = [];
      app.fileName = '';
      app.selectedKey = null;
      setState('empty');
      $('welcome').hidden = false;
      $('tree-pane').hidden = true;
      $('values-pane').hidden = true;
      $('statusbar').hidden = true;
      $('tabbar').hidden = true;
    }
    RV.ui.reports.invalidate();
  }

  /** Switch which session entry the viewer/search/reports show. */
  function setPrimaryHive(entryOrId) {
    const entry = typeof entryOrId === 'object' ? entryOrId : session.hives().find((e) => e.id === entryOrId);
    if (!entry) return;
    session.setPrimary(entry);
    app.hive = entry.hive;
    app.fileName = entry.fileName;
    app.counts = null;
    refreshHiveSelect();
    RV.ui.tree.render($('tree-pane'), app.hive, selectKey);
    selectKey(app.hive.getRootKey());
    RV.ui.statusbar.update(app);
    RV.ui.reports.render();
  }

  function selectKey(key) {
    app.selectedKey = key;
    RV.ui.tree.select(key);
    RV.ui.values.render($('values-pane'), key);
    RV.ui.statusbar.update(app);
  }

  /** Expand the tree along a path and select the final key. */
  function navigateTo(key) {
    RV.ui.tree.reveal(key);
    selectKey(key);
  }

  RV.ui.app = {
    state: app,
    loadFile,
    loadFiles,
    addHives,
    removeHive,
    setPrimaryHive,
    selectKey,
    navigateTo,
    setState,
    currentState,
    currentTab,
    setTab,
    showError,
  };
})(window.RV);
