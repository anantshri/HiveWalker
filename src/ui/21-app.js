// rv.ui — app orchestration: file loading, selection state, pane wiring.
(function (RV) {
  'use strict';

  const app = {
    hive: null,
    fileName: '',
    selectedKey: null,
    counts: null,
  };

  function $(id) { return document.getElementById(id); }

  function setState(state) {
    document.getElementById('app').dataset.state = state;
  }

  function showPanes() {
    for (const id of ['tree-pane', 'values-pane', 'statusbar']) $(id).hidden = false;
    $('meta-btn').hidden = false;
    $('search-input').disabled = false;
    $('welcome').hidden = true;
    $('error-card').hidden = true;
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

  /** Load a File (browser) or Uint8Array (tests). */
  async function loadFile(file) {
    try {
      const buf = file instanceof Uint8Array ? file : new Uint8Array(await file.arrayBuffer());
      app.hive = RV.reg.openHive(buf);
      app.fileName = file instanceof Uint8Array ? '(buffer)' : file.name;
      app.counts = null;
      $('file-name').textContent = app.fileName;
      $('file-name').title = app.hive.meta.fileName || '';
      setState('loaded');
      showPanes();
      RV.ui.resizer.init($('panes'), 'tree-pane', 'values-pane');
      RV.ui.tree.render($('tree-pane'), app.hive, selectKey);
      selectKey(app.hive.getRootKey());
      RV.ui.statusbar.update(app);
    } catch (e) {
      app.hive = null;
      showError(`${e.name}: ${e.message}`);
    }
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
    selectKey,
    navigateTo,
    setState,
    currentState,
    showError,
  };
})(window.RV);
