// rv.ui — hive metadata slide-over panel.
(function (RV) {
  'use strict';

  let pane = null;

  function ensurePane() {
    if (pane) return pane;
    pane = document.createElement('aside');
    pane.id = 'meta-pane';
    pane.hidden = true;
    document.body.appendChild(pane);
    return pane;
  }

  function toggle() {
    const p = ensurePane();
    p.hidden = !p.hidden;
    if (!p.hidden) render();
  }

  function hide() {
    if (pane) pane.hidden = true;
  }

  function render() {
    const hive = RV.ui.app.state.hive;
    if (!hive) return;
    const vm = RV.ui.viewModel.hiveMeta(hive);
    const p = ensurePane();
    p.textContent = '';

    // Explicit close affordance (Escape also works).
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'panel-close';
    close.textContent = '✕';
    close.title = 'Close (Esc)';
    close.addEventListener('click', hide);
    p.appendChild(close);

    const title = document.createElement('h2');
    title.textContent = vm.title;
    p.appendChild(title);

    const table = document.createElement('table');
    table.className = 'meta-table';
    for (const [k, v] of vm.rows) {
      const tr = document.createElement('tr');
      const th = document.createElement('th');
      th.textContent = k;
      const td = document.createElement('td');
      td.textContent = String(v);
      tr.appendChild(th);
      tr.appendChild(td);
      table.appendChild(tr);
    }
    p.appendChild(table);

    if (vm.warnings.length > 0) {
      const w = document.createElement('div');
      w.className = 'meta-warnings';
      vm.warnings.forEach((msg) => {
        const line = document.createElement('div');
        line.textContent = `⚠ ${msg}`;
        w.appendChild(line);
      });
      p.appendChild(w);
    }

    if (hive.meta.dirty) {
      const note = document.createElement('p');
      note.className = 'meta-note';
      note.textContent = 'This hive is “dirty”: its sequence numbers differ, so transaction-log entries were not fully applied. Transaction-log replay is out of scope for this viewer (matching RegRipper); consider yarp + registryFlush.py or rla.exe first.';
      p.appendChild(note);
    }
  }

  RV.ui.hivemeta = { toggle, hide, render };
})(window.RV);
