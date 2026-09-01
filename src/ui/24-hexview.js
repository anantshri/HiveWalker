// rv.ui — slide-over hex viewer for binary values, windowed for big blobs.
(function (RV) {
  'use strict';

  const PAGE = 512; // bytes per rendered window
  let pane = null;
  let current = null;

  function ensurePane() {
    if (pane) return pane;
    pane = document.createElement('div');
    pane.id = 'hex-pane';
    pane.hidden = true;
    document.body.appendChild(pane);

    const title = document.createElement('div');
    title.className = 'hex-title';
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = '✕';
    close.className = 'hex-close';
    close.title = 'Close (Esc)';
    close.addEventListener('click', hide);
    pane.appendChild(title);
    pane.appendChild(close);

    const body = document.createElement('div');
    body.className = 'hex-body';
    pane.appendChild(body);

    const more = document.createElement('button');
    more.type = 'button';
    more.textContent = 'Show more';
    more.className = 'hex-more';
    more.addEventListener('click', () => {
      if (!current) return;
      current.shown = Math.min(current.shown + PAGE, current.bytes.length);
      renderBody();
    });
    pane.appendChild(more);
    return pane;
  }

  function renderBody() {
    if (!current) return;
    const body = pane.querySelector('.hex-body');
    const vm = RV.ui.viewModel.hexRows(current.bytes, { to: current.shown });
    body.textContent = '';
    const pre = document.createElement('pre');
    const head = 'offset    ' + ' '.repeat(0) + 'hex'.padEnd(48) + 'ascii\n';
    pre.textContent = head + vm.map((r) => `${r.offsetHex}  ${r.hex.padEnd(47)} ${r.ascii}`).join('\n');
    body.appendChild(pre);
    const moreBtn = pane.querySelector('.hex-more');
    moreBtn.hidden = current.shown >= current.bytes.length;
  }

  /**
   * @param {string} title
   * @param {{name:string, size:number}} row — the table row that was clicked
   */
  function show(title, row) {
    ensurePane();
    // The caller passes the live VkValue's raw bytes via app state.
    const key = RV.ui.app.state.selectedKey;
    const value = key && key.getValue(row.name === '(Default)' ? '' : row.name);
    if (!value) return;
    current = { bytes: value.getRawData(), shown: PAGE };
    pane.querySelector('.hex-title').textContent = `${title} — ${row.size} bytes`;
    pane.hidden = false;
    renderBody();
  }

  function hide() {
    if (pane) pane.hidden = true;
    current = null;
  }

  RV.ui.hexview = { show, hide };
})(window.RV);
