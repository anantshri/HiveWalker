// rv.ui — status bar: selection info + cancellable whole-hive count.
(function (RV) {
  'use strict';

  let countCtl = null;

  function update(app) {
    const bar = document.getElementById('statusbar');
    if (!bar) return;
    const vm = RV.ui.viewModel.statusBar(app.hive, app.selectedKey, app.counts);
    bar.textContent = vm.text;

    // One-time "count all" affordance.
    if (!bar.querySelector('#count-all')) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.id = 'count-all';
      btn.textContent = 'Count all keys';
      btn.addEventListener('click', () => countAll(app, btn));
      bar.appendChild(btn);
    }
  }

  function countAll(app, btn) {
    if (countCtl) { countCtl.abort(); countCtl = null; }
    countCtl = new AbortController();
    btn.disabled = true;
    btn.textContent = 'counting…';
    const iter = app.hive.walk({ signal: countCtl.signal });
    let keys = 0;
    let values = 0;
    const step = () => {
      const t0 = performance.now();
      while (performance.now() - t0 < 16) {
        const { value, done } = iter.next();
        if (done) {
          app.counts = { keys, values };
          btn.textContent = `done: ${keys.toLocaleString()} keys`;
          btn.disabled = false;
          update(app);
          return;
        }
        keys++;
        values += value.valueCount;
      }
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  RV.ui.statusbar = { update };
})(window.RV);
