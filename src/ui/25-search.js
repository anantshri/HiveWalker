// rv.ui — debounced incremental search with grouped results.
(function (RV) {
  'use strict';

  const BATCH = 50;
  let timer = null;
  let controller = null;
  let resultsEl = null;

  function init(input, results, onHit) {
    resultsEl = results;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      const q = input.value.trim();
      if (q === '') {
        cancel();
        results.hidden = true;
        results.textContent = '';
        return;
      }
      timer = setTimeout(() => run(q, onHit), 200);
    });
    input.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') {
        input.value = '';
        cancel();
        results.hidden = true;
        results.textContent = '';
      }
    });
  }

  function cancel() {
    if (controller) controller.abort();
    controller = null;
    clearTimeout(timer);
  }

  function run(query, onHit) {
    cancel();
    const hive = RV.ui.app.state.hive;
    if (!hive) return;
    controller = new AbortController();
    resultsEl.hidden = false;
    resultsEl.textContent = '';
    const status = document.createElement('div');
    status.className = 'search-status';
    resultsEl.appendChild(status);

    const iter = hive.search({ query, signal: controller.signal, maxResults: 500 });
    const groups = new Map(); // key path -> hits
    let n = 0;
    let done = false;

    const step = () => {
      if (done) return;
      const t0 = performance.now();
      while (performance.now() - t0 < 16) {
        const { value, done: finished } = iter.next();
        if (finished) { done = true; break; }
        n++;
        const path = value.key.path;
        if (!groups.has(path)) groups.set(path, []);
        groups.get(path).push(value);
        if (n % BATCH === 0) render(status, groups, onHit);
      }
      render(status, groups, onHit);
      if (!done) requestAnimationFrame(step);
      else status.textContent = `${n} result${n === 1 ? '' : 's'} for “${query}”`;
    };
    requestAnimationFrame(step);
  }

  function render(status, groups, onHit) {
    // Rebuild the group list (fine for ≤500 results).
    const list = resultsEl.querySelector('.search-groups') || (() => {
      const g = document.createElement('div');
      g.className = 'search-groups';
      resultsEl.appendChild(g);
      return g;
    })();
    list.textContent = '';
    for (const [path, hits] of groups) {
      const group = document.createElement('div');
      group.className = 'search-group';
      const head = document.createElement('button');
      head.type = 'button';
      head.className = 'search-path';
      head.textContent = path;
      head.addEventListener('click', () => onHit(hits[0].key));
      group.appendChild(head);
      for (const hit of hits) {
        const row = document.createElement('div');
        row.className = 'search-hit hit-' + hit.field;
        const where = hit.field === 'key' ? 'key'
          : hit.field === 'valueName' ? 'value name' : 'data';
        row.textContent = `${where}: ${hit.text}`;
        row.addEventListener('click', () => onHit(hit.key));
        group.appendChild(row);
      }
      list.appendChild(group);
    }
    status.textContent = 'searching…';
  }

  RV.ui.search = { init };
})(window.RV);
