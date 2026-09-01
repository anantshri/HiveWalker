// rv.ui — Reports workspace: the full-width "Reports" tab. A filterable plugin
// rail on the left, a toolbar (Run all / Copy report / Export PDF) and the
// result cards on the right. Tab switching lives in 21-app.js (setTab).
(function (RV) {
  'use strict';

  let lastResults = []; // results currently displayed (one or run-all)
  let filterText = '';

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function pane() { return document.getElementById('reports-tab'); }

  // Copy helper: clipboard with a select-the-text fallback (same pattern as
  // 23-values.js) for file:// where clipboard may be blocked.
  function makeCopyButton(getText, region) {
    const copy = el('button', 'path-copy', '⧉ Copy report');
    copy.type = 'button';
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(getText());
        copy.textContent = '✓ Copied';
      } catch {
        const range = document.createRange();
        range.selectNodeContents(region);
        const sel = window.getSelection();
        if (sel) { sel.removeAllRanges(); sel.addRange(range); }
        copy.textContent = 'Ctrl+C';
      }
      setTimeout(() => { copy.textContent = '⧉ Copy report'; }, 1200);
    });
    return copy;
  }

  /** Render one report result's sections into `container`. */
  function renderResult(container, result) {
    const view = RV.ui.viewModel.reportView(result);
    container.textContent = '';

    container.appendChild(el('h3', 'report-title', view.title));

    const meta = el('div', 'report-meta');
    view.meta.forEach(([k, v]) => {
      const chip = el('span', 'report-chip');
      chip.appendChild(el('span', 'report-chip-k', k));
      chip.appendChild(el('span', 'report-chip-v', String(v)));
      meta.appendChild(chip);
    });
    container.appendChild(meta);

    if (view.error) {
      container.appendChild(el('div', 'report-error', `${view.error.name}: ${view.error.message}`));
      return;
    }
    if (view.empty) {
      container.appendChild(el('div', 'report-empty', '(no data found)'));
      return;
    }

    for (const section of view.sections) {
      const sec = el('div', 'report-section');
      if (section.title) sec.appendChild(el('h4', null, section.title));
      for (const block of section.blocks) {
        if (block.kind === 'text') {
          const div = el('div', 'report-text');
          block.lines.forEach((l) => div.appendChild(el('div', null, l)));
          sec.appendChild(div);
        } else if (block.kind === 'note') {
          sec.appendChild(el('div', 'report-note', block.text));
        } else if (block.kind === 'kv') {
          const table = el('table', 'meta-table');
          block.pairs.forEach(([k, v]) => {
            const tr = el('tr');
            tr.appendChild(el('th', null, k));
            tr.appendChild(el('td', null, v));
            table.appendChild(tr);
          });
          sec.appendChild(table);
        } else if (block.kind === 'table') {
          const table = el('table', 'values-table');
          const thead = el('thead');
          const hr = el('tr');
          block.columns.forEach((c) => hr.appendChild(el('th', null, c)));
          thead.appendChild(hr);
          table.appendChild(thead);
          const tbody = el('tbody');
          block.rows.forEach((row) => {
            const tr = el('tr');
            row.forEach((cell) => tr.appendChild(el('td', null, cell)));
            tbody.appendChild(tr);
          });
          table.appendChild(tbody);
          sec.appendChild(table);
        }
      }
      container.appendChild(sec);
    }
  }

  function showResults(results) {
    lastResults = results;
    const output = document.getElementById('report-output');
    if (!output) return;
    output.textContent = '';
    if (results.length === 0) {
      output.appendChild(el('div', 'report-placeholder',
        'No report run yet — pick a plugin from the list, or "Run all applicable".'));
      return;
    }
    results.forEach((res) => {
      const box = el('div', 'report-result');
      renderResult(box, res);
      output.appendChild(box);
    });
  }

  function exportPdf() {
    if (lastResults.length === 0) return;
    const name = lastResults.length === 1
      ? lastResults[0].plugin
      : 'all-' + lastResults.length + 'plugins';
    RV.ui.pdf.downloadReportPdf(lastResults, name);
  }

  /** (Re)build the whole workspace for the currently loaded hive. */
  function render() {
    const hive = RV.ui.app.state.hive;
    const p = pane();
    if (!hive || !p) return;
    p.textContent = '';

    // --- Left rail: filter + plugin list ---
    const rail = el('aside', null);
    rail.id = 'reports-rail';

    const head = el('div', 'report-rail-head');
    head.appendChild(el('h2', null, 'Reports'));
    const filter = el('input');
    filter.id = 'report-filter';
    filter.type = 'search';
    filter.placeholder = 'Filter plugins…';
    filter.autocomplete = 'off';
    filter.spellcheck = false;
    filter.value = filterText;
    filter.addEventListener('input', () => {
      filterText = filter.value;
      renderList();
    });
    head.appendChild(filter);

    const list = RV.ui.viewModel.pluginList(hive);
    head.appendChild(el('p', 'report-detected',
      `Detected hive type(s): ${list.detectedTypes.join(', ')}`));
    rail.appendChild(head);

    const scroll = el('div');
    scroll.id = 'report-plugin-scroll';

    function renderList() {
      scroll.textContent = '';
      const needle = filterText.trim().toLowerCase();
      const ul = el('ul', 'report-plugin-list');
      const items = needle === ''
        ? list.plugins
        : list.plugins.filter((pl) => {
          const hay = `${pl.name} ${pl.shortDescr} ${pl.category} ${pl.mitre || ''}`.toLowerCase();
          return hay.includes(needle);
        });
      items.forEach((pl) => {
        const li = el('li', pl.applicable ? 'report-plugin applicable' : 'report-plugin');
        const btn = el('button', 'report-plugin-btn');
        btn.type = 'button';
        const row1 = el('span', 'row1');
        row1.appendChild(el('span', 'report-plugin-name', pl.name));
        if (pl.category) row1.appendChild(el('span', 'report-badge', pl.category));
        if (pl.mitre) row1.appendChild(el('span', 'report-badge mitre', pl.mitre));
        btn.appendChild(row1);
        btn.appendChild(el('span', 'report-plugin-descr', pl.shortDescr));
        btn.title = pl.applicable
          ? `Run ${pl.name}`
          : `Run ${pl.name} (hive type ${pl.hiveTypes.join('/')} not detected — run anyway)`;
        btn.addEventListener('click', () => {
          showResults([RV.plugins.runtime.run(pl.name, hive, { session: RV.plugins.session })]);
        });
        li.appendChild(btn);
        ul.appendChild(li);
      });
      if (items.length === 0) ul.appendChild(el('li', 'report-placeholder', '(no plugins match)'));
      scroll.appendChild(ul);
    }
    renderList();
    rail.appendChild(scroll);
    p.appendChild(rail);

    // --- Main column: toolbar + output ---
    const main = el('div');
    main.id = 'report-main';

    const controls = el('div', 'report-controls');
    const runAllBtn = el('button', 'report-run-all', 'Run all applicable');
    runAllBtn.type = 'button';
    runAllBtn.addEventListener('click', () => {
      const controller = new AbortController();
      const { results } = RV.plugins.runtime.runAll(hive, { signal: controller.signal, session: RV.plugins.session });
      showResults(results);
    });
    controls.appendChild(runAllBtn);

    const pdfBtn = el('button', 'report-export-pdf', '⇩ Export PDF');
    pdfBtn.type = 'button';
    pdfBtn.title = 'Download the displayed report(s) as a PDF';
    pdfBtn.addEventListener('click', exportPdf);
    controls.appendChild(pdfBtn);

    controls.appendChild(el('span', 'spacer'));
    const output = el('div', 'report-output');
    controls.appendChild(makeCopyButton(
      () => RV.ui.viewModel.reportTextAll(lastResults), output));
    main.appendChild(controls);

    main.appendChild(output);
    output.id = 'report-output';
    p.appendChild(main);

    showResults(lastResults);
  }

  /**
   * Mark displayed results stale after a session change (hive attached or
   * removed). Cross-hive plugins (SAM hash decryption, LSA secrets) may now
   * have more data than the last run saw. Prompt instead of silently
   * re-running — deterministic and testable.
   */
  function invalidate() {
    if (lastResults.length === 0) { render(); return; }
    const output = document.getElementById('report-output');
    if (!output) return;
    const note = el('div', 'report-note session-note',
      'Session changed (hive attached/removed) — re-run to refresh cross-hive results such as SAM hash decryption.');
    output.insertBefore(note, output.firstChild);
  }

  RV.ui.reports = { render, showResults, invalidate };
})(window.RV);
