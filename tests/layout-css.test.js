'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Static regression guards for the app-shell layout CSS. These encode two
// real rendering bugs that shipped with the tab refactor:
//   1. with auto-placement, a hidden #tabbar shifts #page-footer into the 1fr
//      row → footer eats half the screen on first open;
//   2. `#app[data-tab="reports"] #reports-tab { display: block }` outranked
//      the workspace grid rule → two-column layout never applied on the
//      Reports tab (no rail, nothing scrollable).
// A headless browser isn't available in this container, so we pin the CSS
// invariants directly.

const CSS = fs.readFileSync(path.resolve(__dirname, '..', 'src', 'styles.css'), 'utf8');

test('app shell: explicit grid-row placement keeps rows stable while #tabbar is hidden', () => {
  // grid-template-rows uses minmax(0,1fr) for the main row so it can shrink.
  assert.match(CSS, /#app\s*\{[^}]*grid-template-rows:\s*auto auto minmax\(0,\s*1fr\) auto/s);
  // Each shell element is pinned to its row — no auto-placement shifting.
  for (const sel of ['#topbar', '#tabbar', '#page-footer']) {
    const re = new RegExp(sel.replace('#', '#') + String.raw`\s*\{[^}]*grid-row:\s*\d`, 's');
    assert.ok(re.test(CSS), `${sel} has explicit grid-row`);
  }
  const mainRow = CSS.match(/#viewer-tab,\s*#reports-tab\s*\{[^}]*grid-row:\s*3/s);
  assert.ok(mainRow, 'both tabs pinned to grid-row 3');
});

test('reports tab: the active rule must set display:grid (not block)', () => {
  const active = CSS.match(/#app\[data-tab="reports"\]\s*#reports-tab\s*\{([^}]*)\}/s);
  assert.ok(active, 'active reports-tab rule exists');
  assert.match(active[1], /display:\s*grid/, 'active reports tab is a grid');
  // And it must not be defeated from elsewhere.
  assert.doesNotMatch(CSS, /#app\[data-tab="reports"\]\s*#reports-tab\s*\{[^}]*display:\s*block/s);
});

test('reports workspace: two columns with a shrinkable main and scroll on both sides', () => {
  // Several #reports-tab blocks exist (shell placement, visibility, workspace).
  // Find the one declaring the workspace columns.
  const blocks = [...CSS.matchAll(/#reports-tab\s*\{([^}]*)\}/gs)].map((m) => m[1]);
  const ws = blocks.find((b) => /grid-template-columns/.test(b));
  assert.ok(ws, 'workspace rule exists');
  assert.match(ws, /grid-template-columns:\s*300px minmax\(0,\s*1fr\)/, 'rail + shrinkable main');
  assert.match(ws, /overflow:\s*hidden/, 'tab clips its children');
  const rail = CSS.match(/#report-plugin-scroll\s*\{([^}]*)\}/s);
  assert.ok(rail && /overflow-y:\s*auto/.test(rail[1]), 'rail list scrolls');
  const main = CSS.match(/#report-main\s*\{([^}]*)\}/s);
  assert.ok(main && /overflow-y:\s*auto/.test(main[1]), 'results column scrolls');
  // The rail is a flex column that can shrink (so its scroll area engages).
  const railCol = CSS.match(/#reports-rail\s*\{([^}]*)\}/s);
  assert.ok(railCol && /min-height:\s*0/.test(railCol[1]), 'rail can shrink');
});

test('viewer tab: shrinkable panes row keeps statusbar visible', () => {
  const v = CSS.match(/#app\[data-tab="viewer"\]\s*#viewer-tab\s*\{([^}]*)\}/s);
  assert.ok(v, 'active viewer rule exists');
  assert.match(v[1], /grid-template-rows:\s*minmax\(0,\s*1fr\)\s*auto/, 'panes shrink, statusbar fixed');
  assert.match(v[1], /min-height:\s*0/, 'viewer tab can shrink inside the shell row');
});
