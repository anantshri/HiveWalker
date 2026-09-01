'use strict';

// Behavioral tests for tree keyboard navigation and click-to-open, using a
// minimal DOM stub (the tree binder needs a real-ish parentNode/children
// graph, which the load-src stub doesn't provide).

const test = require('node:test');
const assert = require('node:assert');

// -- tiny DOM ---------------------------------------------------------------
function makeDom() {
  class El {
    constructor(tag) {
      this.tagName = (tag || 'div').toUpperCase();
      this.children = [];
      this.parentNode = null;
      this.listeners = {};
      this.textContent = '';
      this.title = '';
      this.hidden = false;
      this.className = '';
      this.dataset = {};
      this.style = {};
      this.type = 'button';
      this._cls = new Set();
    }
    appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
    insertBefore(c, ref) {
      c.parentNode = this;
      const i = ref ? this.children.indexOf(ref) : -1;
      if (i >= 0) this.children.splice(i, 0, c); else this.children.push(c);
      return c;
    }
    addEventListener(t, fn) { (this.listeners[t] ||= []).push(fn); }
    dispatch(type, ev = {}) {
      for (const fn of this.listeners[type] || []) fn({ stopPropagation() {}, preventDefault() {}, ...ev });
    }
    querySelector(sel) {
      const cls = sel.startsWith('.') ? sel.slice(1) : null;
      const walk = (el) => {
        for (const c of el.children) {
          if (cls && (c.className || '').split(' ').includes(cls)) return c;
          const r = walk(c); if (r) return r;
        }
        return null;
      };
      return walk(this);
    }
    querySelectorAll(sel) {
      const cls = sel.startsWith('.') ? sel.slice(1) : null;
      const out = [];
      const walk = (el) => {
        for (const c of el.children) {
          if (cls && (c.className || '').split(' ').includes(cls)) out.push(c);
          walk(c);
        }
      };
      walk(this);
      return out;
    }
    remove() {
      if (this.parentNode) {
        const i = this.parentNode.children.indexOf(this);
        if (i >= 0) this.parentNode.children.splice(i, 1);
      }
    }
    get classList() {
      const self = this;
      return {
        add: (c) => self._cls.add(c),
        remove: (c) => self._cls.delete(c),
        contains: (c) => self._cls.has(c),
      };
    }
    set colSpan(_v) {}
    scrollIntoView() {}
    getBoundingClientRect() { return { left: 0, width: 600 }; }
    get nextSibling() {
      if (!this.parentNode) return null;
      const i = this.parentNode.children.indexOf(this);
      return this.parentNode.children[i + 1] || null;
    }
  }
  const byId = new Map();
  return {
    El,
    createElement: (t) => new El(t),
    getElementById: (id) => {
      if (!byId.has(id)) byId.set(id, new El('div'));
      return byId.get(id);
    },
    addEventListener() {},
    body: new El('body'),
    _byId: byId,
  };
}

const dom = makeDom();
globalThis.window = globalThis;
globalThis.document = dom;

const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const RV = loadSrc();
const reg = RV.reg;

// Tree: root → [AppEvents, Console(2 kids), Software]
//                     Console → [ColorDesk, Fonts]
function buildTree() {
  const buf = new HiveBuilder().build((r) => {
    r.key('AppEvents');
    r.key('Console').key('ColorDesk').key('Fonts');
    r.key('Software');
  }).toBuffer();
  return reg.openHive(buf);
}

function setup() {
  const hive = buildTree();
  const treeEl = dom.createElement('div');
  const selected = [];
  RV.ui.tree.render(treeEl, hive, (k) => selected.push(k.path));
  RV.ui.tree.init(); // attaches keydown handling, as main.js does
  return { hive, treeEl, selected };
}

function key(el, k) {
  el.dispatch('keydown', { key: k });
}

test('tree: clicking a row with children opens it (selects first)', () => {
  const { treeEl, selected } = setup();
  const consoleRow = treeEl.children.find((r) => r.dataset.path.endsWith('Console'));
  assert.ok(consoleRow, 'Console row rendered');
  assert.strictEqual(consoleRow.dataset.expanded, undefined); // not open yet
  consoleRow.dispatch('click');
  assert.strictEqual(consoleRow.dataset.expanded, 'true', 'opened on click');
  assert.ok(selected.at(-1).endsWith('Console'), 'selected too');
  // children now visible
  const paths = treeEl.querySelectorAll('.tree-row').map((r) => r.dataset.path);
  assert.ok(paths.some((p) => p.endsWith('ColorDesk')), 'child rendered');
});

test('tree: clicking an open row closes it', () => {
  const { treeEl } = setup();
  const consoleRow = treeEl.children.find((r) => r.dataset.path.endsWith('Console'));
  consoleRow.dispatch('click'); // open
  consoleRow.dispatch('click'); // close
  assert.strictEqual(consoleRow.dataset.expanded, 'false');
  const paths = treeEl.querySelectorAll('.tree-row').map((r) => r.dataset.path);
  assert.ok(!paths.some((p) => p.endsWith('ColorDesk')), 'child removed');
});

test('tree: twisty click toggles without selecting', () => {
  const { treeEl, selected } = setup();
  const consoleRow = treeEl.children.find((r) => r.dataset.path.endsWith('Console'));
  const twisty = consoleRow.querySelector('.twisty');
  twisty.dispatch('click');
  assert.strictEqual(consoleRow.dataset.expanded, 'true');
  assert.strictEqual(selected.length, 0, 'no selection from twisty');
});

test('tree: ArrowDown moves to the next visible row', () => {
  const { treeEl, selected } = setup();
  // root is active after render
  key(treeEl, 'ArrowDown');
  assert.ok(selected.at(-1).endsWith('AppEvents'));
  key(treeEl, 'ArrowDown');
  assert.ok(selected.at(-1).endsWith('Console'));
  key(treeEl, 'ArrowDown');
  assert.ok(selected.at(-1).endsWith('Software'));
});

test('tree: ArrowDown skips collapsed children', () => {
  const { treeEl, selected } = setup();
  key(treeEl, 'ArrowDown');
  key(treeEl, 'ArrowDown'); // Console
  key(treeEl, 'ArrowDown'); // must skip its collapsed children → Software
  assert.ok(selected.at(-1).endsWith('Software'));
});

test('tree: ArrowRight opens, then enters; ArrowLeft closes, then to parent', () => {
  const { treeEl, selected } = setup();
  key(treeEl, 'ArrowDown');
  key(treeEl, 'ArrowDown'); // Console
  key(treeEl, 'ArrowRight'); // open
  const consoleRow = treeEl.children.find((r) => r.dataset.path.endsWith('Console'));
  assert.strictEqual(consoleRow.dataset.expanded, 'true');
  key(treeEl, 'ArrowRight'); // enter first child
  assert.ok(selected.at(-1).endsWith('ColorDesk'));
  key(treeEl, 'ArrowLeft'); // no children → parent
  assert.ok(selected.at(-1).endsWith('Console'));
  key(treeEl, 'ArrowLeft'); // has children, open → collapse
  assert.strictEqual(consoleRow.dataset.expanded, 'false');
});

test('tree: ArrowUp walks back up', () => {
  const { treeEl, selected } = setup();
  key(treeEl, 'End');
  assert.ok(selected.at(-1).endsWith('Software'));
  key(treeEl, 'ArrowUp');
  assert.ok(selected.at(-1).endsWith('Console'));
  key(treeEl, 'Home');
  assert.strictEqual(selected.at(-1).split('\\').length, 1, 'root selected');
});

test('tree: Enter toggles the active row', () => {
  const { treeEl } = setup();
  key(treeEl, 'ArrowDown');
  key(treeEl, 'ArrowDown'); // Console
  key(treeEl, 'Enter');
  const consoleRow = treeEl.children.find((r) => r.dataset.path.endsWith('Console'));
  assert.strictEqual(consoleRow.dataset.expanded, 'true');
});

test('tree: collapse moves the active key out of the closing branch', () => {
  const { treeEl, selected } = setup();
  const consoleRow = treeEl.children.find((r) => r.dataset.path.endsWith('Console'));
  consoleRow.dispatch('click'); // open + select
  key(treeEl, 'ArrowRight'); // into ColorDesk
  assert.ok(selected.at(-1).endsWith('ColorDesk'));
  consoleRow.dispatch('click'); // close the branch…
  key(treeEl, 'ArrowDown'); // …active must be Console, so next is Software
  assert.ok(selected.at(-1).endsWith('Software'));
});
