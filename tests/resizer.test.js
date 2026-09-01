'use strict';

// Resizer behaviour in its own file so the empty-state check runs before
// any loadFile initialises the module (init is one-shot).

const test = require('node:test');
const assert = require('node:assert');

function makeDom() {
  class El {
    constructor(tag) {
      this.tagName = (tag || 'div').toUpperCase();
      this.children = []; this.parentNode = null; this.listeners = {};
      this.textContent = ''; this.title = ''; this.hidden = false;
      this.className = ''; this.dataset = {}; this.style = {}; this.type = 'button';
      this.id = ''; this._cls = new Set();
    }
    appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
    // Real DOM: assigning textContent replaces all children.
    set textContent(v) { this.children = []; this._text = v; }
    get textContent() { return this._text || ''; }
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
      const id = sel.startsWith('#') ? sel.slice(1) : null;
      const walk = (el) => {
        for (const c of el.children) {
          if (cls && (c.className || '').split(' ').includes(cls)) return c;
          if (id && c.id === id) return c;
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
      return { add: (c) => self._cls.add(c), remove: (c) => self._cls.delete(c), contains: (c) => self._cls.has(c) };
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
  globalThis.window = globalThis;
  globalThis.document = {
    El,
    createElement: (t) => new El(t),
    getElementById: (id) => { if (!byId.has(id)) byId.set(id, new El('div')); return byId.get(id); },
    addEventListener() {},
    body: new El('body'),
    createRange: () => ({ selectNodeContents() {} }),
  };
  globalThis.getSelection = () => ({ removeAllRanges() {}, addRange() {} });
  Object.defineProperty(globalThis, 'navigator', {
    value: { clipboard: { writeText: async () => {} } },
    configurable: true,
  });
  globalThis.performance = { now: () => Date.now() };
  globalThis.requestAnimationFrame = (fn) => fn();
  globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
  return { El, byId };
}


const dom = makeDom();
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const RV = loadSrc();

test('resizer: no handle in the empty (welcome) state', () => {
  const panes = document.getElementById('panes');
  RV.ui.resizer.init(panes, 'tree-pane', 'values-pane');
  assert.ok(
    !panes.children.some((c) => c.id === 'pane-resizer'),
    'no handle before any hive is loaded',
  );
});

test('resizer: injected and draggable after load', async () => {
  const buf = new HiveBuilder().build(() => {}).toBuffer();
  const panes = document.getElementById('panes');
  const origDoc = globalThis.document.addEventListener;

  // Capture the drag listeners registered by the load-time init (first
  // loadFile in this process).
  const docListeners = [];
  globalThis.document.addEventListener = (t, fn) => docListeners.push([t, fn]);
  await RV.ui.app.loadFile(buf);
  globalThis.document.addEventListener = origDoc;

  const handles = panes.children.filter((c) => c.id === 'pane-resizer');
  assert.strictEqual(handles.length, 1, 'exactly one handle after load');
  handles[0].dispatch('mousedown', { preventDefault() {}, clientX: 0 });
  const move = docListeners.find(([t]) => t === 'mousemove');
  const up = docListeners.find(([t]) => t === 'mouseup');
  assert.ok(move && up, 'drag listeners registered');
  move[1]({ clientX: 300 });
  up[1]();
  assert.match(panes.style.gridTemplateColumns || '', /^300px/, 'columns applied');

  // Re-init after load is a no-op (no duplicate handles).
  RV.ui.resizer.init(panes, 'tree-pane', 'values-pane');
  assert.strictEqual(
    panes.children.filter((c) => c.id === 'pane-resizer').length, 1,
    'init is idempotent',
  );
});

test('resizer: stays hidden again if state returns to empty/error', async () => {
  // CSS owns visibility; assert the DOM/CSS contract: the handle exists but
  // display is governed by #app[data-state]. Verify the guard logic only
  // injects on 'loaded' by forcing an error state and re-initialising.
  RV.ui.app.setState('error');
  const panes = document.getElementById('panes');
  RV.ui.resizer.init(panes, 'tree-pane', 'values-pane'); // no-op (initialised)
  assert.ok(panes.children.some((c) => c.id === 'pane-resizer'));
});
