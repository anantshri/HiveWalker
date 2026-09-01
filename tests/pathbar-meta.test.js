'use strict';

// Path bar + metadata-panel tests on the shared DOM stub.

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
const reg = RV.reg;

test('path bar: crumbs render one segment per path component', async () => {
  const buf = new HiveBuilder().build((r) => {
    r.key('Software').key('Microsoft').key('Windows');
  }).toBuffer();
  await RV.ui.app.loadFile(buf);
  const deep = RV.ui.app.state.hive.getSubkey(['Software', 'Microsoft', 'Windows'].join('\\'));
  assert.ok(deep);
  RV.ui.app.navigateTo(deep);

  const pane = document.getElementById('values-pane');
  const bar = pane.children[0];
  assert.strictEqual(bar.className, 'path-bar');
  const crumbs = bar.querySelector('.path-crumbs');
  const texts = crumbs.children.map((c) => c.textContent);
  assert.ok(texts.includes('root'));
  assert.ok(texts.includes('Software'));
  assert.ok(texts.includes('Microsoft'));
  assert.ok(texts.includes('Windows'));
  assert.ok(texts.includes('›'), 'separator present');
  const copy = bar.querySelector('.path-copy');
  assert.ok(copy, 'copy button present');
});

test('path bar: crumb click navigates to that ancestor', async () => {
  const buf = new HiveBuilder().build((r) => {
    r.key('A').key('B').key('C');
  }).toBuffer();
  await RV.ui.app.loadFile(buf);
  const c = RV.ui.app.state.hive.getSubkey(['A', 'B', 'C'].join('\\'));
  RV.ui.app.navigateTo(c);
  const pane = document.getElementById('values-pane');
  const crumbs = pane.children[0].querySelector('.path-crumbs');
  const aCrumb = crumbs.children.find((x) => x.textContent === 'A');
  aCrumb.dispatch('click');
  assert.ok(RV.ui.app.state.selectedKey.path.endsWith(['A'].join('\\')));
  assert.strictEqual(RV.ui.app.state.selectedKey.path.split('\\').length, 2);
});

test('meta panel: ✕ button closes it', async () => {
  const buf = new HiveBuilder().build(() => {}).toBuffer();
  await RV.ui.app.loadFile(buf);
  RV.ui.hivemeta.toggle();
  // ensurePane() creates its own element; find it via body
  const pane = findMetaPane();
  assert.ok(pane, 'meta pane exists');
  assert.strictEqual(pane.hidden, false, 'open');
  const close = pane.children.find((c) => c.className === 'panel-close');
  assert.ok(close, 'close button rendered');
  close.dispatch('click');
  assert.strictEqual(pane.hidden, true, 'closed');
});

function findMetaPane() {
  const walk = (el) => {
    for (const c of el.children) {
      if (c.id === 'meta-pane') return c;
      const r = walk(c); if (r) return r;
    }
    return null;
  };
  return walk(document.body);
}
