'use strict';
// E2E simulation of the new UI features (not a node:test file — run directly).
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
}
makeDom();

const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const RV = loadSrc();

(async () => {
  const buf = new HiveBuilder().build((r) => {
    r.key('Software').key('Microsoft').value('Ver', 1, '1.0');
  }).toBuffer();

  // 0) empty state: no resizer handle before any load
  const panes0 = document.getElementById('panes');
  RV.ui.resizer.init(panes0, 'tree-pane', 'values-pane');
  console.log('0. no handle in empty state:', !panes0.children.some((c) => c.id === 'pane-resizer'));

  await RV.ui.app.loadFile(buf);
  const app = RV.ui.app.state;
  console.log('loaded:', !!app.hive, '| selected:', app.selectedKey.path);

  // 1) click-to-open
  const treePane = document.getElementById('tree-pane');
  const swRow = treePane.querySelectorAll('.tree-row').find((r) => r.dataset.path.endsWith('Software'));
  swRow.dispatch('click');
  console.log('1. click-to-open expanded:', swRow.dataset.expanded === 'true');
  const msRow = treePane.querySelectorAll('.tree-row').find((r) => r.dataset.path.endsWith('Microsoft'));
  console.log('   child visible after click:', !!msRow);

  // 2) resizer appears only after load (app.showPanes initialises it)
  const panes = document.getElementById('panes');
  console.log('2. resizer present after load:', panes.children.some((c) => c.id === 'pane-resizer'));

  // 3) path bar
  RV.ui.app.navigateTo(app.hive.getSubkey('Software\\Microsoft'));
  const pane = document.getElementById('values-pane');
  const bar = pane.children[0];
  const crumbs = bar.querySelector('.path-crumbs');
  console.log('3. path bar:', bar.className === 'path-bar',
    '| crumbs:', crumbs.children.map((c) => c.textContent).join(''));

  // 4) keyboard nav
  RV.ui.tree.init();
  treePane.dispatch('keydown', { key: 'ArrowDown' });
  console.log('4. ArrowDown selected:', app.selectedKey.path);

  // 5) meta panel close (ensurePane attaches to document.body, not byId)
  RV.ui.hivemeta.toggle();
  const metaPane = findIn(document.body, 'meta-pane');
  console.log('5. meta open (hidden=false):', metaPane.hidden === false);
  const closeBtn = metaPane.children.find((c) => c.className === 'panel-close');
  closeBtn.dispatch('click');
  console.log('   closed via ✕ (hidden=true):', metaPane.hidden === true);
})().catch((e) => { console.error('FAIL:', e); process.exit(1); });

function findIn(el, id) {
  for (const c of el.children) {
    if (c.id === id) return c;
    const r = findIn(c, id);
    if (r) return r;
  }
  return null;
}
