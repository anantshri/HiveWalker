'use strict';

// Minimal but behaviour-faithful DOM stub for driving the browser UI under
// Node — enough of Element/document for tree/values/panels to render and for
// event handlers to fire via dispatch(). Extracted from e2e-ui-sim.js so both
// the standalone sim and node:test files share one implementation.

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
    setAttribute(k, v) { this['attr_' + k] = String(v); }
    getAttribute(k) { const v = this['attr_' + k]; return v === undefined ? null : v; }
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
  // A connected skeleton of the static elements index.html ships, so app code
  // resolves the same instances a browser would (renders attach into them).
  const seed = (parent, id, tag) => { const e = new El(tag || 'div'); e.id = id; parent.appendChild(e); return e; };
  const body = new El('body');
  const appEl = seed(body, 'app');
  appEl.dataset.state = 'empty';
  appEl.dataset.tab = 'viewer';
  const topbar = seed(appEl, 'topbar', 'header');
  seed(topbar, 'file-input', 'input');
  seed(topbar, 'add-btn', 'label');
  seed(topbar, 'add-file-input', 'input');
  const hiveSelect = seed(topbar, 'hive-select', 'select');
  hiveSelect.hidden = true;
  seed(topbar, 'file-name', 'span');
  seed(appEl, 'tabbar', 'nav');
  const viewerTab = seed(appEl, 'viewer-tab', 'main');
  const panes = seed(viewerTab, 'panes');
  seed(panes, 'welcome', 'div');
  seed(panes, 'error-card', 'div');
  seed(panes, 'tree-pane', 'nav');
  seed(panes, 'values-pane', 'section');
  seed(viewerTab, 'statusbar', 'footer');
  seed(appEl, 'search-results', 'div');
  seed(appEl, 'reports-tab', 'section');
  seed(appEl, 'page-footer', 'footer');
  // NOTE: #meta-pane / #hex-pane are intentionally NOT seeded — the real DOM
  // creates them lazily (26-hivemeta ensurePane / 24-hexview); seeding would
  // shadow the dynamically created instances.
  globalThis.document = {
    El,
    createElement: (t) => new El(t),
    // Like a browser: resolve by walking the connected tree; fall back to a
    // lazily-created placeholder for lookups of not-yet-rendered elements.
    getElementById(id) {
      const found = findIn(body, id);
      if (found) return found;
      if (byId.has(id)) return byId.get(id);
      const created = new El('div');
      byId.set(id, created);
      return created;
    },
    addEventListener() {},
    body,
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

  // PDF-export surface: Blob + object URLs + clickable download anchors.
  const downloads = []; // {name, type, bytes}
  globalThis.Blob = class Blob {
    constructor(parts, opts) {
      this.type = (opts && opts.type) || '';
      this.bytes = Buffer.concat(parts.map((p) => Buffer.from(p)));
    }
  };
  const urlCounter = { n: 0 };
  const urlBytes = new Map();
  globalThis.URL = globalThis.URL || {};
  globalThis.URL.createObjectURL = (blob) => {
    urlCounter.n += 1;
    urlBytes.set('blob:stub-' + urlCounter.n, blob);
    return 'blob:stub-' + urlCounter.n;
  };
  globalThis.URL.revokeObjectURL = (u) => { urlBytes.delete(u); };
  globalThis.__downloads = downloads;
  globalThis.__urlBytes = urlBytes;
  // El.click() on an <a href="blob:…"> records a download (for PDF export).
  El.prototype.click = function click() {
    if (this.tagName === 'A' && this.href && this.href.startsWith('blob:')) {
      const b = urlBytes.get(this.href);
      downloads.push({ name: this.download, type: b.type, bytes: b.bytes });
    }
  };
  return { El };
}

/** Depth-first search for an element by id (panels attach to document.body). */
function findIn(el, id) {
  for (const c of el.children) {
    if (c.id === id) return c;
    const r = findIn(c, id);
    if (r) return r;
  }
  return null;
}

module.exports = { makeDom, findIn };
