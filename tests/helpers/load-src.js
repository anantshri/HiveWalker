// Loads the app's classic scripts into Node exactly as the browser would:
// the ordered <script src> list is read from index.html itself, so the page
// stays the single source of truth for load order.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..', '..');
const INDEX_HTML = path.join(ROOT, 'index.html');

const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
const SRC_ATTR_RE = /\bsrc=["']([^"']+)["']/i;

/**
 * Every <script> in document order: inline bootstrap scripts (which create
 * the RV namespace, exactly as the browser runs them) and src scripts.
 * @returns {{src: string|null, code: string}[]}
 */
function scriptBlocksFromIndex() {
  const html = fs.readFileSync(INDEX_HTML, 'utf8');
  const blocks = [];
  let m;
  while ((m = SCRIPT_RE.exec(html)) !== null) {
    const srcMatch = m[1].match(SRC_ATTR_RE);
    const src = srcMatch ? srcMatch[1] : null;
    if (src && /^[a-z]+:/i.test(src)) continue; // skip remote scripts
    if (!src && m[2].trim() === '') continue;
    blocks.push({ src, code: m[2] });
  }
  if (!blocks.some((b) => b.src)) {
    throw new Error('no <script src> found in index.html');
  }
  return blocks;
}

/** @returns {string[]} src paths in document order */
function scriptSourcesFromIndex() {
  return scriptBlocksFromIndex().filter((b) => b.src).map((b) => b.src);
}

/**
 * Load the app's classic scripts. Without `only`, every script in index.html
 * runs (browser parity — requires all listed files to exist on disk).
 *
 * With `only`, src files are treated as ordered layers: everything up to and
 * including the last matching file loads. Later layers (and DOM-bound
 * main.js) are skipped, so early-layer tests don't need the whole UI present.
 *
 * @param {{only?: RegExp}} [opts]
 * @returns the RV namespace (globalThis.RV)
 */
function loadSrc(opts) {
  // Classic scripts reference `window.RV`; in Node the global object plays
  // that role (idempotent across repeated loads in one process).
  if (typeof globalThis.window === 'undefined') globalThis.window = globalThis;
  // Minimal document stub so DOM binders can load (not run) under Node.
  if (typeof globalThis.document === 'undefined') {
    const stubElement = () => ({
      addEventListener() {}, textContent: '', hidden: true, style: {}, dataset: {},
      appendChild() {}, insertBefore() {}, querySelector() { return stubElement(); },
      querySelectorAll() { return []; }, classList: { add() {}, remove() {} },
      getBoundingClientRect() { return { left: 0, width: 0 }; },
    });
    globalThis.document = {
      getElementById: stubElement,
      createElement: stubElement,
      addEventListener() {},
      body: stubElement(),
    };
  }
  const only = opts && opts.only;
  const blocks = scriptBlocksFromIndex();

  let cutoff = Infinity; // index of the last matching src block
  if (only) {
    let matched = -1;
    blocks.forEach((b, i) => {
      if (b.src && only.test(b.src)) matched = i;
    });
    if (matched === -1) throw new Error(`no script matches ${only}`);
    cutoff = matched;
  }

  blocks.forEach((block, i) => {
    if (i > cutoff) return;
    const abs = block.src ? path.join(ROOT, block.src) : '<index.html inline>';
    const code = block.src ? fs.readFileSync(abs, 'utf8') : block.code;
    vm.runInThisContext(code, { filename: abs });
  });

  if (typeof globalThis.RV !== 'object' || globalThis.RV === null) {
    throw new Error('RV namespace was not initialised');
  }
  return globalThis.RV;
}

module.exports = { loadSrc, scriptSourcesFromIndex, scriptBlocksFromIndex, ROOT };
