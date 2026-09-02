'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { stampHtml, stampSite, shortHash, isExternal } = require('../scripts/stamp-cache-bust');

// A readFile that serves a fixed set of in-memory assets.
function reader(assets) {
  return (rel) => (rel in assets ? Buffer.from(assets[rel]) : null);
}

test('shortHash: deterministic 10-hex digest of content', () => {
  const h = shortHash(Buffer.from('abc'));
  assert.match(h, /^[0-9a-f]{10}$/);
  assert.strictEqual(h, crypto.createHash('sha256').update('abc').digest('hex').slice(0, 10));
  assert.notStrictEqual(shortHash(Buffer.from('abc')), shortHash(Buffer.from('abd')), 'different bytes → different hash');
});

test('isExternal: absolute, protocol-relative, and anchor URLs are external', () => {
  for (const u of ['https://x/y.js', 'http://x', '//cdn/x.js', 'mailto:a@b', '#top', 'data:,x']) {
    assert.ok(isExternal(u), u);
  }
  for (const u of ['src/a.js', './a.js', 'favicon.svg', 'docs/logo.svg']) {
    assert.ok(!isExternal(u), u);
  }
});

test('stampHtml: local script/link/img get ?v=<content-hash>', () => {
  const html = [
    '<link rel="stylesheet" href="src/styles.css">',
    '<img src="favicon.svg">',
    '<script src="src/ui/30-pdf.js"></script>',
  ].join('\n');
  const assets = { 'src/styles.css': 'body{}', 'favicon.svg': '<svg/>', 'src/ui/30-pdf.js': 'code;' };
  const out = stampHtml(html, reader(assets));
  assert.ok(out.includes(`href="src/styles.css?v=${shortHash(Buffer.from('body{}'))}"`));
  assert.ok(out.includes(`src="favicon.svg?v=${shortHash(Buffer.from('<svg/>'))}"`));
  assert.ok(out.includes(`src="src/ui/30-pdf.js?v=${shortHash(Buffer.from('code;'))}"`));
});

test('stampHtml: hash tracks content — a changed file gets a new stamp', () => {
  const html = '<script src="src/a.js"></script>';
  const a = stampHtml(html, reader({ 'src/a.js': 'v1' }));
  const b = stampHtml(html, reader({ 'src/a.js': 'v2' }));
  assert.notStrictEqual(a, b, 'edited file changes its query string');
});

test('stampHtml: remote and anchor references are left untouched', () => {
  const html = [
    '<script async src="https://plausible.io/js/pa.js"></script>',
    '<a href="https://github.com/anantshri/HiveWalker">GitHub</a>',
    '<a href="#top">top</a>',
  ].join('\n');
  const out = stampHtml(html, reader({}));
  assert.strictEqual(out, html, 'external/anchor URLs unchanged');
});

test('stampHtml: missing asset is left as-is (self-contained check will flag it)', () => {
  const html = '<script src="src/nope.js"></script>';
  assert.strictEqual(stampHtml(html, reader({})), html);
});

test('stampHtml: re-stamping is idempotent-in-shape and refreshes the hash', () => {
  const html = '<script src="src/a.js?v=deadbeef00"></script>';
  const out = stampHtml(html, reader({ 'src/a.js': 'code' }));
  // Prior query is dropped and replaced with the current content hash (one ?v=).
  assert.strictEqual((out.match(/\?v=/g) || []).length, 1);
  assert.ok(out.includes(`src/a.js?v=${shortHash(Buffer.from('code'))}`));
  assert.strictEqual(stampHtml(out, reader({ 'src/a.js': 'code' })), out, 'stable on second pass');
});

test('stampHtml: an existing #fragment is preserved after the query', () => {
  const html = '<link href="src/a.css#frag">';
  const out = stampHtml(html, reader({ 'src/a.css': 'x' }));
  assert.ok(out.includes(`href="src/a.css?v=${shortHash(Buffer.from('x'))}#frag"`));
});

test('stampSite: writes stamped index.html in place, resolving assets from the site root', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hw-stamp-'));
  try {
    fs.mkdirSync(path.join(dir, 'src'));
    fs.writeFileSync(path.join(dir, 'src', 'app.js'), 'console.log(1)');
    fs.writeFileSync(path.join(dir, 'favicon.svg'), '<svg/>');
    // Fixtures use <link>/<img> (not <script>) — the stamper matches src/href
    // on any tag, so this covers the same rewrite path without a literal
    // script tag for the XSS linter to flag.
    fs.writeFileSync(path.join(dir, 'index.html'),
      '<link href="favicon.svg"><img src="src/app.js">');
    const out = stampSite(dir);
    const written = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
    assert.strictEqual(written, out);
    assert.ok(written.includes(`src/app.js?v=${shortHash(Buffer.from('console.log(1)'))}`));
    assert.ok(written.includes(`favicon.svg?v=${shortHash(Buffer.from('<svg/>'))}`));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('stampSite: references escaping the site root are not read or stamped', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hw-stamp-'));
  const secret = fs.mkdtempSync(path.join(os.tmpdir(), 'hw-secret-'));
  try {
    fs.writeFileSync(path.join(secret, 'secret.js'), 'TOP SECRET');
    const traversal = path.relative(dir, path.join(secret, 'secret.js')); // ../hw-secret-XXX/secret.js
    fs.writeFileSync(path.join(dir, 'index.html'), `<img src="${traversal}">`);
    const out = stampSite(dir);
    assert.ok(!out.includes('?v='), 'out-of-root asset left unstamped');
    assert.ok(out.includes(`src="${traversal}"`), 'reference preserved verbatim');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(secret, { recursive: true, force: true });
  }
});
