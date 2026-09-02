#!/usr/bin/env node
'use strict';

// Cache-busting stamper for the static site.
//
// The app ships as ~50 unbundled classic scripts loaded straight from
// index.html. Browsers (and the GitHub Pages CDN) cache each file
// independently, so a new release can leave a browser running a *mix* of old
// and new files — exactly the failure that produced a blank PDF export (the
// PDF writer's object-numbering was updated but the cached copy computed the
// page tree the old way).
//
// The fix: give every locally-referenced asset a `?v=<content-hash>` query
// string. The hash changes iff the file's bytes change, so browsers re-fetch
// precisely the files that were modified and can never blend versions.
//
// This runs at *deploy time* against the assembled `_site` — the working-tree
// index.html stays clean (readable diffs; the test loader reads plain paths).
//
// Usage: node scripts/stamp-cache-bust.js <site-dir>

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/** Short, stable content hash for a file's bytes. */
function shortHash(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex').slice(0, 10);
}

/** True for anything we must not stamp: absolute URLs, protocol-relative, anchors. */
function isExternal(url) {
  return url.startsWith('#') || url.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(url);
}

/**
 * Rewrite every local `src="…"` / `href="…"` in `html` to carry a
 * `?v=<hash>` query string derived from the referenced file's content.
 *
 * @param {string} html
 * @param {(relPath: string) => (Buffer|Uint8Array|null)} readFile
 *   Resolves an asset path (query/fragment already stripped) to its bytes,
 *   or null when it is missing / outside the site (left unstamped).
 * @returns {string}
 */
function stampHtml(html, readFile) {
  return html.replace(/\b(src|href)="([^"]+)"/gi, (whole, attr, url) => {
    if (isExternal(url)) return whole;
    // Split the raw value into base path, existing query, and fragment.
    let base = url;
    let frag = '';
    const h = base.indexOf('#');
    if (h >= 0) { frag = base.slice(h); base = base.slice(0, h); }
    const q = base.indexOf('?');
    if (q >= 0) base = base.slice(0, q); // drop any prior ?v= so re-stamping is idempotent
    if (!base) return whole;
    const buf = readFile(base);
    if (buf == null) return whole; // missing asset — leave it for the self-contained check to flag
    return `${attr}="${base}?v=${shortHash(buf)}${frag}"`;
  });
}

/**
 * Stamp `<siteDir>/index.html` in place. Assets are resolved relative to the
 * site root and confined to it (a stray `../` reference is treated as missing,
 * never read from outside the published tree).
 * @returns {string} the stamped HTML that was written
 */
function stampSite(siteDir) {
  const root = path.resolve(siteDir);
  const indexPath = path.join(root, 'index.html');
  const html = fs.readFileSync(indexPath, 'utf8');
  const readFile = (rel) => {
    const p = path.resolve(root, rel);
    if (p !== root && !p.startsWith(root + path.sep)) return null; // stay inside the site
    try { return fs.readFileSync(p); } catch { return null; }
  };
  const out = stampHtml(html, readFile);
  fs.writeFileSync(indexPath, out);
  return out;
}

if (require.main === module) {
  const dir = process.argv[2];
  if (!dir) {
    process.stderr.write('usage: stamp-cache-bust.js <site-dir>\n');
    process.exit(2);
  }
  stampSite(dir);
  process.stdout.write(`stamped ${path.join(dir, 'index.html')}\n`);
}

module.exports = { stampHtml, stampSite, shortHash, isExternal };
