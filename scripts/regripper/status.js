#!/usr/bin/env node
// RegRipper porting-status refresh — regenerates docs/regripper-plugin-status.json
// from the current source of truth: the corpus (/tmp/rr_analysis.json — run
// analyze.js first), the bespoke plugins in src/plugins/40-43, and the
// descriptors in src/plugins/50-descriptors.js. Skip reasons are taken from
// /tmp/rr_desc_*.json when present (they carry the extraction-time reasons).
// See docs/regripper-plugins.md.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');

// Bespoke plugin names, parsed from the 4x-<hive>.js registrations.
const bespoke = [];
for (const f of fs.readdirSync(path.join(ROOT, 'src', 'plugins')).sort()) {
  if (!/^(3[0-9]|4[0-9])-.+\.js$/.test(f)) continue;
  const s = fs.readFileSync(path.join(ROOT, 'src', 'plugins', f), 'utf8');
  for (const m of s.matchAll(/name:\s*'([a-z0-9_]+)'/g)) bespoke.push(m[1]);
}

// Descriptors from the generated file.
const descSrc = fs.readFileSync(path.join(ROOT, 'src', 'plugins', '50-descriptors.js'), 'utf8');
const descMap = new Map(JSON.parse(descSrc.slice(descSrc.indexOf('['), descSrc.lastIndexOf(']') + 1))
  .map((d) => [d.name, d]));

// Skip reasons from the extraction batches, when still on disk.
const skipMap = new Map();
for (let i = 0; i < 64; i++) {
  const p = `/tmp/rr_desc_${i}.json`;
  if (!fs.existsSync(p)) continue;
  try {
    for (const d of JSON.parse(fs.readFileSync(p, 'utf8'))) if (d && d.skip) skipMap.set(d.name, d.reason || '');
  } catch { /* malformed batch — ignore */ }
}

const rows = JSON.parse(fs.readFileSync('/tmp/rr_analysis.json', 'utf8'));
const out = [];
for (const r of rows) {
  const name = r.f.replace(/\.pl$/, '');
  if (r.tln) { out.push({ name, hive: r.hive, status: 'excluded', note: '_tln output-format duplicate' }); continue; }
  const e = { name, hive: r.hive, category: r.cat, output: r.output };
  if (bespoke.includes(name)) {
    e.status = 'done-bespoke';
  } else if (descMap.has(name)) {
    e.status = 'done-descriptor';
    e.mode = descMap.get(name).mode;
  } else if (skipMap.has(name)) {
    e.status = 'deferred';
    e.reason = skipMap.get(name);
  } else if (r.unpack > 0) {
    e.status = 'deferred';
    e.reason = 'binary decoder (uses unpack)';
  } else {
    e.status = 'deferred';
    e.reason = 'not yet processed';
  }
  out.push(e);
}
out.sort((a, b) => a.name.localeCompare(b.name));
fs.writeFileSync(path.join(ROOT, 'docs', 'regripper-plugin-status.json'), JSON.stringify(out, null, 1) + '\n');

const counts = {};
out.forEach((e) => { counts[e.status] = (counts[e.status] || 0) + 1; });
console.log('regripper-plugin-status.json refreshed:', JSON.stringify(counts));
