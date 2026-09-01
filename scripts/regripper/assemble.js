#!/usr/bin/env node
// RegRipper descriptor assembler — step 3 of the pipeline
// (see docs/regripper-plugins.md).
//
// Merges every /tmp/rr_desc_*.json produced by extraction (agents and/or
// scripts/regripper/extract.js), validates shape/hive/mode, dedups against the
// bespoke plugin names registered in src/plugins/40-43, and (re)generates
// src/plugins/50-descriptors.js. Rejected entries and skip reasons are dumped
// to /tmp/rr_rejected.json and /tmp/rr_skips.json.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const ROOT = path.resolve(__dirname, '..', '..');

// Bespoke plugin names are read from the 4x registrations rather than
// hard-coded, so the dedup set stays in sync with the source.
const DONE = new Set();
for (const f of fs.readdirSync(path.join(ROOT, 'src', 'plugins')).sort()) {
  if (!/^4[0-9]-.+\.js$/.test(f)) continue;
  const s = fs.readFileSync(path.join(ROOT, 'src', 'plugins', f), 'utf8');
  for (const m of s.matchAll(/name:\s*'([a-z0-9_]+)'/g)) DONE.add(m[1]);
}
const VALID_MODES = new Set(['values', 'named', 'subkeys', 'mru']);
const KNOWN_HIVES = new Set(['system', 'software', 'ntuser', 'usrclass', 'sam', 'security', 'amcache', 'bcd']);

let all = [];
const skips = [];
const batchFiles = fs.readdirSync('/tmp').filter((f) => /^rr_desc_\d+\.json$/.test(f)).sort();
if (batchFiles.length === 0) console.error('no /tmp/rr_desc_*.json found — run extraction first');
for (const bf of batchFiles) {
  const p = `/tmp/${bf}`;
  let arr;
  try { arr = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { console.error('BAD JSON', p, e.message); continue; }
  for (const d of arr) {
    if (d && d.skip) { skips.push(d); continue; }
    all.push(d);
  }
}

const seen = new Set(DONE);
const good = [];
const rejected = [];
for (const d of all) {
  const why = [];
  if (!d || typeof d.name !== 'string' || !d.name) why.push('no name');
  else if (seen.has(d.name)) why.push('duplicate/collision');
  if (d && (!Array.isArray(d.hives) || d.hives.length === 0)) why.push('no hives');
  if (d && Array.isArray(d.hives)) for (const h of d.hives) if (!KNOWN_HIVES.has(h)) why.push('bad hive ' + h);
  if (d && !Array.isArray(d.paths)) why.push('no paths');
  if (d && d.paths && d.paths.length === 0) why.push('empty paths');
  const mode = d && (d.mode || 'values');
  if (d && !VALID_MODES.has(mode)) why.push('bad mode ' + d.mode);
  if (mode === 'named' && (!Array.isArray(d.names) || d.names.length === 0)) why.push('named without names');
  if (why.length) { rejected.push({ name: d && d.name, why: why.join(', ') }); continue; }
  // Normalise: keep only known fields.
  const clean = { name: d.name, hives: d.hives, category: d.category || '', mitre: d.mitre || '',
    version: String(d.version || ''), shortDescr: d.shortDescr || '', mode: mode, paths: d.paths };
  if (d.ccs) clean.ccs = true;
  if (mode === 'named') clean.names = d.names;
  if (mode === 'subkeys' && Array.isArray(d.subkeyNames) && d.subkeyNames.length) clean.subkeyNames = d.subkeyNames;
  good.push(clean);
  seen.add(d.name);
}

good.sort((a, b) => a.name.localeCompare(b.name));

const header = `// rv.plugins — auto-imported RegRipper "simple" plugin descriptors.
// Generated from RegRipper 4.0 plugins that follow regular key/value/subkey
// read patterns (no bespoke binary decoding, no user intervention). Each entry
// is data consumed by RV.plugins.simple (see 32-simple.js). Bespoke plugins
// live in 40-43; binary-decoder plugins are a separate follow-up.
// RegRipper is by H. Carvey (keydet89) — https://github.com/keydet89/RegRipper4.0
// (RR 3.0: MIT; RR 4.0: personal/academic use only — see NOTICE.md)
(function (RV) {
  'use strict';
  RV.plugins.simple.registerAll(`;
const footer = `);
})(window.RV);
`;
fs.writeFileSync(path.join(ROOT, 'src', 'plugins', '50-descriptors.js'),
  header + JSON.stringify(good, null, 2) + footer);

console.log('descriptors accepted:', good.length);
console.log('rejected (validation):', rejected.length);
console.log('skipped by agents:', skips.length);
fs.writeFileSync('/tmp/rr_rejected.json', JSON.stringify(rejected, null, 2));
fs.writeFileSync('/tmp/rr_skips.json', JSON.stringify(skips, null, 2));
