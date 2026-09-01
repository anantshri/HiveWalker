#!/usr/bin/env node
// RegRipper corpus analyser — step 1 of the descriptor pipeline
// (see docs/regripper-plugins.md).
//
// Parses every plugin in supporting/RegRipper4.0/plugins: %config metadata,
// unpack usage (binary decoders), heavy modules, and _tln variants. Writes
// /tmp/rr_analysis.json and prints the corpus breakdown. With --batches N,
// also writes the not-yet-ported "simple" plugin list chunked into
// /tmp/rr_batch_N.txt files for extraction.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DIR = path.resolve(__dirname, '..', '..', 'supporting', 'RegRipper4.0', 'plugins');
const DONE = new Set(['compname', 'timezone', 'shutdown', 'services', 'usbstor', 'ips', 'mountdev',
  'winver', 'uninstall', 'run', 'profilelist', 'networkcards', 'userassist', 'recentdocs',
  'typedpaths', 'runmru', 'samparse']);

const rows = [];
for (const f of fs.readdirSync(DIR).filter((f) => f.endsWith('.pl')).sort()) {
  const s = fs.readFileSync(path.join(DIR, f), 'latin1');
  const g = (re) => { const m = s.match(re); return m ? m[1].trim() : ''; };
  const uses = [...s.matchAll(/^use\s+([A-Za-z0-9_:]+)/gm)].map((m) => m[1])
    .filter((u) => !['strict', 'warnings', 'vars'].includes(u));
  rows.push({
    f,
    hive: g(/hive\s*=>\s*"([^"]*)"/i).toLowerCase(),
    output: g(/output\s*=>\s*"([^"]*)"/i).toLowerCase() || 'report',
    cat: g(/category\s*=>\s*"([^"]*)"/i).toLowerCase(),
    unpack: (s.match(/unpack\(/g) || []).length,
    uses: uses.join('|'),
    tln: /_tln\.pl$/.test(f),
  });
}
fs.writeFileSync('/tmp/rr_analysis.json', JSON.stringify(rows));

const tln = rows.filter((r) => r.tln).length;
const nonTln = rows.filter((r) => !r.tln);
const simple = nonTln.filter((r) => r.unpack === 0 && (r.uses === '' || r.uses === 'Encode' || r.uses === 'Encode::Unicode'));
const byOutput = {};
rows.forEach((r) => { byOutput[r.output] = (byOutput[r.output] || 0) + 1; });

console.log('total:', rows.length, '| _tln:', tln, '| report plugins:', nonTln.length);
console.log('by output:', JSON.stringify(byOutput));
console.log('simple (no unpack/heavy modules):', simple.length,
  '| binary-decoder (unpack):', nonTln.length - simple.length);

if (process.argv.includes('--batches')) {
  const n = parseInt((process.argv[process.argv.indexOf('--batches') + 1] || '6'), 10);
  const todo = simple.map((r) => r.f.replace(/\.pl$/, '')).filter((nm) => !DONE.has(nm));
  const chunk = Math.ceil(todo.length / n);
  for (let i = 0; i < n; i++) {
    fs.writeFileSync(`/tmp/rr_batch_${i}.txt`, todo.slice(i * chunk, (i + 1) * chunk).join('\n'));
  }
  console.log(`not-yet-ported simple plugins: ${todo.length} → ${n} batches (/tmp/rr_batch_*.txt)`);
}
