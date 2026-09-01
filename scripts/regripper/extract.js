#!/usr/bin/env node
// RegRipper heuristic descriptor extractor — step 2 (fallback) of the pipeline
// (see docs/regripper-plugins.md).
//
// Conservative parser for "simple" plugins: pulls %config metadata reliably,
// detects ccs/mode/paths/names, and SKIPS anything ambiguous (runtime-assembled
// paths, unpack, nested descent, path fragments) rather than emit a wrong
// descriptor. A wrong path only degrades to "not found" at runtime, never a
// crash — but under-coverage is the price of fidelity. Preferred extraction
// route is subagents reading the Perl (higher fidelity); this is the
// budget-free fallback.
//
// Usage: node scripts/regripper/extract.js [batch-ids…]   (default: 2 4 5)
// Reads /tmp/rr_batch_<id>.txt (see analyze.js --batches), writes
// /tmp/rr_desc_<id>.json.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const DIR = path.resolve(__dirname, '..', '..', 'supporting', 'RegRipper4.0', 'plugins');

function mapHive(hraw) {
  const tags = [];
  for (let part of String(hraw).split(',')) {
    part = part.trim().toLowerCase().replace(/\\/g, '');
    if (!part) continue;
    if (/^ntuser/.test(part)) tags.push('ntuser');
    else if (/^usrclass/.test(part)) tags.push('usrclass');
    else if (/^system/.test(part)) tags.push('system');
    else if (/^software/.test(part)) tags.push('software');
    else if (/^sam/.test(part)) tags.push('sam');
    else if (/^security/.test(part)) tags.push('security');
    else if (/^amcache/.test(part)) tags.push('amcache');
    else if (/^bcd/.test(part)) tags.push('bcd');
    else if (/^all$/.test(part)) return null; // 'all' → skip
    else tags.push(part);
  }
  return [...new Set(tags)];
}

// Collapse Perl double-quoted "\\x" escapes to single backslash; strip leading \.
function normPath(s) {
  return s.replace(/\\\\/g, '\\').replace(/^\\+/, '').replace(/\\+$/, '');
}

function quotedStrings(block) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g;
  let m;
  while ((m = re.exec(block)) !== null) out.push(m[1] !== undefined ? m[1] : m[2]);
  return out;
}

function extract(name) {
  const src = fs.readFileSync(`${DIR}/${name}.pl`, 'latin1');
  const skip = (reason) => ({ name, skip: true, reason });

  if (/unpack\(/.test(src)) return skip('binary unpack');
  // Runtime-assembled paths (var concatenation beyond the ccs/current prefix)
  // produce fragments under a literal-only heuristic — skip for fidelity.
  const bodyEarly = (src.match(/sub\s+pluginmain\s*\{([\s\S]*)/) || [null, src])[1];
  if (/\.\s*\$(?!ccs\b|current\b)\w+\s*\.\s*['"]/.test(bodyEarly)) return skip('dynamic path assembly');
  if (/\$\w*path\w*\s*=\s*\$(?!ccs\b|current\b)\w+/.test(bodyEarly)) return skip('dynamic path assembly');

  const cfg = src.match(/%config\s*=\s*\(([\s\S]*?)\);/);
  const cfgTxt = cfg ? cfg[1] : '';
  // Hardcoded per-field regexes (no dynamic RegExp — keeps scanners happy and
  // the patterns auditable). Each matches `field => "value"` or a bare integer.
  const CFG_RES = {
    hive: /hive\s*=>\s*(?:"([^"]*)"|([0-9]+))/i,
    category: /category\s*=>\s*(?:"([^"]*)"|([0-9]+))/i,
    MITRE: /MITRE\s*=>\s*(?:"([^"]*)"|([0-9]+))/i,
    version: /version\s*=>\s*(?:"([^"]*)"|([0-9]+))/i,
  };
  const grab = (k) => {
    const m = cfgTxt.match(CFG_RES[k]);
    return m ? (m[1] !== undefined ? m[1] : m[2]) : '';
  };
  const hives = mapHive(grab('hive'));
  if (!hives || hives.length === 0) return skip('hive all/unknown');

  const category = grab('category').toLowerCase();
  const mitre = grab('MITRE').replace(/\\/g, '');
  const version = (grab('version') || '').replace(/[^0-9]/g, '') || '0';
  let shortDescr = '';
  const sd = src.match(/sub\s+getShortDescr\s*\{[\s\S]*?return\s*("([^"]*)"|'([^']*)')/);
  if (sd) shortDescr = (sd[2] !== undefined ? sd[2] : sd[3]).replace(/\\/g, '');

  const body = (src.match(/sub\s+pluginmain\s*\{([\s\S]*)/) || [null, src])[1];

  // ControlSet resolution?
  const ccs = /getCCS|get_value\("Current"\)|"ControlSet00"|\$ccs/.test(body);

  // Candidate paths.
  const paths = new Set();
  // $var = "..."/'...' path assignments (key_path, path, etc.)
  for (const m of body.matchAll(/\$\w*(?:key_)?path\w*\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*;/g)) {
    paths.add(m[1]);
  }
  // @paths = ( ... ) / @keys = ( ... )
  for (const m of body.matchAll(/@(?:paths|keys)\s*=\s*\(([\s\S]*?)\)\s*;/g)) {
    for (const q of quotedStrings(m[1])) paths.add(`"${q}"`);
  }
  // $ccs."..."  or  $current."..."
  for (const m of body.matchAll(/\$(?:ccs|current)\s*\.\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g)) {
    paths.add(m[1]);
  }
  // get_subkey("literal-with-backslash")
  for (const m of body.matchAll(/get_subkey\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\)/g)) {
    const raw = m[1];
    if (/\\/.test(raw)) paths.add(raw); // only path-like (has a backslash)
  }

  // Convert captured quoted literals → normalised path strings.
  const pathList = [];
  for (const q of paths) {
    const dq = q[0] === '"';
    let inner = q.slice(1, -1);
    if (dq) inner = inner; // normPath collapses \\
    let p = normPath(inner).trim();
    // discard obvious non-paths / control-set leftovers / value names
    if (!p || p === 'Select' || /^ControlSet/i.test(p)) continue;
    if (/(^|\\)\s*$/.test(p) || /\\\s*\\/.test(p)) continue; // trailing/empty component → fragment
    if (!/[\\]/.test(p) && p.length < 3) continue;
    pathList.push(p);
  }
  const uniqPaths = [...new Set(pathList)];
  if (uniqPaths.length === 0) return skip('no path detected');

  // Mode detection.
  const hasSubkeys = /get_list_of_subkeys/.test(body);
  const hasValues = /get_list_of_values/.test(body);
  const hasMru = /MRUListEx|MRUList/.test(body);
  // count get_subkey calls — >1 hints nested descent (skip those under subkeys)
  const subkeyCalls = (body.match(/get_subkey\(/g) || []).length;

  let mode, names, subkeyNames;
  if (hasMru) {
    mode = 'mru';
  } else if (hasSubkeys) {
    mode = 'subkeys';
    // nested descent inside the subkey loop → not representable; skip.
    // Heuristic: get_subkey called more times than we have candidate paths.
    if (subkeyCalls > uniqPaths.length) return skip('nested subkey descent');
    const gv = [...body.matchAll(/get_value\(\s*"([^"]*)"\s*\)/g)].map((m) => m[1]).filter((n) => n && n !== 'Current');
    subkeyNames = [...new Set(gv)].slice(0, 12);
  } else if (hasValues) {
    mode = 'values';
  } else {
    // specific named values only
    const gv = [...body.matchAll(/get_value\(\s*"([^"]*)"\s*\)/g)].map((m) => m[1]).filter((n) => n && n !== 'Current');
    if (gv.length === 0) return skip('no values/subkeys/named reads detected');
    mode = 'named';
    names = [...new Set(gv)];
  }

  // If any data decode markers appear, prefer to skip for fidelity.
  if (/decode|tr\/|=~\s*s\/|parseGUID|getTime|format8601Date\([^)]*get_value/.test(body) && mode !== 'subkeys' && mode !== 'values') {
    // (values/subkeys just dump raw data — decode markers there are cosmetic;
    //  for named/mru a decode usually means transformed output → skip.)
    if (mode === 'named' || mode === 'mru') return skip('data decode/transform');
  }

  const d = { name, hives, category, mitre, version, shortDescr, mode, paths: uniqPaths };
  if (ccs) d.ccs = true;
  if (mode === 'named') d.names = names;
  if (mode === 'subkeys' && subkeyNames && subkeyNames.length) d.subkeyNames = subkeyNames;
  return d;
}

const batchIds = process.argv.slice(2).map((a) => parseInt(a, 10)).filter(Number.isInteger);
for (const b of (batchIds.length ? batchIds : [2, 4, 5])) {
  const list = fs.readFileSync(`/tmp/rr_batch_${b}.txt`, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
  const out = list.map((n) => { try { return extract(n); } catch (e) { return { name: n, skip: true, reason: 'parse error: ' + e.message }; } });
  fs.writeFileSync(`/tmp/rr_desc_${b}.json`, JSON.stringify(out, null, 2));
  const desc = out.filter((d) => !d.skip).length;
  console.log(`batch ${b}: ${desc} descriptors, ${out.length - desc} skipped`);
}
