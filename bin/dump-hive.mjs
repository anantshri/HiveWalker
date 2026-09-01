#!/usr/bin/env node
// dump-hive — CLI verification aid: dump a hive's tree as text or JSON.
// Loads the parser through the same index.html script list as the tests.
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import url from 'node:url';

const ROOT = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), '..');
const INDEX = path.join(ROOT, 'index.html');

function loadRV() {
  globalThis.window = globalThis;
  const html = fs.readFileSync(INDEX, 'utf8');
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const src = (m[1].match(/\bsrc=["']([^"']+)["']/i) || [])[1];
    if (!src) {
      vm.runInThisContext(m[2], { filename: '<index.html inline>' });
      continue;
    }
    if (/^[a-z]+:/i.test(src)) continue;
    if (!src.startsWith('src/reg/')) continue; // parser only — no UI in Node
    vm.runInThisContext(fs.readFileSync(path.join(ROOT, src), 'utf8'), {
      filename: path.join(ROOT, src),
    });
  }
  return globalThis.RV;
}

const RV = loadRV();

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const file = args.find((a) => !a.startsWith('--'));
if (!file) {
  console.error('usage: node bin/dump-hive.mjs <hive-file> [--json]');
  process.exit(2);
}
if (!fs.existsSync(file)) {
  console.error(`no such file: ${file}`);
  process.exit(2);
}

const buf = new Uint8Array(fs.readFileSync(file));
let hive;
try {
  hive = RV.reg.openHive(buf);
} catch (e) {
  console.error(`error: ${e.message}`);
  process.exit(1);
}

if (asJson) {
  const out = { meta: hive.toJSON().meta, warnings: hive.warnings, keys: [] };
  for (const key of hive.walk()) {
    out.keys.push({
      path: key.path,
      lastWrite: key.lastWrite.toString(),
      warnings: key.warnings,
      values: key.getValues().map((v) => ({
        name: v.displayName,
        type: v.typeName,
        size: v.dataSize,
        data: v.getDisplay().text,
      })),
    });
  }
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
} else {
  console.log(`hive: ${file}`);
  console.log(`  embedded name: ${hive.meta.fileName}`);
  console.log(`  version: ${hive.meta.majorVersion}  bins: ${hive.bins.length}  dirty: ${hive.meta.dirty}`);
  for (const w of hive.warnings) console.log(`  warning: ${w}`);
  console.log('');
  const keyCount = { n: 0 };
  for (const key of hive.walk()) {
    keyCount.n++;
    const ts = RV.reg.filetime.formatFiletime(key.lastWrite);
    console.log(`[${key.path}]  (${ts})`);
    for (const v of key.getValues()) {
      const d = v.getDisplay();
      console.log(`    ${v.displayName.padEnd(28)} ${v.typeName.padEnd(24)} ${d.text}`);
    }
    for (const w of key.warnings) console.log(`    !! ${w}`);
  }
  console.log(`\n${keyCount.n} keys`);
}
