'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');

test('scaffold: index.html lists classic scripts that exist on disk', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { scriptSourcesFromIndex, ROOT } = require('./helpers/load-src');
  for (const src of scriptSourcesFromIndex()) {
    const abs = path.join(ROOT, src);
    assert.ok(fs.existsSync(abs), `${src} referenced by index.html is missing`);
  }
});

test('scaffold: loading app scripts populates RV namespace', () => {
  const RV = loadSrc();
  assert.ok(RV && typeof RV === 'object', 'RV namespace exists');
});
