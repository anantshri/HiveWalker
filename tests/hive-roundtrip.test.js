'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { mulberry32 } = require('./helpers/mutate');

const reg = loadSrc({ only: /12-hive/ }).reg;

// ---------------------------------------------------------------------------
// Deterministic random trees → build → parse → deep-compare.

function randomTree(rng, depth) {
  // Returns a spec-builder function for a random subtree.
  const namePool = 'Key Node Value Data Test Horn Calf Osiris Delta Echo Foxtrot'.split(' ');
  const randName = () => namePool[Math.floor(rng() * namePool.length)] + Math.floor(rng() * 90 + 10);

  const randValue = () => {
    const kind = Math.floor(rng() * 6);
    switch (kind) {
      case 0: return { name: randName(), type: 1, data: randName() + ' value' };
      case 1: return { name: randName(), type: 4, data: Math.floor(rng() * 0xffffffff) };
      case 2: return { name: randName(), type: 11, data: BigInt(Math.floor(rng() * 1e15)) };
      case 3: return { name: randName(), type: 3, data: new Uint8Array(1 + Math.floor(rng() * 40)).map(() => Math.floor(rng() * 256)) };
      case 4: return { name: randName(), type: 7, data: [randName(), randName()] };
      default: return { name: randName(), type: 2, data: '%PATH%\\' + randName() };
    }
  };

  return function build(parent) {
    const nValues = Math.floor(rng() * 3);
    for (let i = 0; i < nValues; i++) {
      const v = randValue();
      parent.value(v.name, v.type, v.data);
    }
    if (depth <= 0) return;
    const nKids = Math.floor(rng() * 4); // 0..3
    for (let i = 0; i < nKids; i++) {
      const name = randName();
      parent.key(name, { lastWrite: BigInt(Math.floor(rng() * 2 ** 40)) }, randomTree(rng, depth - 1));
    }
  };
}

/** Collect the expected shape from a builder spec (independent of parsing). */
function specShape(key) {
  return {
    name: key.name,
    lastWrite: key.lastWrite,
    values: key.values.map((v) => ({ name: v.name, type: v.type, data: v.data })),
    children: key.children.map(specShape),
  };
}

/** Collect the parsed shape via the facade. */
function parsedShape(key) {
  return {
    name: key.name,
    lastWrite: key.lastWrite,
    values: key.getValues().map((v) => ({
      name: v.name,
      type: v.type,
      data: dataOf(v),
    })),
    children: key.getSubkeys().map(parsedShape),
  };
}

function dataOf(v) {
  const d = v.getData();
  switch (d.kind) {
    case 'string': return d.value;
    case 'multi': return d.value;
    case 'number': return typeof d.value === 'bigint' ? d.value : d.value >>> 0;
    case 'binary': return Array.from(d.value);
    default: return null;
  }
}

// The builder encodes expectations its own way; normalise both sides.
function normalise(v) {
  if (v.type === 3 || v.type === 0) return Array.from(v.data instanceof Uint8Array ? v.data : new Uint8Array(v.data ?? []));
  if (v.type === 11) return BigInt(v.data);
  if (v.type === 4 || v.type === 5) return Number(v.data) >>> 0;
  if (v.type === 7) return Array.isArray(v.data) ? v.data : [String(v.data)];
  return String(v.data ?? '');
}

for (const seed of [1, 2, 3, 42, 2026]) {
  for (const subkeyList of ['lf', 'lh', 'li', 'ri']) {
    test(`round-trip: seed ${seed}, subkeyList ${subkeyList}`, () => {
      const rng = mulberry32(seed * 31 + subkeyList.charCodeAt(0));
      const builder = new HiveBuilder({ subkeyList });
      builder.build(randomTree(rng, 4));
      const expected = specShape(builder.root);
      const hive = reg.openHive(builder.toBuffer());
      const got = parsedShape(hive.getRootKey());

      assert.deepStrictEqual(got.name, expected.name);
      assert.deepStrictEqual(got.lastWrite, expected.lastWrite);
      assert.deepStrictEqual(got.values.map((v) => v.name).sort(), expected.values.map((v) => v.name).sort());
      // counts
      const countKeys = (k) => 1 + k.children.reduce((n, c) => n + countKeys(c), 0);
      assert.strictEqual(countKeys(got), countKeys(expected));
      // value-level compare by name
      const byName = Object.fromEntries(expected.values.map((v) => [v.name, v]));
      for (const v of got.values) {
        const e = byName[v.name];
        assert.ok(e, `unexpected value ${v.name}`);
        assert.strictEqual(v.type, e.type, `${v.name} type`);
        assert.deepStrictEqual(v.data, normalise(e), `${v.name} data`);
      }
    });
  }
}

// Win10 1709+ CM_KEY_NODE/CM_KEY_VALUE layouts round-trip identically.
for (const seed of [7, 99]) {
  test(`round-trip: CM_KEY_* layout, seed ${seed}`, () => {
    const rng = mulberry32(seed);
    const builder = new HiveBuilder({ nkLayout: 'CM_KEY_NODE', vkLayout: 'CM_KEY_VALUE' });
    builder.build(randomTree(rng, 3));
    const expected = specShape(builder.root);
    const hive = reg.openHive(builder.toBuffer());
    const got = parsedShape(hive.getRootKey());
    const countKeys = (k) => 1 + k.children.reduce((n, c) => n + countKeys(c), 0);
    assert.strictEqual(countKeys(got), countKeys(expected));
    const byName = Object.fromEntries(expected.values.map((v) => [v.name, v]));
    for (const v of got.values) {
      const e = byName[v.name];
      assert.ok(e, `unexpected value ${v.name}`);
      assert.strictEqual(v.type, e.type);
      assert.deepStrictEqual(v.data, normalise(e));
    }
  });
}

test('round-trip: getSubkey(path) walks a deep chain', () => {
  const builder = new HiveBuilder();
  builder.build((r) => {
    r.key('L1').key('L2').key('L3').key('L4').value('Deep', 1, 'found');
  });
  const hive = reg.openHive(builder.toBuffer());
  const k = hive.getSubkey('L1\\L2\\L3\\L4');
  assert.ok(k);
  assert.strictEqual(k.getValue('Deep').getData().value, 'found');
});

test('round-trip: external (non-inline) data path exercised', () => {
  const big = new Uint8Array(200).map((_, i) => i & 0xff);
  const builder = new HiveBuilder({ forceInline: false });
  builder.build((r) => {
    r.value('Big', 3, big);
    r.value('Small', 4, 7); // would be inline; forced external
  });
  const hive = reg.openHive(builder.toBuffer());
  const root = hive.getRootKey();
  assert.deepStrictEqual(Array.from(root.getValue('Big').getData().value), Array.from(big));
  assert.strictEqual(root.getValue('Small').getData().value, 7);
});

test('round-trip: timestamps survive exactly', () => {
  const stamps = [0n, 1n, 116444736000000000n, 0x01d0c7a57f5a6c00n];
  const builder = new HiveBuilder();
  builder.build((r) => {
    stamps.forEach((s, i) => r.key(`T${i}`, { lastWrite: s }));
  });
  const hive = reg.openHive(builder.toBuffer());
  for (const k of hive.getRootKey().getSubkeys()) {
    const i = Number(k.name.slice(1));
    assert.strictEqual(k.lastWrite, stamps[i]);
  }
});
