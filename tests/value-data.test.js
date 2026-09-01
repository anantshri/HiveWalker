'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const reg = loadSrc({ only: /12-hive/ }).reg;
const { openHive, decodeValue, formatValueData } = reg;

function build(build, opts) {
  return openHive(new HiveBuilder(opts).build(build).toBuffer());
}

test('facade: openHive exposes root, paths, and metadata', () => {
  const hive = build((r) => {
    r.key('Software').key('Microsoft').value('Ver', 1, '4.0');
  });
  const root = hive.getRootKey();
  assert.strictEqual(root.name, 'root');
  const sw = hive.getSubkey('Software');
  assert.strictEqual(sw.path, 'root\\Software');
  assert.strictEqual(hive.getSubkey('software\\microsoft').valueCount, 1); // case-insensitive
  assert.strictEqual(hive.getSubkey('Software\\Bogus'), null);
  assert.strictEqual(hive.meta.checksumValid, true);
});

test('facade: values decode through the full stack', () => {
  const hive = build((r) => {
    r.value('D', 4, 0x2a);
    r.value('S', 1, 'some string');
    r.value('Q', 11, 0x1122334455667788n);
    r.value('M', 7, ['one', 'two']);
    r.value('', 1, 'def');
  });
  const root = hive.getRootKey();
  const vals = root.getValues();
  assert.strictEqual(vals.length, 5);

  const byName = Object.fromEntries(vals.map((v) => [v.displayName, v]));
  assert.strictEqual(byName.D.getData().value, 42);
  assert.strictEqual(byName.S.getData().value, 'some string');
  assert.strictEqual(byName.Q.getData().value, 0x1122334455667788n);
  assert.deepStrictEqual(byName.M.getData().value, ['one', 'two']);

  // (Default) sorts first
  assert.strictEqual(vals[0].displayName, '(Default)');
  assert.strictEqual(vals[0].getData().value, 'def');
});

test('decoders: every REG_* type round-trips', () => {
  const utf16 = (s) => new Uint8Array(Buffer.from(s, 'utf16le'));
  const cases = [
    [1, utf16('hi\0'), { kind: 'string', value: 'hi' }],
    [2, utf16('A\0'), { kind: 'string', value: 'A' }],
    [7, utf16('a\0b\0\0'), { kind: 'multi', value: ['a', 'b'] }],
    [4, new Uint8Array([0xff, 0, 0, 0]), { kind: 'number', value: 255 }],
    [5, new Uint8Array([0, 0, 0, 0xff]), { kind: 'number', value: 255 }],
    [11, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), { kind: 'number', value: 0x0807060504030201n }],
    [3, new Uint8Array([9, 9]), { kind: 'binary' }],
    [0, new Uint8Array(0), { kind: 'binary' }],
  ];
  for (const [type, raw, expect] of cases) {
    const got = decodeValue(type, raw);
    assert.strictEqual(got.kind, expect.kind, `type ${type}`);
    if (expect.kind === 'binary') {
      assert.ok(got.value instanceof Uint8Array);
    } else {
      assert.deepStrictEqual(got.value, expect.value, `type ${type}`);
    }
  }
});

test('decoders: multi-sz trailing empties dropped', () => {
  // "a\0b\0\0" in UTF-16LE: a=61 00, NUL=00 00, b=62 00, NUL=00 00, NUL=00 00
  const d = decodeValue(7, new Uint8Array([0x61, 0, 0, 0, 0x62, 0, 0, 0, 0, 0]));
  assert.deepStrictEqual(d.value, ['a', 'b']);
});

test('decoders: wrong-size DWORD degrades to binary with note', () => {
  const d = decodeValue(4, new Uint8Array([1, 2, 3]));
  assert.strictEqual(d.kind, 'binary');
  assert.match(d.note, /DWORD with 3 bytes/);
});

test('display: numeric values show hex note', () => {
  const r4 = formatValueData(4, new Uint8Array([0x2a, 0, 0, 0]));
  assert.strictEqual(r4.text, '42');
  assert.strictEqual(r4.note, '0x0000002a');
  const r11 = formatValueData(11, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
  assert.strictEqual(r11.text, '578437695752307201');
  assert.strictEqual(r11.note, '0x0807060504030201');
});

test('display: binary values preview first bytes', () => {
  const raw = new Uint8Array(20).fill(0xab);
  const r = formatValueData(3, raw);
  assert.match(r.text, /^(ab ){16}…$/);
  assert.strictEqual(formatValueData(3, new Uint8Array(0)).text, '(zero-length binary value)');
});

test('display: 16-byte binary under GUID-ish name renders GUID', () => {
  const raw = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  const r = formatValueData(3, raw, { name: 'ClassID' });
  assert.match(r.text, /^\{04030201-0605-0807-090a-0b0c0d0e0f10\}/);
});

test('facade: walk() visits every key iteratively', () => {
  const hive = build((r) => {
    r.key('A').key('A1').key('A1a');
    r.key('B').key('B1');
    r.key('C');
  });
  const paths = [...hive.walk()].map((k) => k.path).sort();
  assert.strictEqual(paths.length, 7);
  assert.ok(paths.includes('root\\A\\A1\\A1a'));
  assert.ok(paths.includes('root\\C'));
});

test('facade: countAll totals keys and values', () => {
  const hive = build((r) => {
    r.value('v1', 4, 1);
    r.key('K').value('v2', 1, 'x');
  });
  const { keys, values } = hive.countAll();
  assert.strictEqual(keys, 2);
  assert.strictEqual(values, 2);
});

test('facade: search finds keys, value names, and data', () => {
  const hive = build((r) => {
    r.key('Run').value('Updater', 1, 'C:\\tools\\updater.exe');
    r.key('Version').value('Build', 4, 1234);
  });
  // key-name hit
  assert.ok([...hive.search({ query: 'run' })].some((h) => h.field === 'key'));
  // value-name + value-data hits
  const hits = [...hive.search({ query: 'update' })];
  assert.ok(hits.some((h) => h.field === 'valueName' && h.value.name === 'Updater'));
  assert.ok(hits.some((h) => h.field === 'valueData' && h.text.includes('updater.exe')));
  // numeric data hit
  assert.ok([...hive.search({ query: '1234' })].some((h) => h.field === 'valueData'));
});

test('facade: search respects maxResults', () => {
  const hive = build((r) => {
    for (let i = 0; i < 30; i++) r.key(`Target${i}`);
  });
  const hits = [...hive.search({ query: 'target', maxResults: 5 })];
  assert.strictEqual(hits.length, 5);
});

test('facade: empty query yields nothing', () => {
  const hive = build((r) => r.key('X'));
  assert.deepStrictEqual([...hive.search({ query: '' })], []);
});

test('facade: subkey/value counts come from the nk record', () => {
  const hive = build((r) => {
    r.key('One');
    r.key('Two');
    r.value('a', 4, 1);
    r.value('b', 4, 2);
    r.value('c', 4, 3);
  });
  const root = hive.getRootKey();
  assert.strictEqual(root.subkeyCount, 2);
  assert.strictEqual(root.valueCount, 3);
  assert.strictEqual(root.getValues().length, 3);
});

test('facade: corrupt child nk degrades to a warning', () => {
  const buf = new HiveBuilder().build((r) => { r.key('Good'); r.key('Bad'); }).toBuffer();
  const probe = openHive(buf);
  const badRel = probe.getRootKey().getSubkeys().find((k) => k.name === 'Bad').rel;
  const cell = reg.cellAt(probe.reader, probe.binMap, badRel);
  buf[cell.dataAbs] = 0x71; // 'q' — breaks the nk signature
  buf[cell.dataAbs + 1] = 0x71;

  const hive = openHive(buf);
  const kids = hive.getRootKey().getSubkeys();
  // Good survives; Bad is skipped with a warning.
  assert.deepStrictEqual(kids.map((k) => k.name), ['Good']);
  assert.ok(hive.getRootKey().warnings.some((w) => /0x/.test(w)));
});
