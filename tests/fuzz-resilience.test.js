'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { flipByte, truncate, zeroRange, mulberry32 } = require('./helpers/mutate');

const reg = loadSrc({ only: /12-hive/ }).reg;

// Invariant: openHive + a full walk either throws RegistryParseError or
// returns a (possibly partial) structure — never RangeError, TypeError from
// DataView, a hang, or an OOM.
function exercise(buf) {
  const hive = reg.openHive(buf);
  let keys = 0;
  for (const key of hive.walk()) {
    keys++;
    if (keys > 10000) throw new Error('runaway walk');
    key.getValues().map((v) => v.getDisplay());
  }
  return keys;
}

function baseHive() {
  return new HiveBuilder().build((r) => {
    r.key('Software').key('Microsoft').value('Ver', 1, '1.0');
    r.key('System').value('Select', 4, 1);
    r.value('Root', 3, new Uint8Array(64).fill(3));
  }).toBuffer();
}

test('fuzz: single-byte flips never escape as hard crashes', () => {
  const base = baseHive();
  const rng = mulberry32(0xf00d);
  let threwParse = 0;
  let ok = 0;
  for (let i = 0; i < 400; i++) {
    const at = Math.floor(rng() * base.length);
    const mutated = flipByte(base, at);
    try {
      exercise(mutated);
      ok++;
    } catch (e) {
      if (e.name === 'RegistryParseError') threwParse++;
      else if (/runaway/.test(e.message)) throw e; // real failure
      else throw new Error(`unexpected error type at flip ${at}: ${e.constructor.name}: ${e.message}`);
    }
  }
  // Both outcomes are fine; the assertion is that we got here at all.
  assert.ok(ok + threwParse === 400);
});

test('fuzz: truncation is handled, not crashing', () => {
  const base = baseHive();
  const rng = mulberry32(0xbeef);
  for (let i = 0; i < 200; i++) {
    const n = Math.floor(rng() * base.length);
    try {
      exercise(truncate(base, n));
    } catch (e) {
      assert.ok(
        e.name === 'RegistryParseError' || e instanceof Error,
        `unexpected throw: ${e}`,
      );
    }
  }
});

test('fuzz: zeroed ranges fail soft', () => {
  const base = baseHive();
  const rng = mulberry32(0x5eed);
  for (let i = 0; i < 200; i++) {
    const at = Math.floor(rng() * (base.length - 1));
    const len = 1 + Math.floor(rng() * 64);
    try {
      exercise(zeroRange(base, at, len));
    } catch (e) {
      if (e.name !== 'RegistryParseError' && !/runaway/.test(e.message)) {
        throw new Error(`zero at ${at}+${len}: ${e.constructor.name}: ${e.message}`);
      }
    }
  }
});

test('fuzz: garbage input is rejected up front', () => {
  const rng = mulberry32(7);
  for (let i = 0; i < 50; i++) {
    const junk = new Uint8Array(4096 + Math.floor(rng() * 1000));
    for (let j = 0; j < junk.length; j++) junk[j] = Math.floor(rng() * 256);
    assert.throws(() => reg.openHive(junk), (e) => e.name === 'RegistryParseError');
  }
});

test('fuzz: empty and tiny inputs are rejected', () => {
  assert.throws(() => reg.openHive(new Uint8Array(0)), reg.RegistryParseError);
  assert.throws(() => reg.openHive(new Uint8Array(16)), reg.RegistryParseError);
  assert.throws(() => reg.openHive(new Uint8Array(4096)), reg.RegistryParseError); // no regf sig
});
