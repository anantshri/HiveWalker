'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');

const { BufferReader, RegistryParseError } = loadSrc({ only: /01-buffer-reader/ }).reg;

function buf(bytes) {
  return new Uint8Array(bytes).buffer;
}

test('u8/u16/u32/i32/u64 read little-endian', () => {
  const r = new BufferReader(buf([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]));
  assert.strictEqual(r.u8(0), 0x01);
  assert.strictEqual(r.u16(0), 0x0201);
  assert.strictEqual(r.u32(0), 0x04030201);
  assert.strictEqual(r.u64(0), 0x0807060504030201n);
});

test('i32 reads signed values (cell sizes are negative when allocated)', () => {
  const r = new BufferReader(buf([0x00, 0x00, 0x00, 0x80])); // 0x80000000
  assert.strictEqual(r.i32(0), -2147483648);
});

test('out-of-bounds reads throw RegistryParseError with offset', () => {
  const r = new BufferReader(buf([1, 2, 3]));
  assert.throws(() => r.u32(0), (e) => e instanceof RegistryParseError && e.offset === 0);
  assert.throws(() => r.u16(2), (e) => e instanceof RegistryParseError && e.offset === 2);
  assert.throws(() => r.u8(99), (e) => e instanceof RegistryParseError && e.offset === 99);
  assert.throws(() => r.bytes(1, 100), (e) => e instanceof RegistryParseError && e.offset === 1);
});

test('negative offsets are rejected, not wrapped', () => {
  const r = new BufferReader(buf([1, 2, 3]));
  assert.throws(() => r.u8(-1), RegistryParseError);
});

test('ascii/utf16le/sig decode', () => {
  // "hi" utf16le + "AB"
  const r = new BufferReader(buf([0x68, 0x00, 0x69, 0x00, 0x41, 0x42]));
  assert.strictEqual(r.utf16le(0, 4), 'hi');
  assert.strictEqual(r.ascii(4, 2), 'AB');
  assert.strictEqual(r.sig(4, 2), 'AB');
});

test('utf16le tolerates odd byte counts', () => {
  const r = new BufferReader(buf([0x68, 0x00, 0x69, 0x00, 0x00]));
  assert.strictEqual(r.utf16le(0, 5), 'hi');
});

test('bytes returns a copy, not a view', () => {
  const src = new Uint8Array([9, 8, 7]);
  const r = new BufferReader(src.buffer);
  const out = r.bytes(0, 3);
  assert.deepStrictEqual(out, src);
  out[0] = 255;
  assert.strictEqual(src[0], 9);
});

test('accepts Uint8Array views with offsets', () => {
  const big = new Uint8Array([0, 0, 1, 0, 0, 0]);
  const view = big.subarray(2, 6); // 4 bytes starting at element 2
  const r = new BufferReader(view);
  assert.strictEqual(r.length, 4);
  assert.strictEqual(r.u32(0), 1);
});

test('constructor rejects nonsense', () => {
  assert.throws(() => new BufferReader('nope'), TypeError);
  assert.throws(() => new BufferReader(null), TypeError);
});

test('RegistryParseError message includes hex offset', () => {
  const e = new RegistryParseError('bad cell', 4096);
  assert.match(e.message, /bad cell \(at offset 0x1000\)/);
  assert.strictEqual(new RegistryParseError('x').offset, null);
});
