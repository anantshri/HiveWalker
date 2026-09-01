'use strict';

// Encode a JS Date as an 8-byte little-endian Windows FILETIME buffer — the
// on-disk form of binary timestamps (ShutdownTime, UserAssist, USBStor props).
function ftBytes(date) {
  const ms = BigInt(date.getTime());
  const ft = (ms + 11644473600000n) * 10000n; // 100ns ticks since 1601
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(ft);
  return b;
}

module.exports = { ftBytes };
