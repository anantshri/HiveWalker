// rv.reg — FILETIME (100ns intervals since 1601-01-01 UTC) conversions.
// BigInt end-to-end: the Perl reference (time.pl getTime) went through a
// float and lost sub-second precision.
(function (RV) {
  'use strict';

  const EPOCH_DIFF_MS = 11644473600000n; // ms between 1601-01-01 and 1970-01-01
  const TICKS_PER_MS = 10000n;
  const MAX_FILETIME = 2650467743999999999n; // 9999-12-31 friendly ceiling

  /** @returns {bigint} milliseconds since Unix epoch */
  function filetimeToMs(ft) {
    if (typeof ft !== 'bigint') throw new TypeError('filetime must be BigInt');
    return ft / TICKS_PER_MS - EPOCH_DIFF_MS;
  }

  /** @returns {Date|null} null when ft is 0 (regedit's "never") */
  function filetimeToDate(ft) {
    if (typeof ft !== 'bigint') throw new TypeError('filetime must be BigInt');
    if (ft === 0n) return null;
    if (ft > MAX_FILETIME) return null; // corrupt future stamp
    return new Date(Number(filetimeToMs(ft)));
  }

  function pad(n, w) {
    return String(n).padStart(w, '0');
  }

  /** "2024-03-05 14:22:09.123" in UTC, regedit-style. */
  function formatFiletime(ft) {
    const d = filetimeToDate(ft);
    if (d === null) return '(no timestamp)';
    return (
      `${pad(d.getUTCFullYear(), 4)}-${pad(d.getUTCMonth() + 1, 2)}-${pad(d.getUTCDate(), 2)} ` +
      `${pad(d.getUTCHours(), 2)}:${pad(d.getUTCMinutes(), 2)}:${pad(d.getUTCSeconds(), 2)}` +
      `.${pad(d.getUTCMilliseconds(), 3)} UTC`
    );
  }

  RV.reg.filetime = { EPOCH_DIFF_MS, TICKS_PER_MS, MAX_FILETIME, filetimeToMs, filetimeToDate, formatFiletime };
})(window.RV);
