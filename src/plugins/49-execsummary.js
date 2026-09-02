// rv.plugins — execsummary: a cross-artifact execution timeline. It does not
// re-decode anything; it runs the existing, tested execution plugins
// (userassist, bam, amcache_file, shimcache) against whichever hives are
// attached and merges their rows into one time-sorted table. This is the
// flagship "what ran, and when" rollup proposed in issue #6.
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  // Each source names the plugin to run, the hive type it needs, and substrings
  // that locate its time/executable columns in the plugin's output tables.
  const SOURCES = [
    { plugin: 'userassist', type: 'ntuser', label: 'UserAssist', timeHdr: 'Last Run', exeHdr: 'Value' },
    { plugin: 'bam', type: 'system', label: 'BAM/DAM', timeHdr: 'Last Execution', exeHdr: 'Program' },
    { plugin: 'amcache_file', type: 'amcache', label: 'Amcache', timeHdr: 'Last Modified', exeHdr: 'Path' },
    { plugin: 'shimcache', type: 'system', label: 'ShimCache', timeHdr: 'Last Modified', exeHdr: 'Path' },
  ];

  // Placeholder cells emitted by the source plugins for "no timestamp".
  const NO_TIME = new Set(['-', '', '(never)', '(invalid)']);

  /** Pull (time, exe) pairs out of a plugin result's table blocks. */
  function harvest(result, timeHdr, exeHdr) {
    const out = [];
    for (const sec of (result && result.sections) || []) {
      for (const b of sec.blocks || []) {
        if (b.kind !== 'table') continue;
        const ti = b.columns.findIndex((c) => c.includes(timeHdr));
        const ei = b.columns.findIndex((c) => c.includes(exeHdr));
        if (ti < 0 || ei < 0) continue;
        for (const row of b.rows) {
          const when = String(row[ti] == null ? '' : row[ti]).trim();
          const exe = String(row[ei] == null ? '' : row[ei]).trim();
          if (NO_TIME.has(when) || !exe) continue;
          out.push({ when, exe });
        }
      }
    }
    return out;
  }

  R.register({
    name: 'execsummary',
    hives: ['ntuser', 'system', 'amcache'],
    category: 'program execution (timeline)',
    // A correlation of execution-evidence data sources, not a single technique
    // — left unmapped. (Was T1204.)
    version: '20260902',
    shortDescr: 'Unified execution timeline merging UserAssist, BAM/DAM, Amcache and ShimCache',
    run(hive, ctx) {
      ctx.section('Execution Timeline (cross-artifact)');
      const session = ctx.session;

      // Candidate hives: everything attached in the session, plus the hive this
      // plugin was invoked on (deduped by object identity).
      const seen = new Set();
      const candidates = [];
      const add = (h, types, name) => {
        if (h && !seen.has(h)) { seen.add(h); candidates.push({ hive: h, types, name }); }
      };
      if (session && typeof session.hives === 'function') {
        for (const e of session.hives()) add(e.hive, e.types, e.fileName);
      }
      add(hive, H.guessHiveType(hive), '(current)');

      const timeline = [];
      const used = [];
      for (const s of SOURCES) {
        const cand = candidates.find((c) => c.types && c.types.has(s.type));
        if (!cand) continue;
        let res;
        try { res = R.run(s.plugin, cand.hive, { session }); } catch { continue; }
        if (!res || res.error) continue;
        const rows = harvest(res, s.timeHdr, s.exeHdr);
        for (const r of rows) timeline.push({ when: r.when, source: s.label, exe: r.exe });
        used.push(`${s.label} (${rows.length})`);
      }

      if (timeline.length === 0) {
        ctx.rptMsg('No execution artifacts found. Attach NTUSER.DAT, SYSTEM and/or Amcache.hve for a fuller timeline.');
        return;
      }

      // Timestamps are fixed-width "YYYY-MM-DD HH:MM:SS UTC" → lexical sort is
      // chronological. Newest first.
      timeline.sort((a, b) => (a.when < b.when ? 1 : a.when > b.when ? -1 : 0));
      ctx.rptMsg('Sources merged: ' + used.join(', '));

      const t = ctx.table(['When (UTC)', 'Source', 'Executable']);
      for (const e of timeline.slice(0, H.MAX_PLUGIN_ROWS)) t.row([e.when, e.source, e.exe]);
      if (timeline.length > H.MAX_PLUGIN_ROWS) ctx.note(`Truncated to ${H.MAX_PLUGIN_ROWS} of ${timeline.length} events.`);
      ctx.note('Per-artifact time semantics differ: UserAssist and BAM/DAM are execution times; Amcache is file first-seen/last-modified; ShimCache is file last-modified (an entry proves presence, not execution). Correlate before concluding.');
    },
  });
})(window.RV);
