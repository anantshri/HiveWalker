// rv.plugins — plugin registry + executor. The JS mirror of RegRipper's driver
// (rip.pl): plugins register a plain object with a run(hive, ctx) method; the
// runtime lists which apply to a loaded hive and runs one into a structured,
// serialisable result that both the DOM table view and the text export consume.
(function (RV) {
  'use strict';

  // Registration order is stable and meaningful (mirrors RegRipper's plugin
  // list order), so a plain array is the registry.
  const registry = [];
  const byName = new Map();

  /** Validate + store a plugin. Throws on a malformed plugin (a coding error,
   *  caught by tests, never by end users). */
  function register(plugin) {
    if (!plugin || typeof plugin !== 'object') throw new TypeError('plugin must be an object');
    if (typeof plugin.name !== 'string' || plugin.name === '') throw new TypeError('plugin.name required');
    if (!Array.isArray(plugin.hives) || plugin.hives.length === 0) throw new TypeError(`plugin ${plugin.name}: hives[] required`);
    if (typeof plugin.run !== 'function') throw new TypeError(`plugin ${plugin.name}: run() required`);
    if (byName.has(plugin.name)) throw new Error(`plugin ${plugin.name}: already registered`);
    // Normalise the hive tags to lowercase so matching against guessHiveType
    // (also lowercase) is trivial.
    const norm = { ...plugin, hives: plugin.hives.map((h) => String(h).toLowerCase()) };
    registry.push(norm);
    byName.set(norm.name, norm);
    return norm;
  }

  /** All registered plugins, in registration order. */
  function all() { return registry.slice(); }

  function get(name) { return byName.get(name) || null; }

  /** Plugins whose declared hive tags intersect the hive's detected types. */
  function applicableTo(hive) {
    const types = RV.plugins.helpers.guessHiveType(hive);
    return registry.filter((p) => p.hives.some((h) => types.has(h)));
  }

  /**
   * Run one plugin against a hive. Never throws: a plugin error is captured in
   * the result's `error` field so one bad plugin can't crash the page.
   * @returns the structured result shape documented in the plan.
   */
  function run(plugin, hive) {
    const p = typeof plugin === 'string' ? get(plugin) : plugin;
    if (!p) throw new Error(`unknown plugin: ${plugin}`);
    const ctx = RV.plugins.helpers.makeContext();
    let error = null;
    try {
      p.run(hive, ctx);
    } catch (e) {
      error = { name: e && e.name ? e.name : 'Error', message: e && e.message ? e.message : String(e) };
    }
    return {
      plugin: p.name,
      shortDescr: p.shortDescr || '',
      hiveTypes: p.hives.slice(),
      category: p.category || '',
      mitre: p.mitre || null,
      version: p.version || '',
      ranAt: new Date(),
      error,
      sections: ctx.sections(),
    };
  }

  /**
   * Run every applicable plugin, honouring an optional abort signal between
   * plugins (the same cooperative-cancellation pattern the parser's walk uses).
   */
  function runAll(hive, opts) {
    const signal = opts && opts.signal;
    const results = [];
    let aborted = false;
    for (const p of applicableTo(hive)) {
      if (signal && signal.aborted) { aborted = true; break; }
      results.push(run(p, hive));
    }
    return { results, aborted };
  }

  RV.plugins.runtime = { register, all, get, applicableTo, run, runAll };
})(window.RV);
