// rv.plugins — multi-hive session store. DOM-free so it is testable
// headless: the app layer owns file reading and rendering, this module only
// tracks which hives are attached and what types they were detected as.
(function (RV) {
  'use strict';

  let nextId = 1;
  let entries = []; // {id, hive, fileName, types:Set<string>}
  let primaryId = null;
  const attachCallbacks = [];
  const detachCallbacks = [];

  function typesOf(hive) {
    try {
      return RV.plugins.helpers.guessHiveType(hive);
    } catch {
      return new Set(['unknown']);
    }
  }

  function entryById(id) {
    return entries.find((e) => e.id === id) || null;
  }

  function attach(hive, fileName) {
    const entry = {
      id: 'h' + nextId++,
      hive,
      fileName: fileName || '(buffer)',
      types: typesOf(hive),
    };
    entries.push(entry);
    if (primaryId == null) primaryId = entry.id;
    for (const cb of attachCallbacks.slice()) {
      try { cb(entry); } catch { /* listener errors must not break attach */ }
    }
    return entry;
  }

  function remove(entryOrId) {
    const entry = typeof entryOrId === 'object' ? entryOrId : entryById(entryOrId);
    if (!entry) return;
    entries = entries.filter((e) => e !== entry);
    if (primaryId === entry.id) primaryId = entries.length ? entries[0].id : null;
    for (const cb of detachCallbacks.slice()) {
      try { cb(entry); } catch { /* listener errors must not break remove */ }
    }
  }

  function setPrimary(entryOrId) {
    const entry = typeof entryOrId === 'object' ? entryOrId : entryById(entryOrId);
    if (entry) primaryId = entry.id; // no callbacks; the UI drives re-render
  }

  function clear() {
    const removed = entries;
    entries = [];
    primaryId = null;
    for (const entry of removed) {
      for (const cb of detachCallbacks.slice()) {
        try { cb(entry); } catch { /* ignore */ }
      }
    }
  }

  function byType(tag) {
    const t = String(tag).toLowerCase();
    // Last attach wins so re-attaching a fresher SAM replaces the old one.
    for (let i = entries.length - 1; i >= 0; i--) {
      if (entries[i].types.has(t)) return entries[i];
    }
    return null;
  }

  function onAttach(cb) {
    attachCallbacks.push(cb);
    return () => {
      const i = attachCallbacks.indexOf(cb);
      if (i >= 0) attachCallbacks.splice(i, 1);
    };
  }

  function onDetach(cb) {
    detachCallbacks.push(cb);
    return () => {
      const i = detachCallbacks.indexOf(cb);
      if (i >= 0) detachCallbacks.splice(i, 1);
    };
  }

  RV.plugins.session = {
    hives: () => entries.slice(),
    byType,
    primary: () => entryById(primaryId),
    attach,
    remove,
    setPrimary,
    clear,
    onAttach,
    onDetach,
  };
})(window.RV);
