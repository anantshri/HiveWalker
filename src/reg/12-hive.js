// rv.reg — RegfHive facade: the API surface everything else consumes.
// Mirrors Parse::Win32Registry's shape (getRootKey/getSubkey/getValues/…)
// so plugin-style decoders could be ported later.
(function (RV) {
  'use strict';

  const { LIMITS, KEY_SYM_LINK, BINARY_TYPES } = RV.reg.consts;
  const { BufferReader } = RV.reg;

  /** A parsed registry key. Lazy: subkeys/values load on first access. */
  class NkKey {
    constructor(hive, rel, parent) {
      this._hive = hive;
      this._rel = rel;
      this._parent = parent || null;
      this._rec = null; // parsed nk record
      this._subkeys = undefined; // undefined = not loaded
      this._values = undefined;
      this.warnings = [];
    }

    _ensure() {
      if (this._rec) return;
      this._rec = RV.reg.parseNk(this._hive.reader, this._hive.binMap, this._rel, { warnings: this.warnings });
    }

    get rel() { this._ensure(); return this._rel; }
    get name() { this._ensure(); return this._rec.name; }
    get flags() { this._ensure(); return this._rec.flags; }
    get lastWrite() { this._ensure(); return this._rec.timestamp; }
    get lastWriteDate() { this._ensure(); return RV.reg.filetime.filetimeToDate(this._rec.timestamp); }
    get className() {
      this._ensure();
      if (this._rec.classNameRel == null || this._rec.classNameLen === 0) return null;
      try {
        const cell = RV.reg.cellAt(this._hive.reader, this._hive.binMap, this._rec.classNameRel);
        const n = Math.min(this._rec.classNameLen, cell.size);
        return RV.reg.decodeUtf16LE(this._hive.reader.bytes(cell.dataAbs, n));
      } catch { return null; }
    }
    get subkeyCount() { this._ensure(); return this._rec.subkeyCount; }
    get valueCount() { this._ensure(); return this._rec.valueCount; }
    get parent() { return this._parent; }
    get path() {
      if (!this._parent) return this.name;
      return `${this._parent.path}\\${this.name}`;
    }
    isSymbolicLink() { this._ensure(); return (this._rec.flags & KEY_SYM_LINK) !== 0; }

    /** Children, sorted case-insensitively (regedit order). Cached. */
    getSubkeys() {
      if (this._subkeys !== undefined) return this._subkeys;
      this._ensure();
      const rels = RV.reg.resolveSubkeyOffsets(
        this._hive.reader, this._hive.binMap, this._rec.subkeyListRel, { warnings: this.warnings },
      );
      const kids = [];
      const seen = new Set();
      for (const rel of rels) {
        if (seen.has(rel)) continue; // duplicate entries
        seen.add(rel);
        try {
          const k = new NkKey(this._hive, rel, this);
          k._ensure(); // force parse now so corruption is caught here
          kids.push(k);
        } catch (e) {
          this.warnings.push(`unreadable subkey at 0x${rel.toString(16)}: ${e.message}`);
        }
      }
      kids.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
      this._subkeys = kids;
      return kids;
    }

    getSubkey(name) {
      const lower = String(name).toLowerCase();
      return this.getSubkeys().find((k) => k.name.toLowerCase() === lower) || null;
    }

    /** Values. Cached. */
    getValues() {
      if (this._values !== undefined) return this._values;
      this._ensure();
      const rels = RV.reg.resolveValueOffsets(
        this._hive.reader, this._hive.binMap, this._rec.valueListRel, this._rec.valueCount,
        { warnings: this.warnings },
      );
      const vals = [];
      for (const rel of rels) {
        try {
          vals.push(new VkValue(this._hive, rel));
        } catch (e) {
          this.warnings.push(`unreadable value at 0x${rel.toString(16)}: ${e.message}`);
        }
      }
      // Default value first, then alphabetical (regedit order).
      vals.sort((a, b) => {
        if (a.name === '' && b.name !== '') return -1;
        if (b.name === '' && a.name !== '') return 1;
        return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
      });
      this._values = vals;
      return vals;
    }

    getValue(name) {
      const lower = String(name).toLowerCase();
      return this.getValues().find((v) => v.name.toLowerCase() === lower) || null;
    }

    toJSON() {
      return {
        name: this.name,
        path: this.path,
        lastWrite: this.lastWrite.toString(),
        subkeyCount: this.subkeyCount,
        valueCount: this.valueCount,
        warnings: this.warnings,
      };
    }
  }

  /** A parsed registry value. Data loads lazily. */
  class VkValue {
    constructor(hive, rel) {
      this._hive = hive;
      this._rel = rel;
      this._rec = RV.reg.parseVk(hive.reader, hive.binMap, rel);
    }
    get rel() { return this._rel; }
    get name() { return this._rec.name; }
    get displayName() { return this._rec.name === '' ? '(Default)' : this._rec.name; }
    get type() { return this._rec.type; }
    get typeName() {
      return RV.reg.consts.VALUE_TYPE_NAMES[this._rec.type] || `unknown (0x${this._rec.type.toString(16)})`;
    }
    get dataSize() { return this._rec.dataLen; }
    isBinaryKind() { return BINARY_TYPES.has(this._rec.type); }
    getRawData() { return RV.reg.vkRawData(this._hive.reader, this._hive.binMap, this._rec); }
    getData() { return RV.reg.decodeValue(this._rec.type, this.getRawData()); }
    getDisplay() {
      return RV.reg.formatValueData(this._rec.type, this.getRawData(), { name: this._rec.name });
    }
    toJSON() {
      return { name: this.displayName, type: this.typeName, size: this.dataSize };
    }
  }

  /** An opened hive. */
  class RegfHive {
    constructor(buffer) {
      this.reader = buffer instanceof BufferReader ? buffer : new BufferReader(buffer);
      this.warnings = [];
      this.meta = RV.reg.parseRegfBlock(this.reader);
      if (!this.meta.checksumValid) {
        this.warnings.push('base-block checksum mismatch (hive may be dirty or was copied mid-write)');
      }
      const bins = RV.reg.scanHiveBins(this.reader);
      if (bins.length === 0) this.warnings.push('no hbin blocks found');
      this.binMap = RV.reg.buildBinMap(bins);
      this.bins = bins;
    }

    getRootKey() {
      if (this._root == null) this._root = new NkKey(this, this.meta.rootCellOffset, null);
      return this._root;
    }

    /** 'ControlSet001\\Control' — case-insensitive; null when missing. */
    getSubkey(path) { return this.getKey(path); }

    getKey(path) {
      if (path == null || path === '') return this.getRootKey();
      const parts = String(path).split(/[\\/]+/).filter((p) => p !== '');
      let k = this.getRootKey();
      for (const part of parts) {
        k = k.getSubkey(part);
        if (k === null) return null;
      }
      return k;
    }

    /**
     * Full traversal, iterative and cancellable.
     * @yields {NkKey}
     */
    *walk(opts) {
      const signal = opts && opts.signal;
      const stack = [this.getRootKey()];
      let seen = 0;
      while (stack.length > 0) {
        if (signal && signal.aborted) return;
        if (++seen > LIMITS.MAX_WALK_KEYS) {
          this.warnings.push('walk hit key cap; truncated');
          return;
        }
        const k = stack.pop();
        yield k;
        const kids = k.getSubkeys();
        for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
      }
    }

    countAll(opts) {
      let keys = 0;
      let values = 0;
      for (const k of this.walk(opts)) {
        keys++;
        values += k.valueCount;
      }
      return { keys, values };
    }

    /**
     * Search key names, value names, and decoded string data.
     * @param {{query:string, maxResults?:number, signal?:AbortSignal}} q
     * @yields {{key:NkKey, field:'key'|'valueName'|'valueData', value?:VkValue, text:string}}
     */
    *search(q) {
      const needle = String(q.query || '').toLowerCase();
      if (needle === '') return;
      const max = q.maxResults || LIMITS.MAX_SEARCH_RESULTS;
      const signal = q.signal;
      let n = 0;
      for (const key of this.walk({ signal })) {
        if (n >= max) return;
        if (key.name.toLowerCase().includes(needle)) {
          n++;
          yield { key, field: 'key', text: key.name };
          if (n >= max) return;
        }
        for (const v of key.getValues()) {
          if (v.displayName.toLowerCase().includes(needle)) {
            n++;
            yield { key, field: 'valueName', value: v, text: v.displayName };
            if (n >= max) return;
          }
          const d = v.getData();
          const texts = d.kind === 'string' ? [d.value]
            : d.kind === 'multi' ? d.value
            : d.kind === 'number' ? [String(d.value)]
            : [];
          for (const t of texts) {
            if (t.toLowerCase().includes(needle)) {
              n++;
              yield { key, field: 'valueData', value: v, text: t };
              if (n >= max) return;
              break;
            }
          }
        }
      }
    }

    toJSON() {
      return { meta: { ...this.meta, timestamp: this.meta.timestamp.toString() }, warnings: this.warnings };
    }
  }

  /** Open a hive from an ArrayBuffer or Uint8Array. Throws RegistryParseError. */
  function openHive(buffer) {
    return new RegfHive(buffer);
  }

  RV.reg.openHive = openHive;
  RV.reg.RegfHive = RegfHive;
  RV.reg.NkKey = NkKey;
  RV.reg.VkValue = VkValue;
})(window.RV);
