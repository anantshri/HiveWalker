# RegRipper plugin porting — guide & status

> **Credit:** RegRipper is by **H. Carvey (keydet89)** —
> [RegRipper 4.0](https://github.com/keydet89/RegRipper4.0) ·
> [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0) ·
> [regripper.wordpress.com](https://regripper.wordpress.com/). RR 3.0 is
> MIT-licensed; RR 4.0 is free for personal/academic use **only** and may
> not be included in any distribution — see [`NOTICE.md`](../NOTICE.md).

This document is the durable record of the effort to bring RegRipper's plugin
layer into HiveWalker. **Read this before re-analysing the RegRipper corpus or
porting more plugins** — the corpus breakdown, the porting architecture, and a
complete per-plugin status already exist here so the work isn't repeated.

Companion machine-readable file: [`regripper-plugin-status.json`](regripper-plugin-status.json)
— one row per RegRipper 4.0 plugin with its status.

---

## TL;DR

- Source of truth for plugins: `/workspace/supporting/RegRipper4.0/plugins/*.pl`
  (386 files). RegRipper 3.0 is an older subset; port from 4.0.
- **They can't run as-is** (Perl + a driver). We reimplement the plugin *model*
  in JS on top of HiveWalker's parser (`RV.reg`, which mirrors
  `Parse::Win32Registry`). None of the plugins need user intervention — they are
  all non-interactive — so the real axis is **portability**, not interaction.
- **Current status: 171 plugins registered** — 133 descriptor-driven, 14
  RR-corpus bespoke (17 minus `samparse` counted below once upgraded), 12
  new beyond the RR corpus, plus the crypto/DFIR/offense expansion of
  2026-09-01 (`bootkey`, `samhashes`, `shimcache`, `amcache_*`, `taskcache`,
  `autostarts`, `defposture`, SECURITY-hive pack, …). 61 `_tln` duplicates are
  never ported; 161 remain deferred.

## Corpus breakdown (RegRipper 4.0)

| Bucket | Count | Notes |
|---|---:|---|
| Total `.pl` files | 386 | |
| `_tln` timeline variants | 61 | **Excluded** — output-format duplicates of a base plugin. Never port; text/table are already render modes. |
| Report plugins (non-tln) | 325 | The actual porting target. |
| — "simple" (no binary `unpack`) | 256 | Pure key/value/subkey reads. |
| — binary-decoder (`unpack`) | 69 | Need bespoke byte parsing. |

`output` field distribution: report 322, tln 60, json 2, yara 1, csv 1. We port
the base *report* semantics only; json/yara/csv/tln are formatting variants.

## Porting status (325 report plugins)

| Status | Count | Where |
|---|---:|---|
| done — bespoke `run()` | 31 | `src/plugins/40-system.js`, `41-software.js`, `42-ntuser.js`, `43-sam.js`, `44-security.js`, `45-amcache.js`, `46-offense.js` |
| done — descriptor | 133 | `src/plugins/50-descriptors.js` (engine: `32-simple.js`) |
| done — bespoke, beyond the RR corpus | 12 | `44-security.js`, `45-amcache.js`, `46-offense.js` + `bootkey`/`svcacls`/`portabledevices`/`mountpoints2`/`opensavepidl`/`samhashes` (see below) |
| **deferred** | **161** | not yet ported — see below |

### New bespoke plugins (beyond the RR corpus, 2026-09-01 expansion)

| Plugin | Hive(s) | What it extracts |
|---|---|---|
| `bootkey` | system | SysKey bootkey from `Control\Lsa\{JD,Skew1,GBG,Data}` class names |
| `shimcache` | system | AppCompatCache file-execution traces (XP→Win10 formats) |
| `bam` | system | BAM/DAM per-SID program execution times |
| `wpdbusenum` | system | MTP/PTP portable-device enumeration |
| `svcacls` | system | Service-key DACLs writable by non-admins (offline accesschk, T1574.011) |
| `taskcache` | software | Scheduled tasks incl. hidden (SD-less) and orphan entries (T1053.005) |
| `networklist` | software | Network profiles: names, categories, first/last connection, gateway MACs |
| `emdmgmt` | software | Volume serial numbers for removable-media correlation |
| `portabledevices` | software | Phone/tablet identity (FriendlyName, model, firmware) |
| `tsclient` | ntuser | Outbound RDP history + username hints (T1021.001) |
| `wordwheelquery` | ntuser | Explorer search terms in MRU order |
| `mountpoints2` | ntuser | Drive letters / UNC shares / CSP volumes mounted by the user |
| `opensavepidl` | ntuser | Open/Save dialog MRUs (UTF-16 string extraction; no shellbag parsing) |
| `samhashes` | sam | NT/LM hash extraction; XP-generation decrypt via the session's SYSTEM bootkey |
| `machine_sid` | security | Machine/domain names + SIDs |
| `auditpol` | security | Per-category audit policy + high-value-silenced flags |
| `lsasecrets` | security | LSA Secrets enumeration + classification (Win10+ AES decrypt UNVERIFIED → listed only) |
| `amcache_file` | amcache | File inventory: paths, SHA-1s, sizes, times (Win8 + Win10 shapes) |
| `amcache_app` | amcache | Installed applications |
| `autostarts` | software/ntuser/system | Consolidated autostart sweep with per-row MITRE tags + StartupApproved decode |
| `defposture` | software/system | Defense posture verdicts (Defender/UAC/WDigest/PowerShell/SmartScreen/…) |

Supporting layers: `src/crypto/` (hand-rolled MD4/MD5/SHA-1/RC4/DES/3DES/AES
with spec KATs), `src/decoders/` (SID, security descriptors, ShimCache, SAM
F/V), `src/plugins/33-session.js` (multi-hive sessions — SAM + SYSTEM
together) and the `+ Add hive…` / hive-switcher topbar. Provenance and
verified constants: `docs/crypto-notes.md`.

Deferred = 61 binary-decoder + 114 simple-but-not-declaratively-representable.
Full per-plugin detail (name, hive, status, reason/mode) is in
`regripper-plugin-status.json`. Deferred reasons bucket as:

| Reason bucket | ~Count |
|---|---:|
| binary decoder (uses `unpack`) | 61 |
| dynamic/runtime-assembled path (var concatenation) | 30 |
| no path detected by the heuristic (needs a human read) | 13 |
| nested subkey-of-subkey value reads | ~15 |
| `::guessHive` multi-hive path branching in one plugin | ~8 |
| data transforms (string split, lookup tables, timestamp/GUID decode) | ~10 |
| conditional alert/note logic | several |
| `hive => "all"` whole-hive scanners | 3 |

Deferred by target hive: software 71, ntuser 63, system 47, usrclass 7,
security 3, syscache 2, amcache 1, bcd 1, "all" 10.

---

## Architecture

Everything lives under `src/plugins/` (classic-script IIFEs into `window.RV`,
loaded in numeric order from `index.html`; the plugin block sits after
`src/reg/13-index.js` and **before** `src/ui/20-view-model.js`).

- `30-runtime.js` — `RV.plugins.runtime`: `register`, `all`, `get`,
  `applicableTo(hive)`, `run(plugin, hive)` (never throws; errors captured in
  `result.error`), `runAll(hive, {signal})`. Result shape:
  `{plugin, shortDescr, hiveTypes, category, mitre, version, ranAt, error,
  sections:[{title, blocks:[{kind:'text'|'kv'|'table'|'note', …}]}]}`.
- `31-helpers.js` — `RV.plugins.helpers`: the `ctx` report builder
  (`section`/`rptMsg`/`kv`/`table`/`note`, `MAX_PLUGIN_ROWS` guard),
  `guessHiveType`, `getControlSet` (Select\Current → ControlSetNNN + fallbacks),
  null-safe getters, `filetimeFromBinary`/`unixToDate`/`formatDate`, `rot13`.
- `32-simple.js` — `RV.plugins.simple`: the **descriptor engine**
  (`registerSimple`, `registerAll`).
- `40-43` — bespoke `run()` plugins (per hive).
- `50-descriptors.js` — generated array of 133 descriptors, `registerAll`-ed.

Rendering/UI: DOM-free view-model functions (`pluginList`, `reportView`,
`reportText`, `reportTextAll`) in `src/ui/20-view-model.js`; the Reports panel is
`src/ui/29-reports.js`.

### Descriptor schema (for the regular plugins)

```js
{
  name: 'compname',            // unique; RegRipper package name
  hives: ['system'],           // system|software|ntuser|usrclass|sam|security|amcache|bcd
  category: 'config',
  mitre: 'T1082',              // or ''
  version: '20201021',
  shortDescr: '...',
  ccs: true,                   // System hive only: prefix each path with ControlSetNNN\
  mode: 'values',              // values | named | subkeys | mru
  paths: ['Control\\ComputerName\\ComputerName', ...],  // candidate paths (all tried)
  names: ['ComputerName'],     // mode 'named' only
  subkeyNames: ['DisplayName'] // mode 'subkeys' only (optional)
}
```

Modes: **values** dumps every value of a key; **named** dumps a fixed set of
values; **subkeys** lists subkeys (name + LastWrite + optional per-subkey
values); **mru** follows MRUList/MRUListEx ordering. A descriptor whose target
key is absent degrades to a graceful "not found" note (never throws).

### How to add a plugin

- **Fits a mode** → add a descriptor object to the array in `50-descriptors.js`
  (or a new `5x-*.js` file that calls `RV.plugins.simple.registerAll([...])`,
  wired into `index.html`). No new test needed beyond the load-validation test,
  though a data-present assertion is welcome.
- **Needs bespoke logic** (binary decode, nested descent, transforms, alerts,
  dynamic paths) → write a `run(hive, ctx)` in the matching `4x-<hive>.js` via
  `RV.plugins.runtime.register({...})`, using `31-helpers.js`. Add a
  `HiveBuilder` fixture test (see `tests/plugins-*.test.js`).

Always: run `node --test`, keep new source ≥ existing coverage, run `aidc-scan`,
and **scan generated files for NUL bytes** (a recurring gremlin — see below).

---

## How the 133 descriptors were produced (reproducible method)

Scripts live in [`scripts/regripper/`](../scripts/regripper/). Pipeline:

1. **Analyse** — `scripts/regripper/analyze.js` parses every `.pl`
   (hive/output/category/version/`unpack`/modules/tln) → `/tmp/rr_analysis.json`
   and prints the corpus breakdown. Also chunks the not-yet-ported "simple"
   plugin list into `/tmp/rr_batch_N.txt`.
2. **Extract** — two ways were used:
   - *Preferred:* dispatch subagents to read the Perl and emit descriptor JSON
     per the schema (`{skip,reason}` for non-conforming plugins). Higher fidelity
     because the agent understands runtime string concatenation etc.
   - *Fallback (budget-limited):* `scripts/regripper/extract.js`, a conservative
     heuristic parser that reads literals and **skips anything ambiguous**
     (runtime-assembled paths, `unpack`, nested descent, path fragments). A wrong
     path only degrades to "not found", never a crash — but under-covers.
   Each writes `/tmp/rr_desc_N.json`.
3. **Assemble** — `scripts/regripper/assemble.js` merges all `rr_desc_*.json`,
   validates shape/hive/mode, dedups against already-registered names, and
   writes `src/plugins/50-descriptors.js`. Skips + reasons are preserved in
   `docs/regripper-plugin-status.json`.

> History note: the first mass-extraction run dispatched 6 parallel subagents;
> the org hit its monthly spend limit and killed all of them. Batches 0/1/3 had
> already written output (68 descriptors, high confidence); batches 2/4/5 were
> redone with the heuristic extractor (65 descriptors). That's why some
> descriptors are agent-read (high confidence) and some heuristic (best-effort).

To refresh the status file after adding plugins:
`node scripts/regripper/status.js`.

## Recurring gotcha: NUL bytes in generated source

Several writes silently embedded raw `NUL` (0x00) bytes where single-character
string/regex literals were intended (e.g. a `\u0000` filter). They render as a
space and break nothing visibly but corrupt the file. **After generating or
hand-editing plugin source, scan for NUL:**

```
node -e 'const fs=require("fs");for(const f of process.argv.slice(1))if([...fs.readFileSync(f)].includes(0))console.log("NUL in",f)' src/plugins/*.js
```

Fix by replacing the raw byte with the escape `\u0000`.

## Verification baseline

`node --test` → 212 pass. New engine + generated descriptor file at 100% line
coverage. `tests/plugins-descriptors.test.js` runs **all** descriptor plugins
against a synthetic hive and asserts none throw. `aidc-scan` clean.
