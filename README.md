<div align="center">

<img src="docs/logo.svg" width="110" height="110" alt="HiveWalker logo">

# HiveWalker

**Walk the Windows registry, hive by hive — entirely in your browser.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-0b63b8.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-131%20pass-brightgreen)](#development)
[![Dependencies](https://img.shields.io/badge/dependencies-0-blue)](package.json)
[![Privacy](https://img.shields.io/badge/privacy-100%25%20local-success)](#privacy)

Open a hive file → browse it like regedit. No upload, no server, no install,
no build step — just open `index.html`.

</div>

---

## What it does

HiveWalker parses the raw **regf** binary format of Windows registry hive
files and presents the contents in a familiar regedit-style interface:

- **Key tree** (left) — lazy expansion keeps even 100 MB+ hives responsive;
  parse warnings surface as `⚠` badges on affected keys. Clicking a key with
  subkeys opens it.
- **Values table** (right) — Name / Type / Data with the key's LastWrite
  timestamp; click binary values for a hex view. Regedit-like `(Default)`
  handling and sort order.
- **Full keyboard navigation** — `↑`/`↓` move, `→` open/enter, `←`
  close/parent, `Enter` toggle, `Home`/`End` jump.
- **Path bar** — breadcrumb navigation (click any crumb to jump to that
  ancestor) plus one-click path copy.
- **Search** — incremental, case-insensitive, across key names, value names,
  and string/numeric value data; results grouped by key with click-through.
- **Hive info panel** — embedded filename, format version, sequence numbers,
  dirty flag, checksum validity, bins size, root cell offset.
- **Count all keys** in the status bar for whole-hive statistics.
- **Resizable panes** — drag the divider; the width persists across sessions
  (double-click resets).

Supported files: `SAM` · `SYSTEM` · `SOFTWARE` · `SECURITY` · `NTUSER.DAT` ·
`UsrClass.dat` — any valid regf hive.

## Getting started

1. Download or clone this repository.
2. Open `index.html` in any modern browser — double-clicking works;
   `file://` is fine.
3. Click **Open hive…** (or drag-drop a hive file anywhere on the page).

That's it. There is no step 4.

## Privacy

Hive files contain sensitive data — password hashes, MRU lists, machine and
user identifiers. **Hive file data never leaves your browser** — parsing is
entirely local, with no server and no upload. The only network request the
deployed site makes is cookieless, privacy-friendly analytics (Plausible),
which reports nothing when the page runs from `localhost` or `file://` (the
script is domain-bound, so self-hosted and offline use generate no traffic).
Unplug your network cable and the viewer behaves exactly the same. The
entire app is a few thousand lines of dependency-free JavaScript you can
audit in an afternoon.

## Value types decoded

| Type | Rendering |
|------|-----------|
| `REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK` | UTF-16LE string |
| `REG_MULTI_SZ` | strings joined with `¦` |
| `REG_DWORD`, `REG_DWORD_BIG_ENDIAN` | unsigned decimal + hex tooltip |
| `REG_QWORD` | 64-bit decimal + hex tooltip |
| `REG_BINARY`, `REG_NONE` | hex preview in table; full hex viewer on click |
| Resource list types | as binary |

16-byte binaries under GUID-ish names additionally render as `{GUID}`.

## Failure behaviour

Hives are untrusted input: every byte access is bounds-checked, corrupt
cells degrade to per-key warnings instead of breaking the tree, and all
hive-derived text is rendered via `textContent` (never `innerHTML`).
Fuzz tests (`tests/fuzz-resilience.test.js`) enforce fail-soft behaviour.

## Development

```
npm test              # 131 tests, zero dependencies (node:test)
npm run test:coverage # per-file coverage
npm run dump -- <hive-file> [--json]   # CLI dump for verification
npm run scan          # aidc-scan security gate
```

The app is plain classic scripts in dependency order — the `<script src>`
list in `index.html` is the single source of truth, and Node tests load the
exact same files in the exact same order via `tests/helpers/load-src.js`.

```
src/reg/     parser library (DOM-free, Node-safe)
src/ui/      view-models (pure, tested) + DOM binders
tests/       node:test suites + synthetic-hive builder + fuzz helpers
docs/regf-format.md   the binary-format spec this implements
```

### How correctness is enforced

**Synthetic round-trips** — `tests/helpers/hive-builder.js` writes hives
through a code path fully independent of the parser; seeded random trees are
deep-compared across both key layouts (`nk`/`CM_KEY_NODE`) and all four
subkey-list styles (`lf`/`lh`/`li`/`ri`), covering every value type, inline
and external data, unicode names, and both record layouts.

**Fuzz tests** mutate hive bytes (flips, truncation, zeroing) and assert
fail-soft behaviour: bounded reads, no hangs, no crashes.

The format tables in `docs/regf-format.md` were additionally validated
against genuine Windows hives during development, which caught two layout
bugs the synthetic round-trips could not (a shared-assumption blind spot).
Test hives are deliberately not shipped with the repository.

## Acknowledgments

The **Reports** feature — 150 RegRipper-style forensic plugins — is a
JavaScript reimplementation of the plugin layer of **RegRipper**, the
Windows registry analysis tool by **H. Carvey (keydet89)**:

- [RegRipper 4.0](https://github.com/keydet89/RegRipper4.0) — the plugin
  corpus the ports follow (386 plugins; see
  [`docs/regripper-plugins.md`](docs/regripper-plugins.md))
- [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0) — the earlier,
  MIT-licensed release
- [regripper.wordpress.com](https://regripper.wordpress.com/) — RegRipper
  home page

The plugin architecture (`src/plugins/30-runtime.js`, `32-simple.js`),
shared helpers (`src/plugins/31-helpers.js`, ported from
`rr_helper.pl`/`time.pl`), and all 17 bespoke + 133 descriptor-driven plugin
reports are ports of RegRipper plugins. The Perl reference corpus
(`supporting/RegRipper4.0`) is deliberately **not** shipped with this
repository (see `.gitignore`); it is never executed or linked against.

**License note:** RegRipper 3.0 is MIT-licensed; RegRipper 4.0 is free for
personal and academic use **only** and may not be included in any
distribution. HiveWalker's ports are offered for the same personal/academic
DFIR use. Full details in [`NOTICE.md`](NOTICE.md).

## Known limitations

- Transaction-log (`.LOG1`/`.LOG2`) replay is out of scope (matching
  RegRipper); a dirty-hive note appears in the metadata panel.
- Deleted/unallocated cells are not enumerated — this is a live view.
- Security descriptors are shown as refcounts only.

## License

Copyright (C) 2026 HiveWalker contributors

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version. See [LICENSE](LICENSE).
