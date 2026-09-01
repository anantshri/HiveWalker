# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Keep this file high-level: one bullet per user-visible change, grouped under the
right heading. Record the blow-by-blow detail (commands, diffs, reasoning) in
`DETAILED_CHANGELOG.md` instead.

## [Unreleased]

### Added

- **Viewer / Reports tabs:** the main area is now two workspaces — the
  regedit-style **Viewer** and a full-width **Reports** tab (previously a
  640px slide-over). The Reports workspace has a filterable plugin rail
  (search 150 plugins by name/description/category/MITRE), a toolbar, and
  much more room for report output. Tab state is kept per-view: switching
  back to the Viewer preserves tree expansion and selection
  (`Ctrl+1`/`Ctrl+2` switch, `Esc` returns from Reports).
- **PDF export:** "Export PDF" downloads the displayed report(s) as a real
  PDF — cover page with the loaded hive's info, report content from page 2,
  A4, paginated, monospace tables, and a running footer with page numbers
  plus a **clickable link back to https://anantshri.github.io/HiveWalker/**.
  Implemented by a hand-rolled ~200-line PDF writer (Base-14 fonts, no font
  embedding) so the app stays **zero-dependency**; generation and download
  are entirely local. Non-Latin-1 characters are substituted and noted in
  the footer; copy-to-text export remains fully lossless.

### Fixed

- Footer no longer occupies ~half the window before a hive is loaded (grid
  rows shifted while the tab bar was hidden).
- Reports tab now lays out as intended — filterable plugin rail on the left,
  scrollable results on the right (the workspace grid was being overridden
  by the tab-visibility rule).

- **Reports (RegRipper-style plugins):** a new top-bar **Reports** panel that
  lists forensic plugins applicable to the loaded hive, runs one (or all
  applicable) and shows decoded, labelled output as sections/tables with a
  one-click copy to RegRipper-style plain text. First batch of 17 plugins —
  System: `compname`, `timezone`, `shutdown`, `services`, `usbstor`, `ips`,
  `mountdev`; Software: `winver`, `uninstall`, `run`, `profilelist`,
  `networkcards`; NTUSER: `userassist` (ROT13-decoded), `recentdocs`,
  `typedpaths`, `runmru`; SAM: `samparse` (reduced). All parsing stays local —
  no new dependencies, no network. New extension point at `src/plugins/`.
- **Bulk plugin import (133 more):** a descriptor-driven engine
  (`src/plugins/32-simple.js`) plus 133 auto-imported RegRipper 4.0 plugins
  that follow regular key/value/subkey read patterns, bringing the Reports
  panel to **150 plugins**. The ~114 remaining report-type plugins need bespoke
  decoders (nested-subkey traversal, binary structures, runtime-built paths,
  conditional logic) and are a documented follow-up — none were skipped for
  needing user intervention.
- **RegRipper porting guide & tooling:** `docs/regripper-plugins.md` (corpus
  breakdown, architecture, descriptor schema, per-plugin status) with
  `docs/regripper-plugin-status.json` (all 386 plugins tracked), plus a
  reproducible pipeline in `scripts/regripper/` (`analyze` → `extract` →
  `assemble` → `status`) so the import exercise is never re-derived by hand.
- GitHub links in the app: top-bar link, welcome-card link, and a page
  footer with copyright, GPLv3 license link, GitHub link, and the
  local-parsing note. Repository metadata (`repository`, `homepage`,
  `bugs`) now points at anantshri/HiveWalker.
- README privacy section updated to reflect the Plausible analytics on the
  deployed site (domain-bound, cookieless, silent on localhost/file://)
  while keeping the hive-data-stays-local guarantee.
- Plausible analytics: SRI deliberately omitted (operator-accepted risk —
  lets Plausible rotate the script without breaking analytics; the script is
  domain-bound and silent on localhost/file://), with a documented
  `nosemgrep` suppression for the corresponding scanner rule.

## [0.1.0] - 2026-09-01

First public release: **HiveWalker** — walk the Windows registry, hive by
hive, entirely in your browser.

### Added

- Pure client-side regf parser (`src/reg/`): base block, hbin/cell
  directory, `nk`/`vk`/`sk` records in classic and Win10 1709+ `CM_KEY_*`
  layouts, `lf`/`lh`/`li`/`ri` subkey lists, all REG_* value decoders, and a
  lazy fail-soft traversal facade (`walk()`, `countAll()`, `search()`).
- Regedit-style UI: key tree with click-to-open and full keyboard navigation
  (↑/↓/→/←/Enter/Home/End), values table with hex viewer, breadcrumb path
  bar with one-click copy, incremental search, hive-info panel, resizable
  panes (persisted), drag-drop file opening.
- `bin/dump-hive.mjs` CLI that dumps a hive as text or JSON.
- Test suite (node:test, zero dependencies): property round-trips against
  an independent synthetic-hive builder across both key layouts and all four
  subkey-list styles, plus fuzz invariants (bounds-checked reads, no
  hangs/crashes on corrupt input). The format tables were validated against
  genuine Windows hives during development; test hives are not shipped.
- GPLv3 (GPL-3.0-or-later) licensing, project logo and favicon, CI workflow
  (Linux/macOS/Windows + release-artifact checks).

### Fixed

- `nk` field offsets corrected against real hives: `nameLen`/`classLen` at
  0x48/0x4A, and the value-count region holds the *volatile* count at 0x20
  with the real count at 0x24 (previously every key on a genuine hive
  decoded with an empty name and zero values). `0xFFFFFFFF` counts are
  treated as "none".
- The embedded hive filename stops at its NUL terminator instead of decoding
  all 128 bytes.
