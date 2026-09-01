# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Keep this file high-level: one bullet per user-visible change, grouped under the
right heading. Record the blow-by-blow detail (commands, diffs, reasoning) in
`DETAILED_CHANGELOG.md` instead.

## [Unreleased]

### Added

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
