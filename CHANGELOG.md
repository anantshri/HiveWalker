# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Keep this file high-level: one bullet per user-visible change, grouped under the
right heading. Record the blow-by-blow detail (commands, diffs, reasoning) in
`DETAILED_CHANGELOG.md` instead.

## [Unreleased]

### Added

- **Infosec/DFIR plugin pack (9 new, issue #6):** decode/synthesis plugins that
  surface meaning rather than dump keys — `firewallrules` (decode Windows
  Firewall rule strings; flag inbound-allow and binaries in writable paths),
  `svcunquoted` (unquoted service `ImagePath` + writable-binary privesc),
  `winrm` (PSRemoting exposure and Basic/Unencrypted/TrustedHosts=* weak auth),
  `appcompatlayers` (per-exe compat shims incl. `RUNASADMIN` elevation),
  `officetrust` (Office Trusted Documents — files where the user enabled
  macros), `officemru` (recently opened Office documents with times),
  `comhijack` (user-hive COM `InprocServer32`/`TreatAs` hijacks to writable
  paths), `pcaexec` (Program Compatibility Assistant execution evidence), and
  the flagship `execsummary` (a cross-artifact execution timeline merging
  UserAssist + BAM/DAM + Amcache + ShimCache, time-sorted). All pure-registry,
  no backend; MITRE-tagged.
- **Crypto/DFIR/offense expansion (21 new plugins, 171 total):** SAM account
  details + NT/LM hash extraction (`samparse` F/V decode, new `samhashes`
  with XP-generation decryption via the SysKey bootkey), Amcache.hve support
  (`amcache_file`/`amcache_app`, Win8 + Win10 shapes), ShimCache
  (`shimcache`, XP→Win10 formats), BAM/DAM execution traces, scheduled tasks
  incl. hidden-task detection (`taskcache`), network profiles
  (`networklist`), outbound RDP (`tsclient`), Explorer searches
  (`wordwheelquery`), mount history (`mountpoints2`, `emdmgmt`,
  `wpdbusenum`, `portabledevices`), Open/Save MRUs (`opensavepidl`), the
  SECURITY-hive pack (`machine_sid`, `auditpol`, `lsasecrets`), a
  consolidated autostart sweep with StartupApproved decode (`autostarts`),
  a defense-posture audit (`defposture`) and an offline accesschk for
  service-key ACLs (`svcacls`, T1574.011). New hand-rolled crypto
  (MD4/MD5/SHA-1/RC4/DES/3DES/AES, spec KATs) and binary decoders (SID,
  security descriptors, ShimCache, SAM F/V) with provenance in
  `docs/crypto-notes.md`; unverified derivations report data undecrypted
  rather than guessing.
- **Multi-hive sessions:** load several hives at once (multi-select,
  multi-file drop, `+ Add hive…`) with a topbar hive switcher. Cross-hive
  plugins (SAM hash decryption, LSA secrets) use the session — attach SYSTEM
  alongside SAM, re-run, and `samhashes` decrypts via the bootkey. Session
  changes prompt a re-run instead of silently re-running.

- **RegRipper acknowledgment:** the Reports plugin layer is now properly
  credited to its source, **RegRipper by H. Carvey (keydet89)** — new
  [`NOTICE.md`](NOTICE.md), an Acknowledgments section in the README, and
  attribution in the generated plugin descriptors. License facts recorded:
  RegRipper 3.0 is MIT; RegRipper 4.0 is personal/academic-use only (no
  distribution), which is why the Perl corpus stays unshipped.

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

### Changed

- MITRE ATT&CK markers audited against the released **v19.2** STIX bundle and
  updated for the v19 renumbering: `T1562`/`T1562.001` → `T1685`, `T1562.004` →
  `T1686`, `T1101` → `T1547.005`, `T1128` → `T1546.007` (across the offense
  pack, the new infosec pack and the RegRipper descriptors). The descriptor
  generator now carries a renumber map so future regenerations stay current.
  Every remaining technique ID was verified to exist and be non-revoked. A
  follow-up semantic-correctness pass (does the technique actually *describe*
  the artifact?) unmapped six execution-*evidence* plugins that were tagged with
  ill-fitting techniques — `bam`, `userassist`, `runmru`, `officemru`,
  `pcaexec` (were T1059/T1204) and `execsummary` — matching the existing
  `shimcache`/`amcache` convention of leaving forensic data-source artifacts
  untagged.
- CI/CD moved to Node 24, and every GitHub Action is pinned to its latest
  release: `checkout` v7.0.1, `setup-node` v7.0.0, `configure-pages` v6.0.0,
  `upload-pages-artifact` v5.0.0, `deploy-pages` v5.0.1 (bumped from v5.0.0),
  `upload-artifact` v7.0.1. Pins stay full-commit-SHA with the exact version in
  the trailing comment.

### Fixed

- Deployed releases now cache-bust every local asset. The site loads ~50
  unbundled scripts straight from `index.html`, so a new release could leave a
  browser running a *mix* of old and new files — the failure mode behind a
  recent blank PDF export (the writer's page-tree numbering was updated but a
  cached copy computed `/Kids` the old way). Deploy now stamps each local
  `src`/`href` with a `?v=<content-hash>` query, so browsers re-fetch exactly
  the files that changed and can never blend versions.
- Exported PDFs no longer open as corrupt/blank in strict viewers. The
  writer's per-page object numbering was off by one slot: `/Kids` pointed at
  content streams instead of `/Type /Page` objects, each page's `/Contents`
  referenced its link annotation, and `/Annots` referenced the page itself.
  The reference graph now resolves correctly; a regression test walks it
  (Kids → Page → stream `/Contents`, Link `/Annots` with `/P` back-pointer).
- Values pane renders beside the tree again on fresh sessions. The panes grid
  had only two tracks while the loaded DOM has three children (tree, resizer
  handle, values) — the values pane auto-placed to a second row whenever the
  resizer hadn't yet written its saved-width inline style. The grid now has
  three tracks and each pane is pinned to its column.
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
