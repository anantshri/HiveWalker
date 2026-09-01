# Detailed Changelog

The long-form companion to `CHANGELOG.md`. Where `CHANGELOG.md` says *what*
changed in one line, this file records *why* and *how* — enough for a future
reader to audit, reproduce, or roll back any change without re-deriving it.

Add a new entry (newest first) for every meaningful change. Use the template
below; drop sections that genuinely don't apply.

---

## 2026-09-01 — Remove shipped test hives (regipy fixtures)

**Summary:** The six real-hive test fixtures (and their loader) are removed
from the repository; the CI smoke test now uses the synthetic builder. No
parser or app code changed.

**Why:** Operator decision — the binary hive artifacts should not live in
the GitHub repo. The historical entries below still mention regipy because
they record what was done at the time; the fixtures themselves are gone.

**What changed:**
- Deleted `tests/fixtures/` (six `.xz` hives + README + .gitignore),
  `tests/fixtures.test.js`, and `tests/helpers/fixtures.js`.
- `.github/workflows/ci.yml` smoke test now writes a synthetic hive via
  `tests/helpers/hive-builder.js` and dumps it text+JSON — no fixture
  dependency.
- README / CHANGELOG / docs/regf-format.md: removed fixture-shipping claims
  and regipy attribution; the correctness story now rests on synthetic
  round-trips + fuzz, with a note that format tables were validated against
  real hives during development (hives not shipped).
- `.gitignore`: no fixtures entry needed (nothing to ignore — files deleted);
  `supporting/`, `logs/`, `plans/` remain ignored as before.

**How / commands run:**
```
node --test        # 131 pass (was 146; the 15 fixture tests are gone)
node bin/dump-hive.mjs /tmp/smoke.reg --json   # CI smoke path verified
```

**Verification:** 131/131 remaining tests pass; CLI smoke (text + JSON)
verified locally; `aidc-scan --all` clean; grep shows no regipy references
in shipped files (only this audit log's historical entries and local-only
`logs/`).

**Notes / follow-ups:** If real-hive regression coverage is wanted later,
the loader pattern can be reintroduced pointing at locally-supplied hives
(never committed). The two nk-layout bugs those fixtures caught remain
covered by unit tests with hand-crafted bytes (`sk-and-softpaths.test.js`).

---

## 2026-09-01 — v0.1.0: naming (HiveWalker), logo, release readiness

**Summary:** The project got its final name, a logo, and everything a first
GitHub release needs: LICENSE, release-grade README, .gitignore for the
non-distributable reference copy, a CI workflow, a slimmed fixture layout,
and a tagged changelog entry.

**Why:** User request items 1–3: a conflict-free name, a good logo, and
GitHub release readiness.

**What changed:**
- **Name: HiveWalker.** Verified free before adoption: 0 GitHub repos with
  the name (search API), GitHub username `hivewalker` available (404),
  npm/PyPI/crates.io/Docker Hub/GitLab all clear; the only trace anywhere is
  an unrelated Warcraft-modding site. Runner-up "RegPeek" was rejected for
  sounding near RegSeeker/RegScanner/RegSeek. `package.json` renamed to
  `hivewalker` (MIT, keywords, repo URL), lockfile regenerated, HTML
  `<title>`/brand/meta-description updated.
- **Logo:** `docs/logo.svg` — three amber honeycomb cells (the "hive") with
  a blue key-tree path walking through them; the same art is the
  `favicon.svg` wired via `<link rel="icon">` and shown in the top bar and
  welcome card.
- **LICENSE:** MIT (the aidc license gate requires one for releases).
- **README:** release-grade rewrite — centred logo header, badges
  (MIT/146-tests/0-dependencies/100% local), getting-started, an explicit
  privacy section, value-type table, and the two-legged correctness story.
- **Repo hygiene:** `.gitignore` now excludes `supporting/` (RegRipper is
  personal/academic licensed — must not ship in a public repo) with a
  comment saying why; decompressed fixtures untracked (52 MB → 5.8 MB of
  `.xz` in git) with `tests/helpers/fixtures.js` decompressing on demand
  (`xz`, falling back to `tar -xJf` for Windows CI) and tests still skipping
  gracefully when absent.
- **CI:** `.github/workflows/ci.yml` — npm test + coverage on
  Ubuntu/macOS/Windows, a CLI smoke test against a real fixture, and a
  release-artifact job asserting every `index.html` asset exists, LICENSE +
  package metadata match, and runtime deps are zero.
- **CHANGELOG:** 0.1.0 release section consolidated (the historical
  Added/Fixed detail had duplicated section headers; rewritten as one clean
  first-release entry).

**How / commands run:**
```
curl https://api.github.com/search/repositories?q=hivewalker   # total_count: 0
curl https://registry.npmjs.org/hivewalker                     # Not found
curl https://api.github.com/users/hivewalker                   # 404 (free)
npm i --package-lock-only                                      # 0 vulnerabilities
node --test                                                    # 146 pass
```

**Errors encountered & resolution:** one garbled line (`console长的`) slipped
into ci.yml while drafting the dependency-count check — caught on re-read
and fixed; the checks were then validated locally (asset scan + dep count).

**Verification:** 146/146 tests with fixtures freshly decompressed from the
tracked `.xz`; `aidc-scan --all` clean; ci.yml checks run by hand locally;
logo renders in the app shell (welcome card + top bar + favicon).

**Notes:** the repository URL in `package.json` is a placeholder
(`github.com/example/HiveWalker`) — set the real owner/name at push time.
GitHub username `hivewalker` being free means the org/project can live at
`github.com/hivewalker/HiveWalker` if wanted.

---

## 2026-09-01 — Tree UX: click-to-open, keyboard nav, resizable panes, path bar

**Summary:** Five UI improvements requested after first use: clicking a tree
entry with subkeys opens it; the tree/values panes are resizable; a path bar
with breadcrumb + copy sits atop the values pane; arrow keys navigate the
tree; the Hive Info panel got a close button.

**Why:** User feedback (items 1–5). The original tree only expanded via the
small twisty, panes were fixed-width, the selected key's path was buried in
the header text, and the Hive Info overlay could only be dismissed with
Escape.

**What changed:**
- `src/ui/22-tree.js` — row click now selects AND toggles branches open
  (twisty click still toggles without selecting). Keyboard navigation:
  `visibleRows()` walks rendered rows in document order; ArrowUp/Down move
  selection (skipping collapsed branches), ArrowRight opens then enters,
  ArrowLeft closes then goes to the parent, Enter/Space toggle, Home/End.
  Collapsing a branch re-parents the active key if it was inside. The pane
  is focusable (`tabIndex`); `main.js` also forwards unhandled arrow keys
  globally so navigation works right after a mouse click.
- `src/ui/23-values.js` — new sticky path bar: one crumb per path segment
  (click navigates to that ancestor), '›' separators, and a copy button
  (clipboard API with a select-text fallback for `file://`). LastWrite and
  warning count moved to a compact header line.
- `src/ui/28-resizer.js` (new, registered in index.html) — 6px drag handle
  injected as a grid column between the panes; clamped 160px…80% width,
  persisted to `localStorage` when available, double-click resets.
- `src/ui/26-hivemeta.js` / `24-hexview.js` — explicit ✕ close buttons
  (Escape still works everywhere); `hivemeta.hide()` exported.
- `src/styles.css` — path bar, resizer (hover/drag accent, col-resize
  cursor, user-select suppression while dragging), panel-close, tree focus
  ring; panes grid gains a `160px+6px+1fr` template when resized.
- Tests: `tests/tree-nav.test.js` (9 cases: click-open/close, twisty
  isolation, all arrow semantics, skip-collapsed, active-key re-parent on
  collapse) and `tests/pathbar-meta.test.js` (4 cases: crumb segments,
  crumb-click ancestor navigation, meta ✕, resizer drag applies grid
  columns) on an enriched DOM stub; `tests/e2e-ui-sim.js` (direct-run
  simulation) exercises all five features through `RV.ui.app`.

**How / commands run:**
```
node --test                          # 144 pass (131 prior + 13 new)
node tests/e2e-ui-sim.js             # all five features verified
aidc-scan                            # clean
```

**Errors encountered & resolution:**
- Crumb-click used `target = key.parent` inside the loop instead of
  `target = target.parent`, so deep crumbs only went up one level — caught
  by the crumb-navigation test.
- The DOM stub didn't clear children on `textContent` assignment, so stale
  path bars accumulated and tests read the first (oldest) bar; the stub now
  models that DOM behaviour.
- The resizer test initially grabbed the handle created by `main.js`'s own
  `init` (loadSrc executes main.js headlessly) while calling the test's
  `init` mousemove — two closures, two `dragging` flags. The test now uses
  the last handle from its own init. A comment mentioning an id starting
  with `#` also had to be reworded (JS private-field parse error).

**Verification:** 144/144 tests; e2e simulation shows click-to-open, handle
creation, `root›Software›Microsoft` crumbs, ArrowDown selection, and ✕
closing the Hive Info panel; scan clean.

**Notes:** The resizer persists via `localStorage` when the browser grants
it (plain `file://` may not; the code degrades silently). Keyboard nav is
also bound at document level but ignored while typing in inputs.

**Follow-up fix (same day):** the resizer handle was injected at startup and
dangled beside the welcome card before any hive was loaded. `init` now
guards on `#app[data-state] === 'loaded'` (the state lives on `#app`, not
`#panes` — first attempt read the wrong element), `app.js` initialises the
resizer after `showPanes()`, `main.js` no longer calls it at startup, and
CSS additionally hides `#pane-resizer` outside the loaded state plus renders
welcome/error states as a single centred block instead of a two-column grid.
Resizer tests moved to `tests/resizer.test.js` (the empty-state check must
run before any `loadFile` initialises the one-shot `init`); added
idempotence and handle-count assertions. 146/146 tests.

---

## 2026-08-31 — Real-hive fixtures + nk layout corrections

**Summary:** Downloaded six genuine Windows hive files (regipy's MIT-licensed
test fixtures) and wired them into the suite as regression tests — which
immediately exposed and then proved the fix for two real bugs: the `nk`
name-length and value-count field offsets were wrong, so every key on a real
hive decoded with an empty name and no values.

**Why:** The synthetic round-trip tests couldn't catch a wrong offset shared
by both the builder and the parser (they agree with each other, not with
Windows). Only real hives provide independent ground truth.

**What changed:**
- `tests/fixtures/` — SAM (256 KB), SECURITY (32 KB), NTUSER.DAT (768 KB),
  UsrClass.dat (2.8 MB), SYSTEM (11.7 MB), SOFTWARE (37.7 MB) from
  `raw.githubusercontent.com/mkorman90/regipy/master/regipy_tests/data/*.xz`,
  plus a README with provenance, ground truth, and re-download commands.
- `src/reg/00-const.js` — classic `nk`: `nameLen` 0x44→**0x48**,
  `classLen` 0x46→**0x4A** (name still starts 0x4C; the intervening u32 at
  0x44 is an unnamed field); swapped `valueCount` (now **0x24**) with
  `volValueCount` (now 0x20). `CM_KEY_NODE` table shifted to match (+9).
- `src/reg/06-nk.js` — `0xFFFFFFFF` subkey/value counts mean "none" (real
  hives use this on value-less keys) instead of tripping the implausible-
  counts warning.
- `src/reg/04-regf-block.js` — embedded filename now truncates at its NUL
  terminator (real hives carry garbage in the padding).
- `tests/helpers/hive-builder.js` — writes the corrected layout (unk u32 at
  0x44, volatile count -1 at 0x20).
- `tests/fixtures.test.js` — 15 regression tests: per-hive walk counts and
  structure, value-level ground truth (SYSTEM `Select` DWORDs Current=1
  Default=1 Failed=0 LastKnownGood=2; NTUSER.DAT `Environment` TEMP/TMP =
  `%USERPROFILE%\\AppData\\Local\\Temp` as EXPAND_SZ; SAM user RIDs encoded
  in the (Default) value *type*: Administrator 0x1F4, Guest 0x1F5, Preston
  0x3E8; SAM `F`/`V` binary blobs; UsrClass SID root name; metadata
  versions/dirty flags; whole-hive decode-safety sweep).
- `docs/regf-format.md` — corrected tables + a verification note.

**How / commands run:**
```
cd tests/fixtures && curl … && xz -d …        # fetch + decompress
node bin/dump-hive.mjs tests/fixtures/SAM     # inspect before/after fixes
node --test tests/fixtures.test.js            # 15 pass
node --test                                   # 131 pass, 0 fail
aidc-scan --all                               # all scanners ok/clean
```

**Errors encountered & resolution:**
- First real-hive run showed empty key names and `implausible counts`
  warnings on every root. Hex-dumped genuine `nk` records (NTUSER.DAT
  "Control Panel", "Environment") against my table: nameLen lives at 0x48
  not 0x44, and Console=24/Environment=2/Identities=6 proved valueCount is
  at 0x24 with the *volatile* count at 0x20. Fixed both tables + builder.
- `0xFFFFFFFF` value counts on real roots initially read as corrupt; they
  mean "none" and are now normalised to 0.
- Embedded filenames rendered with CJK garbage — the 128-byte field is
  NUL-padded and must truncate at the terminator.
- Two initial `mustContain` guesses (full paths instead of root children)
  were corrected after listing actual root children.

**Verification:** 131/131 tests (116 prior + 15 new fixture regressions);
all six hives walk cleanly (65/100/1812/6205/30756/117488 keys with
70/109/4094/12369/73456/193870 values); known values byte-exact against
ground truth; `aidc-scan --all` clean.

**Notes / follow-ups:** The fixtures are 57 MB on disk — kept uncompressed
for test speed; `.xz` re-download instructions are in
`tests/fixtures/README.md`. regipy also ships a deliberately corrupted
SYSTEM hive and transaction-log pairs (`transactions_NTUSER.DAT`,
`*.LOG1/2`) that would make good future additions for dirty-hive and
log-replay testing. Fixture absence degrades to a skip, so the suite still
runs anywhere without the download.

---

## 2026-08-31 — Web-based registry hive viewer (initial implementation)

**Summary:** Built the entire application from `plan.md`: a pure client-side
regf hive parser and a regedit-style UI, plus a CLI dump tool and a
116-test suite. Opening `index.html` and picking a hive file now parses and
displays it entirely in the browser.

**Why:** `plan.md` asked for an HTML/CSS/JS registry viewer that
deconstructs a hive file and shows its contents regedit-style, using
`supporting/RegRipper4.0` as the parsing-behaviour reference. The plan
(`plans/golden-inventing-kahn.md`, user-approved with edits) fixed the
constraints: pure client side, no vite/build step, no local server, classic
`<script src>` only — the app must run from `file://`.

**What changed:**
- `index.html` — app shell (three panes, top bar, status bar) + the ordered
  classic script list creating the single `RV` global namespace; this list is
  the single source of truth for load order.
- `src/reg/00-const.js` — signatures, REG_* types, nk flag bits, and the
  per-signature offset tables (`NK_LAYOUTS`/`VK_LAYOUTS`/`SK_LAYOUTS`) for
  both classic and Win10 1709+ (`CM_KEY_*`) layouts, plus safety limits.
- `src/reg/01-buffer-reader.js` — the only byte-access path; every read
  bounds-checked, throwing `RegistryParseError(message, offset)`.
- `src/reg/02-filetime.js`, `03-utf16.js` — BigInt FILETIME conversion
  (ports `time.pl` `getTime` without its float precision loss) and tolerant
  UTF-16LE decoding + GUID formatting (ports `rr_helper.pl`
  `getUnicodeStr`/`parseGUID`).
- `src/reg/04-regf-block.js`, `05-hbin.js` — base-block parse (checksum is
  warn-only; missing `regf` sig is a hard reject) and the hbin directory +
  cell accessor (offsets relative to first hbin; `optOffset` normalises the
  `0xFFFFFFFF` sentinel).
- `src/reg/06-nk.js`, `07-vk.js`, `08-sk.js` — record parsers with
  signature-dispatched layouts, KEY_COMP_NAME/VALUE_COMP_NAME name decoding,
  and the vk inline-data rule (high bit set → bytes live in the data-offset
  slot; `inlineDataAbs` recorded for the raw-data fetch).
- `src/reg/09-subkey-list.js`, `10-value-list.js` — iterative resolvers with
  a visited set (cycle guard) and room-based entry clamping; unknown
  subkey-list signatures warn instead of throwing.
- `src/reg/11-value-data.js` — all REG_* decoders + regedit-style display
  strings (hex notes for DWORD/QWORD, GUID decoration for 16-byte binaries
  under GUID-ish names, multi-SZ join).
- `src/reg/12-hive.js`, `13-index.js` — `RegfHive`/`NkKey`/`VkValue` facade
  (lazy subkeys/values, case-insensitive `getSubkey(path)`, iterative
  `walk()`, `countAll()`, `search()`), frozen namespace.
- `src/ui/20-view-model.js` — pure state→view-model functions (tree node,
  values pane, hex rows, hive metadata, status bar): the DOM-free seam the
  Node tests exercise.
- `src/ui/21-app.js` … `27-statusbar.js` — thin DOM binders: app
  orchestration and file loading, lazy tree with warning badges, values
  table, windowed hex viewer, debounced incremental search grouped by key
  path, hive-metadata panel with the dirty-hive note, status bar with a
  cancellable count-all. All hive-derived text goes through `textContent`.
- `src/main.js`, `src/styles.css` — browser entry (file input, drag-drop,
  search wiring, Escape handling) and regedit-like CSS (light/dark via
  `prefers-color-scheme`).
- `bin/dump-hive.mjs` — CLI verification aid (text/JSON), loading the parser
  through the index.html script list.
- `tests/` — 116 node:test cases: byte-layer units, regf/hbin/cells, nk/vk
  records, subkey/value lists, decoders, facade behaviour, view-models, plus
  `hive-roundtrip.test.js` (seeded random trees × 4 list styles × 2 nk
  layouts, deep-compared against the builder's independent expectation) and
  `fuzz-resilience.test.js` (flip/truncate/zero mutations; invariant =
  `RegistryParseError` or partial structure with warnings, never a hang or
  hard crash).
- `tests/helpers/` — `load-src.js` (runs the index.html script list under
  Node via `vm.runInThisContext`, with a minimal `document` stub so DOM
  binders can load), `hive-builder.js` (synthetic hive writer sharing only
  the format spec with the parser), `mutate.js` (byte mutations + seeded
  PRNG).
- `docs/regf-format.md` — the offset tables this implements, with
  provenance and known limitations; `README.md` — usage, features,
  development commands, limitations.
- `package.json` — scripts only (`test`, `test:coverage`, `dump`, `scan`);
  zero runtime and dev dependencies; `package-lock.json` generated solely
  so `npm audit` has an input (reports 0 vulnerabilities).

**How / commands run:**
```
node --test                                      # 116 pass, 0 fail
node --test --experimental-test-coverage        # parser modules 94–100%
aidc-scan --all                                  # all scanners ok/clean
node bin/dump-hive.mjs /tmp/test-hive.reg        # text dump verified
node bin/dump-hive.mjs /tmp/test-hive.reg --json # JSON dump verified
npm i --package-lock-only                        # 0 vulnerabilities
```

**Errors encountered & resolution:**
- `window is not defined` under the Node loader → the loader now executes
  the inline bootstrap from index.html too and aliases
  `globalThis.window = globalThis`.
- `CM_KEY_NODE`/`CM_KEY_VALUE` signature lengths miscounted (10/11 vs the
  real 11/12) — the builder wrote short signatures and the parser's offset
  shift was wrong. Fixed by measuring the actual strings, shifting fields by
  +9 (nk) / +10 (vk), and adding CM round-trip tests that caught it.
- Builder bugs found by tests and fixed: subkey-list count written at the
  wrong payload offset (flags slot that doesn't exist in lf/lh/li/ri);
  `childRels` passed as record objects instead of `.rel` (entries were all
  zero); child nk parent fields never patched (parents read 0); missing
  VALUE_COMP_NAME flag made names decode as UTF-16; missing 2-byte spare
  before vk names shifted names by 2; `0x80000000|n` fed to `writeUInt32LE`
  as a negative (needed `>>> 0`); hbin headers overwritten by the cell body
  copy (cells must start after each hbin's 0x20-byte header).
- Parser bugs found by tests and fixed: subkey-list signature sniffing
  compared a 4-char read against 2-char signatures (never matched);
  `optOffset` collapsed `0xFFFFFFFE` to null (only the exact sentinel is
  "none"); corrupt child nks threw from `k.name` instead of degrading
  (getSubkeys now force-parses inside its try/catch).
- `node --test tests/` (directory arg) errors with "Cannot find module" —
  plain `node --test` auto-discovery is used instead.

**Verification:** 116/116 tests pass; fuzz invariants hold over 800
mutations; `aidc-scan --all` fully clean; `dump-hive` output inspected for a
synthetic hive (values, types, timestamps, warnings); the full browser flow
(load → tree render → selection → values pane → status bar) exercised
end-to-end under a DOM-stub simulation since no GUI browser is available in
this container.

**Notes / follow-ups:** Transaction-log replay, deleted-cell enumeration,
and security-descriptor decoding are documented non-goals. Real-hive
fixtures would strengthen verification further — none are bundled or
downloaded; if a genuine hive is supplied, `node bin/dump-hive.mjs <hive>`
is the ready-made diff path against RegRipper output. DOM binder coverage
(22-tree.js etc.) is low under Node by construction — their logic lives in
the 100%-covered view-models; a headless-browser test would be the way to
close that gap if ever needed.
