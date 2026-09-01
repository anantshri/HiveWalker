# Detailed Changelog

The long-form companion to `CHANGELOG.md`. Where `CHANGELOG.md` says *what*
changed in one line, this file records *why* and *how* — enough for a future
reader to audit, reproduce, or roll back any change without re-deriving it.

Add a new entry (newest first) for every meaningful change. Use the template
below; drop sections that genuinely don't apply.

---

## 2026-09-01 — PDF export fix: per-page object numbering was off by one slot

**Symptom:** `hivewalker-report-*.pdf` downloads flagged as corrupt (or
rendered blank) by strict PDF viewers, e.g. the 166KB
`hivewalker-report-all-57plugins-20260901-1828.pdf` produced via Reports →
Run all → Export PDF.

**Diagnosis:** the file's byte structure was sound — all 89 xref offsets
matched their `N 0 obj` declarations exactly, every `/Length` matched the
actual stream bytes, header/trailer/`startxref` were correct. The defect was
semantic: `src/ui/30-pdf.js` emitted each page's three objects in the order
content-stream → link-annot → page (so they landed at slots `6+3i`, `7+3i`,
`8+3i`) but computed references as if the page came first
(`pageNum = base + 3i`, `contentNum = base + 3i + 1`, `linkNum = base + 3i +
2`). Every cross-reference was therefore shifted one slot: `/Kids` listed
content streams, `/Contents` pointed at link annotations, `/Annots` pointed
at the page itself (self-reference), and each annotation's `/P` back-pointer
targeted a content stream. Viewers that build the page tree strictly reject
it; lenient ones render nothing.

**Why tests missed it:** `tests/pdf.test.js` validated xref offsets point at
*some* object declaration, counted `/Type /Page` occurrences, and grepped
content strings — but never resolved the reference graph.

**Change:**

- `src/ui/30-pdf.js`: replaced the three inline computations with named
  helpers matching actual emission order — `contentNumAt(i) = base + 3i`,
  `linkNumAt(i) = base + 3i + 1`, `pageNumAt(i) = base + 3i + 2` — used for
  `/Kids`, `/Contents`, `/Annots`, and the annot `/P` back-pointer alike.
- `tests/pdf.test.js`: new test `makePdf: reference graph resolves` — parses
  objects, walks catalog → pages tree → each Kid asserting it is a `/Type
  /Page`, its `/Contents` is a stream object, its `/Annots` are Link
  annotations whose `/P` points back at that page, and that no object
  self-references via `/Contents` or `/Annots` (the off-by-one signature).

**Commands:**

```
node --test tests/pdf.test.js             # 14 pass
node --test                               # 310 pass
node --test --experimental-test-coverage  # 30-pdf.js: 100% lines
aidc-scan                                 # clean (1 Blocking finding fixed en route)
```

**Verification:**

- Confirmed the new test fails against the unfixed writer (stashed the fix →
  `not ok … reference graph resolves`, re-applied → passes) — a true
  regression guard, not a tautology.
- Structural re-validation of the shipped file (xref offsets, `/Length`
  accuracy, EOF) performed with a Python script during diagnosis; the writer
  itself unchanged apart from the numbering. No PDF viewer available in the
  container — operator should open a freshly exported PDF to confirm.

**Security finding (fixed):** `aidc-scan` flagged **Blocking**
`detect-non-literal-regexp` on the new test helper (`new RegExp('/' + key + …)`,
keys hardcoded). Rewritten as a lookup of four literal regexes; scan clean.

**Notes:**

- The corrupted artifact remains in the repo root as the diagnostic exemplar;
  regenerate with Reports → Run all → Export PDF after this fix.
- The off-by-one also explains why permissive viewers could still open the
  file: streams and page dicts were all present and individually valid, only
  the wiring between them was wrong.

---

## 2026-09-01 — Crypto/DFIR/offense expansion: 21 new plugins, multi-hive sessions, in-browser SAM hash decryption

**Why:** the tool covered 150 RegRipper-style plugins but the highest-value
forensic artifacts — account hashes/details, Amcache/ShimCache execution
traces, BAM/DAM, TaskCache, NetworkList, RDP history, the entire SECURITY
hive, defense-posture auditing and service-key ACL review — were all in the
"deferred" bucket (they need bespoke binary decoding, not declarative
descriptors). The user (security professional) chose the full sweep
including the offense pack, plus full in-browser hash decryption via
SAM+SYSTEM sessions.

**What changed:**

- `src/crypto/00-util.js`–`08-selftest.js` — hand-rolled MD4 (RFC 1320),
  MD5 (RFC 1321), SHA-1 (FIPS 180-1), RC4, DES + NTLM string-to-key +
  per-RID key schedule (FIPS 46-3/DCE-RPC), 3DES-EDE-CBC, AES-128/256 CBC
  (FIPS 197/SP 800-38A), plus `selfTest()` with all spec KATs. No
  `crypto.subtle` (file:// is not a secure context); no dependencies.
- `src/decoders/00-sid.js`–`03-samfv.js` — SID parse/format + well-known
  map, self-relative SECURITY_DESCRIPTOR parse (MS-DTYP), ShimCache format
  detection/parse (XP/2003/Win7/Win8/8.1/Win10 incl. Creators offset), SAM
  F/V value structures (offsets validated against MIT-licensed regipy as a
  format reference — reimplemented, not copied).
- `src/plugins/33-session.js` + `30-runtime.js` `opts.session` — DOM-free
  multi-hive session store; `ctx.session.byType('system')` for cross-hive
  plugins.
- `src/ui/21-app.js` / `29-reports.js` / `main.js` / `index.html` —
  `loadFiles`/`addHives`/`removeHive`/`setPrimaryHive`, topbar hive
  `<select>` + `+ Add hive…`, multi-file drop, `reports.invalidate()`
  stale-session prompt.
- New plugins: `bootkey`, `shimcache`, `bam`, `wpdbusenum`, `svcacls`
  (40-system); `taskcache`, `networklist`, `emdmgmt`, `portabledevices`
  (41-software); `tsclient`, `wordwheelquery`, `mountpoints2`,
  `opensavepidl` (42-ntuser); `samhashes` + full `samparse` F/V upgrade
  (43-sam); `machine_sid`, `auditpol`, `lsasecrets` (44-security — the
  SECURITY hive previously had zero plugins); `amcache_file`, `amcache_app`
  (45-amcache + hive-type detection); `autostarts`, `defposture`
  (46-offense). 171 plugins total.
- Parser: `readSkDescriptor` (08-sk) + `NkKey.getSecurityDescriptor()`
  (12-hive); `HiveBuilder` gained `security:`/sk-cell emission for
  end-to-end ACL fixtures.
- Docs: `docs/crypto-notes.md` (every constant with its public citation;
  UNVERIFIED entries ship disabled), NOTICE provenance section,
  `docs/regripper-plugins.md` new-plugins table, status JSON updated
  (31 done-bespoke / 12 done-bespoke-new / 161 deferred).

**Deliberate limitations (never-guess policy):** Vista→Win10-1607 SAM RC4
layer and the Win10+ LSA-Secrets AES key schedule are UNVERIFIED against a
primary source — blobs are reported undecrypted with a note instead of
fabricating plaintext. Full shellbag parsing, BCD, SRUM, DCC2 cracking and
DPAPI decryption remain future work (recorded in the plan file).

**Commands run:** `node --test tests/<file>` per phase; `npm test`;
ground-truth cross-checks `openssl dgst -md4 -provider legacy`,
`openssl enc -des-ecb/-aes-256-cbc -provider legacy`, node `crypto` SHA-1.

**Verification:** 307/307 tests pass (55 new: crypto KATs, decoder byte
fixtures, bootkey scramble/decrypt round-trips, encrypt-direction SAM
fixtures that `samhashes` then decrypts, session UI via dom-stub, and
found/not-found/corrupt paths per new plugin). NUL-byte scan clean over all
touched files; `aidc-scan` clean after fixes.

**Notes:** DES/AES were initially written in a compact byte-indexed style
and produced wrong output despite correct tables; both were rewritten in a
direct-from-spec structure and validated against FIPS 81 / FIPS 197 C.1 /
SP 800-38A vectors plus openssl cross-checks — the lesson (validate every
crypto module against published vectors *before* building on it) is now
enforced by `RV.crypto.selfTest()` running in the test suite.

---

## 2026-09-01 — Values pane below tree on fresh sessions (two-track panes grid)

**Symptom:** Operator reported the viewer showing values *below* the tree
instead of in the right panel.

**Diagnosis:** `#panes` declared a two-track grid
(`minmax(200px,30%) 1fr`), but the loaded-state DOM has three children in
order — `#tree-pane`, `#pane-resizer` (pinned `grid-column: 2`), and
`#values-pane`. Auto-placement put the tree in track 1, the resizer in track
2, and the values pane wrapped to a *new row* — below the tree. The bug was
latent from the original release: sessions with a saved resizer width got a
three-track inline style from `28-resizer.js apply()`
(`gridTemplateColumns = "<w>px 6px 1fr"`), which masked it; fresh sessions
(new browser profile, or a different origin such as file:// vs the deployed
site → different localStorage) hit the two-track CSS and broke.

**Fix (`src/styles.css`):**
- `#panes` now declares three tracks: `minmax(200px, 30%) 6px minmax(0, 1fr)`
  — same shape the resizer writes at runtime.
- Each loaded-state child is pinned to its column: `#tree-pane` → 1,
  `#pane-resizer` → 2 (unchanged), `#values-pane` → 3, so future insertions
  can't reshuffle the layout.
- `minmax(0, 1fr)` on the values track so it shrinks instead of overflowing.

**Test changes:**
- `tests/layout-css.test.js`: new guard — the `#panes` template must have
  exactly 3 tracks (counted after collapsing `minmax(a, b)` args, whose
  internal space breaks naive splitting), each pane pinned to its column, and
  the resizer's inline style must stay the same 3-track shape.
- `tests/helpers/dom-stub.js`: the seeded skeleton now mirrors index.html
  faithfully (welcome/error/tree/values inside `#panes`, statusbar in
  `#viewer-tab`, app dataset state/tab) — this surfaced that seeding the
  lazily-created `#meta-pane` shadowed the real one `26-hivemeta.js`
  creates; overlays are no longer seeded.

**How / commands run:**
```
node --test                                  # 233 pass (was 232)
node tests/e2e-ui-sim.js                      # all green (the fixed stub also
                                             #   restored the meta-close step)
aidc-scan                                     # clean
```

**Notes:** the e2e sim had silently depended on the unseeded-meta behavior;
with the faithful skeleton both the layout guard and the sim pass. Worth
hard-checking in a browser: fresh profile → load hive → values render to the
right of the tree, resizer draggable between them.
## 2026-09-01 — Proper RegRipper acknowledgment (NOTICE.md, README, docs)

**Summary:** Added a proper acknowledgment of RegRipper (H. Carvey /
keydet89) across the shipped docs, per issue
[anantshri/HiveWalker#1](https://github.com/anantshri/HiveWalker/issues/1).

**Why:** The Reports feature ships 150 plugin reports ported from
RegRipper's plugin layer (17 bespoke in `src/plugins/40-43`, 133
descriptor-driven in `src/plugins/50-descriptors.js`, plus
`rr_helper.pl`/`time.pl` decode-helper ports in `src/reg/03-utf16.js` and
`src/plugins/31-helpers.js`), yet no shipped file credited the tool, its
author, or its license terms. RegRipper 3.0 is MIT-licensed, but RegRipper
4.0 (the corpus the ports follow) is free for personal/academic use only
and may not be included in any distribution — facts worth recording next
to the ports themselves.

**What changed:**
- `NOTICE.md` (new) — third-party notice naming RegRipper, its author
  (H. Carvey / keydet89), the RegRipper 3.0/4.0 repos and home page, the
  exact derived material (files above), the statement that the Perl corpus
  is not shipped, and both license texts (RR3.0 MIT / RR4.0
  personal-academic-only) with a redistribution caveat.
- `README.md` — "References" section replaced by an "Acknowledgments"
  section (links, derived-material list, license note pointing at NOTICE).
- `docs/regripper-plugins.md` — credit blockquote under the title.
- `scripts/regripper/assemble.js` + `src/plugins/50-descriptors.js` —
  header template/generated header now carry the author + license line so
  regenerated descriptors keep the attribution (mirrored by hand; the
  `supporting/` corpus is not present locally to rerun the generator).
- `CHANGELOG.md` — bullet under [Unreleased] → Added.

**How / commands run:**
```
node --test                                   # 212 pass (docs-only change)
node scripts/regripper/assemble.js            # not run: needs supporting/ corpus (gitignored)
grep -rn "keydet89\|H. Carvey" --include="*.md" --include="*.js" . | wc -l   # ack present in README/NOTICE/docs/descriptors
```

**Verification:** All 212 tests pass; only comments/markdown changed — no
logic paths touched. `src/plugins/50-descriptors.js` still loads (tests
`plugins-descriptors.test.js` exercises all 133 descriptors).

**Notes / follow-ups:** If the project ever needs broader distribution,
port the remaining plugins from MIT-licensed RegRipper 3.0 (or another
permissive corpus) instead of 4.0, or seek the author's permission.

---

## 2026-09-01 — Layout fixes (footer stretch, Reports scroll) + PDF cover page & site link

**Summary:** Fixed two tab-shell CSS bugs reported by the operator (footer
eating half the screen on open; Reports tab not scrolling, plugin list filling
everything), and extended the PDF export with a hive-info cover page and a
clickable link back to the project site.

**Symptoms → diagnosis:**
1. *Footer ~50% on open.* `#app` used `grid-template-rows: auto auto 1fr auto`
   with auto-placement; before a hive loads `#tabbar` is `display:none`, so it
   occupies no grid slot — auto-placement shifted `#page-footer` into the `1fr`
   row where it stretched. Fix: explicit `grid-row` placement for every shell
   element (1 topbar / 2 tabbar / 3 main / 4 footer) + `minmax(0,1fr)` for the
   main row, making rows immune to hidden middle elements.
2. *Reports tab non-scrollable, plugin list fills the space.*
   `#app[data-tab="reports"] #reports-tab { display:block }` (visibility rule)
   outranked the workspace rule `#reports-tab { display:grid;
   grid-template-columns: … }`, so the two-column workspace never applied —
   the rail's `flex:1` scroll area was meaningless inside a block and 150
   plugins stacked full-height under `overflow:hidden`. Fix: visibility rules
   only toggle `display` (active reports = `display:grid`), and the workspace
   columns/overflow live in one canonical `#reports-tab` block declared once
   with the shell; `minmax(0,1fr)` + `min-width:0` on the main column so it
   can actually shrink and scroll.
   No headless browser exists in this container, so these are pinned by
   `tests/layout-css.test.js` — static CSS-invariant regression guards
   (grid-row placement present, active reports rule is display:grid and never
   block, workspace columns + scroll rules exist).

**PDF additions:**
- Cover page (page 1): centred "HiveWalker Forensic Report" title, generated
  timestamp, and the loaded hive's info rows (reusing `viewModel.hiveMeta`).
  Report content starts on page 2. Cover rows truncate (never paginate) so the
  cover is always one page.
- Site link: every page's footer draws the URL
  `https://anantshri.github.io/HiveWalker/` in accent blue with an underline,
  wrapped in a `/Subtype /Link` `/URI` annotation over exactly that text —
  clickable in any PDF viewer.
- Object numbering changed to per-page (content, link-annot, page) triples so
  each page object can reference its annotation; xref offsets recompute
  accordingly (still asserted).

**How / commands run:**
```
node --test                                  # 232 pass (was 225)
node --test --experimental-test-coverage     # 30-pdf.js 100% lines
node tests/e2e-ui-sim.js                      # all green incl. PDF export
aidc-scan                                     # clean
```

**Verification:** new tests — link annotation per page with correct `/URI` and
`/Rect` over the footer line; cover on page 1 (title + generated + hive rows,
no report body) and report from page 2; 80-row cover still one page; plus the
four CSS layout guards. Manual browser eyeball still recommended (no PDF tools
in the container).

## 2026-09-01 — Viewer/Reports tabs + PDF report export

**Summary:** The Reports feature moved from a 640px slide-over panel to a
full-width workspace tab beside the Viewer, gained a filterable plugin rail,
and a one-click **Export PDF** backed by a hand-rolled zero-dependency PDF
writer.

**Why:** User request: (1) "reports and viewer as 2 different tabs so we give
more space to reports", (2) "report should be neatly extractable as PDF". For
(2) the user explicitly chose direct `.pdf` download over print-to-PDF,
accepting a dependency in principle — but a dependency turned out to be
unnecessary: a text-report PDF needs only Base-14 fonts, text operators, and a
correct xref table (~200 lines), which fits this repo's hand-rolled ethos
(the whole regf parser is hand-rolled) and avoids ~350KB of vendored jsPDF +
SBOM/license surface. Flagged to the user at plan approval; plan approved with
the hand-rolled writer.

**What changed:**
- `index.html` — `#tabbar` (Viewer/Reports, `role="tab"` + `aria-selected`),
  main area restructured to `#viewer-tab` (wrapping `#panes` + `#statusbar`)
  and `#reports-tab`; topbar `#reports-btn` removed (superseded by the tab);
  script tag for `src/ui/30-pdf.js`.
- `src/ui/21-app.js` — `currentTab()`/`setTab(name)`: state on
  `#app[data-tab]`, aria sync, topbar search disabled on Reports (it's
  viewer-scoped). Both tabs stay in the DOM → viewer state persists.
  `showPanes()` reveals the tabbar and pre-renders the Reports workspace.
- `src/main.js` — tab click wiring, `Ctrl/Cmd+1|2`, Escape returns from
  Reports to Viewer.
- `src/ui/29-reports.js` — reworked from slide-over to workspace: left rail
  (`#reports-rail`) with `#report-filter` + plugin list (applicable-first,
  category/MITRE badges), main column with Run-all / Export-PDF / Copy and
  `#report-output` result cards. API is now `render()`/`showResults()`
  (tab-driven; `toggle`/`hide` removed).
- `src/ui/30-pdf.js` (new, `RV.ui.pdf`) — minimal PDF 1.4 writer:
  `makePdf(model, {footerBase})` → Uint8Array. A4 portrait, 40pt margins,
  Courier 9 body (monospace keeps tables aligned) + Helvetica/-Bold headers,
  automatic pagination, per-page footer (`<hive> — generated <UTC> — page N/M`
  + unprintable-char note when needed), WinAnsi sanitisation with
  typographic→ASCII mapping and `\ ( )` escaping, correct xref offsets.
  `downloadReportPdf(results, slug)` → Blob + object-URL `<a download>` (URL
  revoked after 5s). `fileNameFor` → `hivewalker-report-<slug>-<stamp>.pdf`.
- `src/ui/20-view-model.js` — new pure `reportPdfModel(results)` flattening
  structured results into styled lines (`title|section|meta|body|note`), the
  DOM-free seam the PDF tests exercise.
- `src/styles.css` — tabbar + tab-visibility rules (`#app[data-tab]`), the
  reports workspace grid (rail + main), rail filter, wider result cards;
  removed slide-over `#reports-pane` rules.
- `tests/helpers/dom-stub.js` — seeded a connected skeleton of index.html's
  static ids (`app/topbar/tabbar/viewer-tab/panes/reports-tab/page-footer`)
  so renders attach into real shared elements; `getElementById` now walks the
  tree (ids assigned after creation resolve like a browser); added
  `setAttribute/getAttribute`, Blob + `URL.createObjectURL` stubs and
  anchor-click download recording.
- Tests: `tests/pdf.test.js` (10 — sanitisation, escaping, xref/offset
  integrity, style→font mapping, pagination + footers, width wrapping,
  replaced-char note, empty model, model flattening, filename);
  `tests/reports-ui.test.js` rewritten for tabs (switching/persistence/search
  scoping, run/filter/copy, error/empty/note branches, PDF download
  validity, corrupt-hive error card); `tests/e2e-ui-sim.js` steps 6–7 now
  drive the tab workflow end-to-end.

**How / commands run:**
```
node --test                                  # 225 pass (was 212)
node --test --experimental-test-coverage     # 20-view-model, 21-app, 29-reports, 30-pdf: 100% lines
node tests/e2e-ui-sim.js                      # tabs, filter, run, run-all, PDF export: all true
aidc-scan                                     # semgrep + gitleaks clean (one Blocking finding
                                             #   in scripts/regripper/extract.js fixed by
                                             #   hardcoding the four %config regexes; output
                                             #   verified byte-identical afterward)
```

**Verification:** PDF structure asserted in tests (header/EOF, catalog/pages,
fonts, xref offsets all point at object declarations, per-page footers, ≤95
char wrapped lines with no character loss); a real download path exercised via
the stubbed Blob/URL (`%PDF-1.4` envelope + report content present in the
bytes); no `pdftotext`/`qpdf` in the container — browser eyeball check pending
operator. Sanitisation: accented Latin passes through (WinAnsi), CJK → `?`
counted and noted in the footer.

**Notes / gotchas:**
- The DOM stub's old `getElementById` auto-created elements per id, which
  silently forked instances once code assigned ids after creation; the seeded
  skeleton + tree-walking lookup fixed the tab tests and makes future UI tests
  behave like a browser.
- PDF body text is Courier (Base-14): no font embedding, so non-Latin-1 hive
  data is substituted — the footer says how many; copy-to-text stays lossless.
- Escape now doubles as "leave Reports tab"; overlay Escape behavior
  (hex/meta) unchanged.
- Known gremlin check: one raw NUL byte appeared in `30-pdf.js` (sanitiser
  literal) — fixed; all touched files verified NUL-free.

**Summary:** Captured the RegRipper import exercise as durable artifacts so it
is never re-derived: a guide doc, a machine-readable per-plugin status file
covering all 386 plugins, and the extraction pipeline as runnable scripts.

**Why:** The corpus analysis (386 → 61 `_tln` → 325 report → 256 simple + 69
binary), the descriptor schema, and the skip reasons lived only in session
notes and ephemeral `/tmp` files. Anyone resuming the work — including us —
would have had to redo the whole analysis.

**What changed:**
- `docs/regripper-plugins.md` — TL;DR, corpus breakdown tables, porting-status
  tables, architecture map (`src/plugins/30-32`, `40-43`, `50`), the descriptor
  schema, "how to add a plugin" instructions, the reproducible pipeline
  description, and the NUL-byte gotcha.
- `docs/regripper-plugin-status.json` — one row per RR4.0 plugin: name, hive,
  category, output, status (`excluded` 61 / `done-bespoke` 17 /
  `done-descriptor` 133 / `deferred` 175) with mode or deferral reason.
- `scripts/regripper/analyze.js` — corpus analyser (+ `--batches N` chunking).
- `scripts/regripper/extract.js` — the conservative heuristic extractor
  (headered, batch-id parameterised, repo-relative paths).
- `scripts/regripper/assemble.js` — merger/validator/generator; dedup set now
  parsed from `src/plugins/4x-*.js` instead of hard-coded; globs
  `/tmp/rr_desc_*.json`.
- `scripts/regripper/status.js` — regenerates the status JSON from current
  source (`analyze` first).

**How / commands run:**
```
node scripts/regripper/analyze.js          # 386 | 61 _tln | 325 | 256/69
node scripts/regripper/status.js           # {deferred:175, done-descriptor:133, excluded:61, done-bespoke:17}
node scripts/regripper/assemble.js         # 133 accepted, 0 rejected → byte-identical 50-descriptors.js (idempotent)
node --test                                # 212 pass
```

**Verification:** the pipeline reproduces the committed descriptor file
byte-for-byte (idempotency proven with `cmp`); counts match the guide tables;
NUL scan clean on all new files; tests unchanged at 212.

## 2026-09-01 — Bulk import of RegRipper "simple" plugins (133 added → 150 total)

**Summary:** Added a descriptor-driven plugin engine and auto-imported 133
RegRipper 4.0 plugins that follow regular read patterns, on top of the 17
bespoke ports from the earlier entry. The Reports panel now exposes 150
plugins.

**Why:** User asked to import every RegRipper plugin that doesn't need user
intervention. RegRipper plugins are all non-interactive, so the real axis is
*portability*: 386 plugins → 61 `_tln` output-duplicates → 325 report plugins,
of which 256 are "simple" (no binary `unpack`) and 69 use bespoke binary
decoders. Hand-writing hundreds of `run()` functions is neither maintainable
nor testable, so the regular ones became declarative descriptors.

**What changed:**
- `src/plugins/32-simple.js` (new, `RV.plugins.simple`): `registerSimple(desc)`
  / `registerAll(descs)`. A descriptor declares metadata + a read pattern
  (`mode`: `values` | `named` | `subkeys` | `mru`), candidate `paths`, an
  optional `ccs` flag (System-hive current-control-set prefix), and
  `names`/`subkeyNames`. The engine builds a normal runtime plugin that tries
  each path, prints LastWrite + the pattern's output, and degrades gracefully
  to a "not found" note. `MAX_PLUGIN_ROWS` guard applies.
- `src/plugins/50-descriptors.js` (new, generated): 133 validated descriptors,
  registered via `registerAll`.
- `index.html`: `32-simple.js` (after helpers) and `50-descriptors.js` (after
  the bespoke `43-sam.js`) added in dependency order.

**How the descriptors were produced:**
- Analysed the corpus (`/tmp/rr_analysis.json`) to isolate the 247 simple
  plugins not already ported.
- Dispatched 6 parallel subagents to read the Perl and emit descriptor JSON
  matching the engine schema, flagging non-conforming plugins as
  `{skip,reason}`. **3 of 6 completed** (batches 0/1/3 → 68 descriptors)
  before the org hit its monthly spend limit and killed all agents.
- Extracted the remaining 3 batches with a conservative in-process heuristic
  parser (`/tmp/extract.js`): pulls metadata reliably, detects `ccs`/`mode`/
  `paths`/`names`, and **skips anything ambiguous** (runtime-assembled paths,
  binary `unpack`, nested descent) to protect fidelity → 65 descriptors.
- Assembled + validated (`/tmp/assemble.js`): shape + hive-tag + mode checks,
  dedup against the 17 bespoke names. 133 accepted, 0 rejected, 114 skipped.

**What was NOT imported (114, deferred — bespoke work, not user intervention):**
nested subkey-of-subkey value reads, binary-structure decoders, runtime-built
paths (e.g. Office-version probing), `::guessHive` multi-hive path branching in
one plugin, data transforms (string splitting, lookup tables, timestamp
decode), conditional alert logic, and `hive => "all"` scanners. These need
bespoke `run()` functions and are the next wave.

**How / commands run:**
```
node --test                                   # 212 pass (was 199)
node --test --experimental-test-coverage      # 32-simple 100%, 50-descriptors 100%
node tests/e2e-ui-sim.js                       # reports panel now lists 150 plugins
aidc-scan                                      # semgrep + gitleaks clean
```

**Verification:** a validation test runs **all 133** descriptor plugins against
a synthetic control-set hive and asserts none throw (every one produces a
section, error === null); plus data-present checks for `values` mode
(`screensaver`) and `ccs` path resolution (`trailersupport`).

**Notes / gotchas:**
- Descriptor `paths`/`mode` from the heuristic batches are best-effort; a wrong
  path degrades to a harmless "not found", never a crash. Agent batches
  (0/1/3) were read-and-understood, so higher confidence.
- The recurring NUL-byte-in-generated-source issue reappeared in
  `32-simple.js` (a MRUList filter literal) and was fixed with a \u0000 escape; all files verified NUL-free.

## 2026-09-01 — Reports: RegRipper-style plugin/report system

**Summary:** Added an in-browser plugin layer that reimplements the RegRipper
plugin model in JS — a registry + executor, shared helpers mirroring
RegRipper's framework globals, an initial batch of 17 ported plugins, and a
"Reports" slide-over panel. Reports render as structured sections/tables and
copy out as RegRipper-style plain text. Zero new dependencies; all parsing is
local (privacy preserved).

**Why:** HiveWalker already exposes a parser API deliberately shaped like
`Parse::Win32Registry` (`getRootKey`/`getSubkey`/`getValue`/`getData`, per the
comment in `src/reg/12-hive.js`). The `supporting/RegRipper{3,4}.0` Perl
distributions can't run in-browser, but their plugin *logic* (read a few key
paths from a hive type, emit a report) ports cleanly. This turns the viewer
from "browse raw keys" into "run named forensic reports."

**What changed:**
- `src/plugins/30-runtime.js` (new, `RV.plugins.runtime`): `register`,
  `all`, `get`, `applicableTo(hive)`, `run(plugin, hive)` (never throws — a
  plugin error is captured in `result.error`), `runAll(hive, {signal})`
  (cooperative abort between plugins). Returns a serialisable result:
  `{plugin, shortDescr, hiveTypes, category, mitre, version, ranAt, error,
  sections:[{title, blocks:[{kind:'text'|'kv'|'table'|'note', …}]}]}`.
- `src/plugins/31-helpers.js` (new, `RV.plugins.helpers`): the `ctx` report
  builder (`section`/`rptMsg`/`kv`/`table`/`note`, with a `MAX_PLUGIN_ROWS`
  truncation guard); `guessHiveType(hive)` (Set of tags — embedded-name
  basename + marker-key probes, mirroring `rr.pl guessHive`);
  `getControlSet(hive)` (Select\Current → ControlSetNNN with fallbacks); null-
  tolerant getters (`subkey`, `getValueData/String/Dword`); time helpers
  (`filetimeFromBinary`, `unixToDate`, `formatDate`); `rot13`.
- Plugin group files (new): `40-system.js` (compname, timezone, shutdown,
  services, usbstor, ips, mountdev), `41-software.js` (winver, uninstall, run,
  profilelist, networkcards — run/uninstall also tagged `ntuser`),
  `42-ntuser.js` (userassist w/ ROT13 + XP/Win7 record decode, recentdocs w/
  MRUList(Ex), typedpaths, runmru), `43-sam.js` (samparse — reduced: usernames
  from `Names`, RIDs hex→dec; full F/V struct decode deferred).
- `src/ui/20-view-model.js`: added DOM-free `pluginList`, `reportView`,
  `reportText`, `reportTextAll` (the testable seam).
- `src/ui/29-reports.js` (new, `RV.ui.reports`): slide-over panel modelled on
  `26-hivemeta.js` — lists plugins (applicable first, with category/MITRE
  badges), run-one / run-all, copy-to-text (clipboard + select-text fallback
  from `23-values.js`).
- Wiring: `index.html` (`plugins:{}` bootstrap, six plugin + one UI
  `<script>` tags in dependency order, `#reports-btn`, `#reports-pane`),
  `src/main.js` (button + Escape), `src/ui/21-app.js` (`showPanes` reveals the
  button), `src/styles.css` (reports-panel rules, reusing `meta-table`/
  `values-table`).
- Tests (new): `tests/plugins-runtime.test.js`,
  `tests/plugins-{system,software,ntuser,sam,edge}.test.js`,
  `tests/report-view.test.js`, `tests/reports-ui.test.js`, plus
  `tests/helpers/ft-bytes.js` and `tests/helpers/dom-stub.js` (the e2e DOM
  stub extracted from `e2e-ui-sim.js` and shared). `e2e-ui-sim.js` now uses
  the shared stub and drives the reports panel.

**How / commands run:**
```
node --test                                   # 199 pass (was 131)
node --test --experimental-test-coverage      # new src files: 100% lines
node tests/e2e-ui-sim.js                       # reports open/run/run-all: ok
aidc-scan                                      # semgrep + gitleaks clean
```

**Notes / gotchas:**
- Load order matters: runtime+helpers+plugins load after `13-index.js` and
  before `20-view-model.js`; the view-model references `RV.plugins.*` lazily.
- `_tln`/`_json`/`_yara` RegRipper variants are output-format duplicates —
  only the base "report" logic is ported; text vs. table are render modes.
- `run`/`uninstall` apply to both Software and NTUSER; they probe all paths
  (distinct per hive) rather than branching on detection.
- FILETIME-in-binary values (ShutdownTime, USBStor properties, UserAssist)
  are read as 8-byte LE via `filetimeFromBinary`; `winver InstallDate` is a
  DWORD of unix-epoch seconds.

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
