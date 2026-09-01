# NOTICE

## Third-party acknowledgments

### RegRipper

The HiveWalker **Reports** feature (150 RegRipper-style forensic plugins)
is a JavaScript reimplementation of the plugin layer of **RegRipper**, the
Windows registry analysis tool written by **H. Carvey (keydet89)**:

- RegRipper 4.0 — https://github.com/keydet89/RegRipper4.0
- RegRipper 3.0 — https://github.com/keydet89/RegRipper3.0
- RegRipper home page — https://regripper.wordpress.com/

Derived/ported material in this repository:

- Plugin architecture mirror — `src/plugins/30-runtime.js` (registry +
  executor) and `src/plugins/32-simple.js` (descriptor engine).
- Shared helpers ported from `rr_helper.pl` / `time.pl` — decode helpers in
  `src/reg/03-utf16.js` and `src/plugins/31-helpers.js`.
- 17 bespoke plugin `run()` ports — `src/plugins/40-system.js`,
  `41-software.js`, `42-ntuser.js`, `43-sam.js`.
- 133 descriptor-driven plugin reports generated from RegRipper 4.0 plugin
  semantics — `src/plugins/50-descriptors.js` (regenerate via
  `scripts/regripper/assemble.js`).

The Perl reference corpus (`supporting/RegRipper4.0`) is **not** shipped
with this repository (see `.gitignore`); it is used only as a local
behavioural reference during development. RegRipper's code is not executed
or linked against.

### License status of RegRipper

- **RegRipper 3.0** is distributed under the MIT License.
- **RegRipper 4.0** is free for **personal and academic
  (college/university) use only**, and *may not be included in vendor
  products, vendor training, nor in any distribution* (per its README).

HiveWalker's plugin ports follow RegRipper 4.0 plugin semantics and are
offered for the same personal/academic digital-forensics use. Redistributors
of this project should review RegRipper 4.0's terms (and, if needed, switch
the porting corpus to the MIT-licensed RegRipper 3.0 or another permissively
licensed implementation) before any broader distribution.
