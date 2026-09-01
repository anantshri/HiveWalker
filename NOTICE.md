# NOTICE

## Third-party acknowledgments

### RegRipper

The HiveWalker **Reports** feature (171 RegRipper-style forensic plugins)
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
- Bespoke plugin `run()` ports — `src/plugins/40-system.js`,
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

### Format-reference provenance (crypto/DFIR expansion, 2026-09-01)

The 2026-09-01 expansion (hand-rolled crypto in `src/crypto/`, binary
decoders in `src/decoders/`, and the new plugins listed in
`docs/regripper-plugins.md` § "New bespoke plugins") was implemented **from
published specifications and format documentation only**, including:

- RFC 1320 (MD4), RFC 1321 (MD5), FIPS 180-1 (SHA-1), FIPS 46-3 (DES),
  FIPS 197 / SP 800-38A (AES), and the published RC4 specification.
- Publicly documented Windows formats: the SysKey/bootkey derivation and
  SAM hash layering (adsecurity.org write-ups; libyal documentation), the
  AppCompatCache/ShimCache layouts (Mandiant's published ShimCacheParser
  format documentation, Apache-2.0), the Amcache.hve field map, LSA
  Secrets/PolAdtEv structure pages (libyal / kazamiya), and MS-DTYP
  (SIDs, self-relative security descriptors).
- Key-list references for the `autostarts`/`defposture` audits:
  HackTricks "Interesting Windows Registry Keys" and the Splunk Threat
  Research Team's published registry-detection blog.

No code was transcribed from impacket/creddump, and none from RegRipper
(which contains none of this crypto anyway). The MIT-licensed **regipy**
(checkout under `supporting/regipy`, not shipped) was consulted as a format
reference for the SAM F/V offsets, bootkey permutation, Amcache field map
and SECURITY-hive SID blobs; its code was not copied.

Any derivation that could not be confirmed against a primary source is
marked **UNVERIFIED** in `docs/crypto-notes.md` and the corresponding code
path reports data undecrypted rather than guessing (notably the Win10+
LSA-Secrets AES key schedule and the Vista→Win10-1607 SAM RC4 layer).

