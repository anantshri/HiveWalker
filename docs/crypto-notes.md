# Crypto & binary-format notes (provenance + verified constants)

This document records every non-obvious constant, offset and algorithm used by
`src/crypto/` and the binary decoders, with its public source. Anything that
could not be confirmed from a primary or authoritative source is marked
**UNVERIFIED** — those code paths ship disabled and say so in their output;
HiveWalker never emits guessed plaintext.

All implementations are written from the published specifications / format
documentation, not transcribed from any third-party code (see NOTICE.md).

## Hand-rolled crypto (`src/crypto/`)

| Module | Algorithm | Spec / vector source | Verification |
|---|---|---|---|
| `01-md4.js` | MD4 | RFC 1320 (incl. appendix A.5 vectors) | KATs incl. `MD4(UTF-16LE("password")) = 8846f7eaee8fb117ad06bdd830b7586c` (the NT-hash anchor); cross-checked against `openssl dgst -md4 -provider legacy` |
| `02-md5.js` | MD5 | RFC 1321 appendix A.5 | KATs |
| `03-sha1.js` | SHA-1 | FIPS 180-1 §7 examples | KATs; cross-checked against node `crypto` |
| `04-rc4.js` | RC4 | Published spec (Schneier, *Applied Cryptography* 2nd ed. §17.1) | classic Key/Wiki/Secret vectors |
| `05-des.js` | DES + NTLM string-to-key + per-RID key schedule | FIPS 46-3 tables; DCE/RPC 1.1 §13.5.2 for the 7→8 byte expansion | FIPS 81 worked example (key `133457799BBCDFF1`, PT `0123456789ABCDEF` → `85E813540F0AB405`), cross-checked against `openssl enc -des-ecb -provider legacy` |
| `06-aes.js` | AES-128/192/256 ECB + CBC decrypt | FIPS 197 (§5.1/§5.3), SP 800-38A (CBC) | FIPS 197 appendix C.1/C.3; SP 800-38A F.2.1/F.2.5, cross-checked against `openssl enc -aes-*-cbc` |
| `07-desede.js` | DES-EDE-CBC decrypt | SP 800-67 (EDE composition) | round-trip vs composed DES ops in tests |

The per-RID key schedule (`ridToDesKeys`) — public fact, documented in every
SAM-decryption write-up (adsecurity.org "Dumping Hashes"; libyal
documentation):

```
r0..r3 = RID little-endian bytes
key1 = desStringToKey(r0 r1 r2 r3 r0&0x0F r1&0x0F r2&0x0F)
key2 = desStringToKey(r3 r0 r1 r2 r0>>4   r1>>4   r2>>4)
```

Verified structurally (construction identity) + via the decrypt round-trip in
`tests/crypto-sam.test.js`.

Empty-hash anchors (used to detect blank passwords after decryption):

- LM empty: `aad3b435b51404eeaad3b435b51404ee` (two copies of the well-known
  "LANMAN null" constant `AAD3B435B51404EE`)
- NT empty: `31d6cfe0d16ae931b73c59d7e0c089c0` (= MD4 of the empty string)

## SysKey / bootkey (SYSTEM hive)

- Location: `SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}` — each
  key's **class name** holds 8 hex chars (32 total). Public fact, documented at
  adsecurity.org ("SysKey") and in regipy's MIT-licensed `bootkey.py`.
- Descramble permutation: `bootkey[i] = scrambled[pbox[i]]` with
  `pbox = [8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7]` (same public source).

## SAM F and V value layouts (`src/decoders/03-samfv.js`)

Offsets validated against the MIT-licensed regipy `samparse.py` plugin as a
format reference (reimplemented; no code copied):

### F value (≥ 0x48 bytes)

| Offset | Size | Meaning |
|---|---|---|
| 0x08 | 8 | Last logon (FILETIME) |
| 0x18 | 8 | Password last set (FILETIME) |
| 0x20 | 8 | Account expires (FILETIME; 0 = never) |
| 0x28 | 8 | Last failed logon (FILETIME) |
| 0x30 | 4 | RID |
| 0x38 | 2 | Account control flags (ACB bits, table in the decoder) |
| 0x40 | 2 | Failed login count |
| 0x42 | 2 | Login count |

### V value (≥ 0xCC bytes; every region is `offset(u32)+length(u32)` pairs
relative to 0xCC)

| Field | pair offset |
|---|---|
| username | 0x0C |
| fullname | 0x18 |
| comment | 0x24 |
| user comment | 0x30 |
| home directory | 0x48 |
| home directory connect | 0x54 |
| script path | 0x60 |
| profile path | 0x6C |
| workstations | 0x78 |
| LM hash region | 0x9C |
| NT hash region | 0xA8 |

RID→username mapping: the **type** of the `Names\<user>` key's default value
encodes the RID (public SAM quirk).

## AppCompatCache / ShimCache formats (`src/decoders/02-shimcache.js`)

Formats as documented by Mandiant's `ShimCacheParser.py` (Apache 2.0; format
facts reimplemented, no code copied) and libyal's AppCompatCache
documentation:

| Version | Signature | Notes |
|---|---|---|
| XP | `0xDEADBEEF` @0 | header 0x190, fixed 0x228 entries, path scanned to UTF-16 NUL |
| 2003/Vista/2008 | `0xBADC0FFE` @0 | header 8; entry 0x18 (32-bit) / 0x20 (64-bit probe: `maxSize - size == 2 && next u32 == 0`) |
| Win7/2008R2 | `0xBADC0FEE` @0 | header 0x80; entry 0x20/0x30 (same 64-bit probe); exec flag = CSRSS bit 0x2 |
| Win8 | `00ts` @0x80 | 12-byte entry framing `{magic, crc32, len}` |
| Win8.1 | `10ts` @0x80 | same framing |
| Win10 | `10ts` @0x30 | Creators update: `10ts` @0x34; no exec flag; insertion order only |

## Amcache.hve (`src/plugins/45-amcache.js`)

- Win8/8.1 shape: `Root\File\<volume-guid>\<file-ref>` with numerically-named
  values (`15`=path, `101`=SHA-1 with a `0000` prefix to strip, `11`/`17`
  last-modified FILETIME, `12` created, `6` size, `0` product, `1` company);
  `Root\Programs` for application entries. Field map confirmed against
  regipy's MIT-licensed `amcache.py`.
- Win10/11 shape: `Root\InventoryApplicationFile\*` with named values
  (`LowerCaseLongPath`, `FileId` = SHA-1 with `0000` prefix, `Size`,
  `LinkDate`, `BinFileVersion`, `Publisher`); `Root\InventoryApplication` for
  installed apps.

## LSA Secrets (SECURITY hive) — status

- `Policy\PolRevision` (u64, major<<32|minor) drives the version branch;
  absence ⇒ pre-Vista layout.
- Win10+ AES-128 key derivation from `SHA1(bootkey …)`: **UNVERIFIED** until
  pinned against a primary write-up during Phase 9 — if unconfirmed, the
  plugin enumerates secret names/sizes and states decryption is not supported
  for that generation rather than guessing.
- The XP/2003 RC4/DES-EDE path constants are likewise pinned before enabling.

## SECURITY hive SIDs

- `Policy\PolAcDmN` / `Policy\PolPrDmN`: 8-byte UNICODE_STRING-style header,
  then UTF-16LE name (regipy `domain_sid.py` as format reference).
- `Policy\PolMachineAccountS`: binary SID; REG_DWORD 0 ⇒ not domain-joined.

## Self-relative SECURITY_DESCRIPTOR (`src/decoders/01-secdesc.js`)

Layout per MS-DTYP §2.4.6: revision (must be 1), control flags, then
offsets (relative to descriptor start) to owner/group/sacl/dacl SIDs and
ACLs. ACL: revision 2/4, aceCount; ACE: type (0=allow, 1=deny), 2-byte flags,
4-byte access mask, SID. Registry-specific access bits used by `svcacls`:
`KEY_SET_VALUE 0x0002`, `KEY_CREATE_SUB_KEY 0x0004`, `KEY_ALL_ACCESS
0xF003F`, plus generic WRITE/ALL bits mapped per MS-DTYP §2.4.7.
