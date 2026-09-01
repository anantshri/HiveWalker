# The regf hive binary format — offsets used by this viewer

This documents the field offsets `src/reg/` depends on, with provenance
notes. The parser is the executable spec; this file is the human-readable one.

## Base block ("regf", 4096 bytes)

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 4 | signature `regf` | hard requirement |
| 0x04 | 4 | sequence1 | incremented per flush |
| 0x08 | 4 | sequence2 | equal to seq1 when clean → dirty flag |
| 0x0C | 8 | timestamp | FILETIME of last write |
| 0x14 | 4 | major version | 1 |
| 0x18 | 4 | minor version | 3 (WinXP+), 5 (Win7+), 6 (Win10+) |
| 0x1C | 4 | file type | 0 = primary |
| 0x20 | 4 | file format | 1 |
| 0x24 | 4 | root cell offset | relative to first hbin |
| 0x28 | 4 | hive bins size | total hbin bytes |
| 0x2C | 4 | cluster ("block") size | almost always 1 … 4096 |
| 0x30 | 128 | file name | UTF-16LE, NUL-padded |
| 0x1FC | 4 | checksum | XOR-fold of the 127 u32 words before it |

Checksum algorithm (matches the format's `HvpHeaderChecksum`): sum the u32
words at 0x000..0x1FB, then `(sum >>> 16) ^ (sum & 0xffff)`.

## Hive bins ("hbin", 4096-byte multiples)

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | signature `hbin` |
| 0x04 | 4 | offset of this hbin relative to the first hbin |
| 0x08 | 4 | size of this hbin (multiple of 4096) |
| 0x18 | 8 | FILETIME |

Cells start after each hbin's 0x20-byte header. **All offsets stored inside
records are relative to the first hbin** (absolute file offset = 4096 + rel).

## Cells

A cell begins with an `i32` size: negative = in use (allocated), positive =
free. The record follows immediately. `0xFFFFFFFF` in any offset field means
"none".

## Key nodes — `nk` (pre-1709) and `CM_KEY_NODE` (Win10 1709+)

`CM_KEY_NODE` is 11 bytes; every field below shifts by +9 relative to the
classic `nk` table.

| Field | nk | CM_KEY_NODE | Type |
|-------|----|-------------|------|
| signature | 0x00 (2 B) | 0x00 (11 B) | ascii |
| flags | 0x02 | 0x0B | u16 |
| timestamp | 0x04 | 0x0D | u64 FILETIME |
| parent | 0x10 | 0x19 | u32 rel |
| subkey count | 0x14 | 0x1D | u32 |
| subkey list | 0x1C | 0x25 | u32 rel |
| **volatile** value count | 0x20 | 0x29 | u32 (0xFFFFFFFF = none) |
| value count | 0x24 | 0x2D | u32 (0xFFFFFFFF = none) |
| value list | 0x28 | 0x31 | u32 rel |
| security (sk) | 0x2C | 0x35 | u32 rel |
| class name cell | 0x30 | 0x39 | u32 rel |
| name length | 0x48 | 0x51 | u16 |
| name | 0x4C | 0x55 | bytes |

**Verified against real hives** (Win7 v1.3 NTUSER.DAT, Win10 UsrClass.dat,
v1.5 SYSTEM/SOFTWARE) during development: the `Select` DWORDs, SAM user
RID-by-value-type, and the `Environment` EXPAND_SZ values all round-tripped
exactly.

Provenance: the classic `nk` table is community-documented identically
across Parse::Win32Registry, libregf, and regfi, and was confirmed against
genuine Win7/Win10 hives. The `CM_KEY_NODE` shift of +9 follows from the
signature growing 2→11 bytes. Names: flag `0x20` (`KEY_COMP_NAME`) →
single-byte chars, else UTF-16LE.

## Value records — `vk` / `CM_KEY_VALUE` (+10 shift for the 12-byte sig)

| Field | vk | CM_KEY_VALUE | Type |
|-------|----|--------------|------|
| signature | 0x00 (2 B) | 0x00 (12 B) | ascii |
| name length | 0x02 | 0x0C | u16 |
| data length | 0x04 | 0x0E | u32 |
| data offset | 0x08 | 0x12 | u32 |
| type | 0x0C | 0x16 | u32 REG_* |
| flags | 0x10 | 0x1A | u16 |
| spare | 0x12 | 0x1C | u16 |
| name | 0x14 | 0x1E | bytes |

**Inline rule:** when the data length's high bit (`0x80000000`) is set, the
actual length is `dataLen & 0x7FFFFFFF` and the bytes live *inside* the
record at the "data offset" slot. Zero data length is legal (empty data).

## Subkey lists

| Signature | Entry layout | Meaning |
|-----------|--------------|---------|
| `lf`, `lh` | u32 nk offset + u32 hash | direct children (hash ignored here) |
| `li` | u32 nk offset | direct children (Win NT4 style) |
| `ri` | u32 list offset | indirection: entries point at *other* lists |
| `db` | u32 nk offset | direct (Win95 hives; accepted, not seeked) |
| `CM_KEY_FAST_INDEX` / `CM_KEY_FAST_LEAF` / `CM_KEY_HASH_LEAF` | hashed form | as `lf`/`lh` |
| `CM_KEY_INDEX_LEAF` | plain offsets | as `li` |
| `CM_KEY_INDEX` | indirect | as `ri` |

All start with `u16 count` at 0x02 (after the signature). The viewer's
resolver is iterative with a visited set (cycle guard) and an entry cap.

## Value types (REG_*)

`0` NONE, `1` SZ, `2` EXPAND_SZ, `3` BINARY, `4` DWORD, `5` DWORD_BIG_ENDIAN,
`6` LINK, `7` MULTI_SZ, `8` RESOURCE_LIST, `9` FULL_RESOURCE_DESCRIPTOR,
`10` RESOURCE_REQUIREMENTS_LIST, `11` QWORD. Strings are UTF-16LE,
NUL-terminated; MULTI_SZ is NUL-separated with a double-NUL terminator.

## Known limitations

- **Transaction logs** (`.LOG1`/`.LOG2`) are not replayed — matches
  RegRipper's behaviour. The metadata panel surfaces the dirty flag.
- **Deleted/unallocated cells** are not enumerated (live view only).
- **Security descriptors** (`sk`) are parsed only for refcount display.
- Oversized-key **index roots** with `CM_KEY_INDEX` sub-pages are handled by
  the same iterative resolver as `ri`.
