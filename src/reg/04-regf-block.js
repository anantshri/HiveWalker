// rv.reg — the 4096-byte regf base block. Offsets in docs/regf-format.md.
(function (RV) {
  'use strict';

  const { SIG, LIMITS } = RV.reg.consts;
  const { BufferReader, RegistryParseError } = RV.reg;

  const FILENAME_OFF = 0x30;
  const FILENAME_LEN = 128; // 64 UTF-16 code units
  const CHECKSUM_OFF = 0x1fc;

  /**
   * Compute the regf checksum: XOR-fold of the 127 u32 words before 0x1FC
   * into a 16-bit value (the classic "sum >>> 16 ^ sum & 0xffff" fold).
   */
  function computeChecksum(reader) {
    let sum = 0;
    for (let i = 0; i < 0x1fc; i += 4) sum = (sum + reader.u32(i)) >>> 0;
    return ((sum >>> 16) ^ (sum & 0xffff)) >>> 0;
  }

  /**
   * @param {BufferReader} reader
   * @returns {{sequence1:number, sequence2:number, timestamp:bigint, major:number,
   *   minor:number, type:number, format:number, rootCellOffset:number,
   *   hiveBinsSize:number, cluster:number, fileName:string, fileNameRaw:string,
   *   checksum:number, checksumValid:boolean, dirty:boolean,
   *   majorVersion:number, minorVersion:number}}
   * @throws {RegistryParseError} when the signature is not "regf"
   */
  function parseRegfBlock(reader) {
    if (reader.length < LIMITS.REGF_BLOCK_SIZE) {
      throw new RegistryParseError(
        `file too small for a regf base block (${reader.length} bytes)`, 0,
      );
    }
    const sig = reader.sig(0, 4);
    if (sig !== SIG.REGF) {
      throw new RegistryParseError(`not a registry hive (signature ${JSON.stringify(sig)})`, 0);
    }

    const sequence1 = reader.u32(0x04);
    const sequence2 = reader.u32(0x08);
    const timestamp = reader.u64(0x0c);
    const major = reader.u32(0x14);
    const minor = reader.u32(0x18);
    const type = reader.u32(0x1c);
    const format = reader.u32(0x20);
    const rootCellOffset = reader.u32(0x24);
    const hiveBinsSize = reader.u32(0x28);
    const cluster = reader.u32(0x2c);
    const fileNameRaw = reader.utf16le(FILENAME_OFF, FILENAME_LEN);
    const checksum = reader.u32(CHECKSUM_OFF);
    const checksumValid = checksum === computeChecksum(reader);

    return {
      sequence1,
      sequence2,
      timestamp,
      major,
      minor,
      type,
      format,
      rootCellOffset,
      hiveBinsSize,
      cluster,
      fileName: fileNameRaw.split("\u0000")[0].replace(/ +$/g, ''),
      fileNameRaw,
      checksum,
      checksumValid,
      dirty: sequence1 !== sequence2,
      majorVersion: `${major}.${minor}`,
    };
  }

  RV.reg.parseRegfBlock = parseRegfBlock;
  RV.reg.computeRegfChecksum = computeChecksum;
})(window.RV);
