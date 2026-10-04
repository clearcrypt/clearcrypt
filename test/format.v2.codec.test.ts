import { describe, expect, it } from "vitest";
import {
  decodeDataRecordHeaderV2,
  decodeFinalRecordHeaderV2,
  decodeHeaderV2,
  decodeU32BE,
  decodeU64BE,
  encodeDataRecordHeaderV2,
  encodeFinalRecordHeaderV2,
  encodeHeaderV2,
  encodeU32BE,
  encodeU64BE,
} from "../src/v2/spec/codec";
import {
  ARCHIVE_KEY_WRAP_AES_256_GCM_V2,
  CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
  CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
  DEFAULT_CHUNK_SIZE_V2,
  MAX_CHUNK_SIZE_V2,
  MAX_DATA_RECORDS_V2,
  MAX_PLAINTEXT_LENGTH_V2,
  MIN_CHUNK_SIZE_V2,
  PASSWORD_KDF_ARGON2ID_V2,
  RECORD_TYPE_DATA_V2,
  RECORD_TYPE_FINAL_V2,
  U32_MAX,
  U64_MAX,
  V2_DATA_RECORD_HEADER_LENGTH,
  V2_FINAL_RECORD_HEADER_LENGTH,
  V2_HEADER_LENGTH,
  V2_HEADER_OFFSETS,
  VERSION_V2,
} from "../src/v2/spec/constants";
import type { V2Header } from "../src/v2/spec/types";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function makeHeader(overrides: Partial<V2Header> = {}): V2Header {
  return {
    version: VERSION_V2,
    contentCipherId: CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
    contentKeyScheduleId: CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
    chunkSize: DEFAULT_CHUNK_SIZE_V2,
    archiveId: bytes(16, 0x10),
    contentNoncePrefix: bytes(4, 0x20),
    passwordKdfId: PASSWORD_KDF_ARGON2ID_V2,
    passwordSalt: bytes(16, 0x30),
    timeCost: 2,
    memoryCostKiB: 65_536,
    parallelism: 2,
    archiveKeyWrapCipherId: ARCHIVE_KEY_WRAP_AES_256_GCM_V2,
    wrapNonce: bytes(12, 0x40),
    wrappedArchiveKeyCiphertext: bytes(32, 0x50),
    wrappedArchiveKeyTag: bytes(16, 0x70),
    ...overrides,
  };
}

describe("V2 integer codecs", () => {
  it.each([0, 1, U32_MAX])("round-trips u32 value %s", (value) => {
    expect(decodeU32BE(encodeU32BE(value))).toBe(value);
  });

  it.each([0n, 1n, BigInt(Number.MAX_SAFE_INTEGER), U64_MAX])(
    "round-trips u64 value %s without number conversion",
    (value) => {
      expect(decodeU64BE(encodeU64BE(value))).toBe(value);
    }
  );

  it("rejects values and byte lengths outside their encodings", () => {
    expect(() => encodeU32BE(-1)).toThrow(/u32/i);
    expect(() => encodeU32BE(U32_MAX + 1)).toThrow(/u32/i);
    expect(() => encodeU64BE(-1n)).toThrow(/u64/i);
    expect(() => encodeU64BE(U64_MAX + 1n)).toThrow(/u64/i);
    expect(() => decodeU32BE(new Uint8Array(3))).toThrow(/exactly 4 bytes/i);
    expect(() => decodeU64BE(new Uint8Array(7))).toThrow(/exactly 8 bytes/i);
  });
});

describe("V2 fixed header codec", () => {
  it("encodes exactly 122 bytes and round-trips every field", () => {
    const header = makeHeader();
    const encoded = encodeHeaderV2(header);
    const decoded = decodeHeaderV2(encoded);

    expect(encoded).toHaveLength(V2_HEADER_LENGTH);
    expect(decoded).toEqual(header);
    expect(new DataView(encoded.buffer).getUint32(V2_HEADER_OFFSETS.chunkSize, false)).toBe(
      DEFAULT_CHUNK_SIZE_V2
    );
  });

  it("decodes byte fields as zero-copy views over the serialized header", () => {
    const encoded = encodeHeaderV2(makeHeader());
    const decoded = decodeHeaderV2(encoded);

    expect(decoded.archiveId.buffer).toBe(encoded.buffer);
    expect(decoded.contentNoncePrefix.buffer).toBe(encoded.buffer);
    expect(decoded.passwordSalt.buffer).toBe(encoded.buffer);
    expect(decoded.wrapNonce.buffer).toBe(encoded.buffer);
    expect(decoded.wrappedArchiveKeyCiphertext.buffer).toBe(encoded.buffer);
    expect(decoded.wrappedArchiveKeyTag.buffer).toBe(encoded.buffer);
  });

  it.each([MIN_CHUNK_SIZE_V2, 1 << 20, DEFAULT_CHUNK_SIZE_V2, 1 << 23, MAX_CHUNK_SIZE_V2])(
    "accepts supported chunk size %s",
    (chunkSize) => {
      expect(decodeHeaderV2(encodeHeaderV2(makeHeader({ chunkSize }))).chunkSize).toBe(chunkSize);
    }
  );

  it.each([0, MIN_CHUNK_SIZE_V2 - 1, 96 * 1024, MAX_CHUNK_SIZE_V2 + 1])(
    "rejects invalid chunk size %s",
    (chunkSize) => {
      expect(() => encodeHeaderV2(makeHeader({ chunkSize }))).toThrow(/chunkSize/i);
    }
  );

  it("rejects invalid fixed field lengths", () => {
    const cases: Array<[Partial<V2Header>, RegExp]> = [
      [{ archiveId: new Uint8Array(15) }, /archiveId/i],
      [{ contentNoncePrefix: new Uint8Array(3) }, /contentNoncePrefix/i],
      [{ passwordSalt: new Uint8Array(15) }, /passwordSalt/i],
      [{ wrapNonce: new Uint8Array(11) }, /wrapNonce/i],
      [{ wrappedArchiveKeyCiphertext: new Uint8Array(31) }, /wrappedArchiveKeyCiphertext/i],
      [{ wrappedArchiveKeyTag: new Uint8Array(15) }, /wrappedArchiveKeyTag/i],
    ];

    for (const [overrides, pattern] of cases) {
      expect(() => encodeHeaderV2(makeHeader(overrides))).toThrow(pattern);
    }
  });

  it("rejects invalid KDF bounds while encoding and decoding", () => {
    expect(() => encodeHeaderV2(makeHeader({ timeCost: 0 }))).toThrow(/timeCost/i);
    expect(() => encodeHeaderV2(makeHeader({ memoryCostKiB: 8_191 }))).toThrow(/memoryCostKiB/i);
    expect(() => encodeHeaderV2(makeHeader({ parallelism: 17 }))).toThrow(/parallelism/i);

    const encoded = encodeHeaderV2(makeHeader());
    new DataView(encoded.buffer).setUint32(V2_HEADER_OFFSETS.memoryCostKiB, 1, false);
    expect(() => decodeHeaderV2(encoded)).toThrow(/memoryCostKiB/i);
  });

  it("distinguishes malformed magic from unsupported versions and algorithms", () => {
    const invalidMagic = encodeHeaderV2(makeHeader());
    invalidMagic[0] = invalidMagic[0]! ^ 0xff;
    expect(() => decodeHeaderV2(invalidMagic)).toThrow(/magic/i);

    const futureVersion = encodeHeaderV2(makeHeader());
    futureVersion[V2_HEADER_OFFSETS.version] = 0xff;
    expect(() => decodeHeaderV2(futureVersion)).toThrow(/version/i);

    for (const offset of [
      V2_HEADER_OFFSETS.contentCipherId,
      V2_HEADER_OFFSETS.contentKeyScheduleId,
      V2_HEADER_OFFSETS.passwordKdfId,
      V2_HEADER_OFFSETS.archiveKeyWrapCipherId,
    ]) {
      const futureAlgorithm = encodeHeaderV2(makeHeader());
      futureAlgorithm[offset] = 0xff;
      expect(() => decodeHeaderV2(futureAlgorithm)).toThrow(/unsupported/i);
    }
  });

  it("requires exactly one fixed header", () => {
    const encoded = encodeHeaderV2(makeHeader());
    expect(() => decodeHeaderV2(encoded.subarray(0, V2_HEADER_LENGTH - 1))).toThrow(/exactly/i);
    expect(() => decodeHeaderV2(new Uint8Array(V2_HEADER_LENGTH + 1))).toThrow(/exactly/i);
  });
});

describe("V2 record-header codecs", () => {
  it("round-trips DATA boundary values", () => {
    const cases = [
      { recordNumber: 0n, plaintextLength: 1 },
      {
        recordNumber: MAX_DATA_RECORDS_V2 - 1n,
        plaintextLength: DEFAULT_CHUNK_SIZE_V2,
      },
    ];

    for (const value of cases) {
      const header = { recordType: RECORD_TYPE_DATA_V2, ...value };
      const encoded = encodeDataRecordHeaderV2(header, DEFAULT_CHUNK_SIZE_V2);
      expect(encoded).toHaveLength(V2_DATA_RECORD_HEADER_LENGTH);
      expect(decodeDataRecordHeaderV2(encoded, DEFAULT_CHUNK_SIZE_V2)).toEqual(header);
    }
  });

  it("rejects invalid DATA type, number and length", () => {
    expect(() =>
      encodeDataRecordHeaderV2(
        { recordType: RECORD_TYPE_FINAL_V2, recordNumber: 0n, plaintextLength: 1 },
        DEFAULT_CHUNK_SIZE_V2
      )
    ).toThrow(/recordType/i);
    expect(() =>
      encodeDataRecordHeaderV2(
        {
          recordType: RECORD_TYPE_DATA_V2,
          recordNumber: MAX_DATA_RECORDS_V2,
          plaintextLength: 1,
        },
        DEFAULT_CHUNK_SIZE_V2
      )
    ).toThrow(/recordNumber/i);
    expect(() =>
      encodeDataRecordHeaderV2(
        { recordType: RECORD_TYPE_DATA_V2, recordNumber: 0n, plaintextLength: 0 },
        DEFAULT_CHUNK_SIZE_V2
      )
    ).toThrow(/plaintextLength/i);
    expect(() =>
      encodeDataRecordHeaderV2(
        {
          recordType: RECORD_TYPE_DATA_V2,
          recordNumber: 0n,
          plaintextLength: DEFAULT_CHUNK_SIZE_V2 + 1,
        },
        DEFAULT_CHUNK_SIZE_V2
      )
    ).toThrow(/plaintextLength/i);
  });

  it("rejects hostile DATA fields while decoding", () => {
    const wrongType = encodeDataRecordHeaderV2(
      { recordType: RECORD_TYPE_DATA_V2, recordNumber: 0n, plaintextLength: 1 },
      DEFAULT_CHUNK_SIZE_V2
    );
    wrongType[0] = 0xff;
    expect(() => decodeDataRecordHeaderV2(wrongType, DEFAULT_CHUNK_SIZE_V2)).toThrow(/DATA/i);

    const excessiveNumber = new Uint8Array(V2_DATA_RECORD_HEADER_LENGTH);
    const view = new DataView(excessiveNumber.buffer);
    excessiveNumber[0] = RECORD_TYPE_DATA_V2;
    view.setBigUint64(1, MAX_DATA_RECORDS_V2, false);
    view.setUint32(9, 1, false);
    expect(() => decodeDataRecordHeaderV2(excessiveNumber, DEFAULT_CHUNK_SIZE_V2)).toThrow(
      /record number/i
    );
  });

  it("round-trips FINAL boundary values", () => {
    const header = {
      recordType: RECORD_TYPE_FINAL_V2,
      dataRecordCount: MAX_DATA_RECORDS_V2,
      totalPlaintextLength: MAX_PLAINTEXT_LENGTH_V2,
    };
    const encoded = encodeFinalRecordHeaderV2(header);

    expect(encoded).toHaveLength(V2_FINAL_RECORD_HEADER_LENGTH);
    expect(decodeFinalRecordHeaderV2(encoded)).toEqual(header);
  });

  it("rejects FINAL values beyond the global limits", () => {
    expect(() =>
      encodeFinalRecordHeaderV2({
        recordType: RECORD_TYPE_FINAL_V2,
        dataRecordCount: MAX_DATA_RECORDS_V2 + 1n,
        totalPlaintextLength: 0n,
      })
    ).toThrow(/dataRecordCount/i);
    expect(() =>
      encodeFinalRecordHeaderV2({
        recordType: RECORD_TYPE_FINAL_V2,
        dataRecordCount: 0n,
        totalPlaintextLength: MAX_PLAINTEXT_LENGTH_V2 + 1n,
      })
    ).toThrow(/totalPlaintextLength/i);

    const excessiveLength = new Uint8Array(V2_FINAL_RECORD_HEADER_LENGTH);
    const view = new DataView(excessiveLength.buffer);
    excessiveLength[0] = RECORD_TYPE_FINAL_V2;
    view.setBigUint64(1, 0n, false);
    view.setBigUint64(9, MAX_PLAINTEXT_LENGTH_V2 + 1n, false);
    expect(() => decodeFinalRecordHeaderV2(excessiveLength)).toThrow(/plaintext length/i);
  });
});
