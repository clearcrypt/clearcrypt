import { describe, expect, it } from "vitest";
import { V2IncrementalReader, type V2ReaderItem } from "../src/v2/reader";
import {
  encodeDataRecordHeaderV2,
  encodeFinalRecordHeaderV2,
  encodeHeaderV2,
} from "../src/v2/spec/codec";
import {
  ARCHIVE_KEY_WRAP_AES_256_GCM_V2,
  AUTH_TAG_LENGTH_V2,
  CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
  CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
  MAX_CHUNK_SIZE_V2,
  MIN_CHUNK_SIZE_V2,
  PASSWORD_KDF_ARGON2ID_V2,
  RECORD_TYPE_DATA_V2,
  RECORD_TYPE_FINAL_V2,
  VERSION_V2,
} from "../src/v2/spec/constants";
import type { V2Header } from "../src/v2/spec/types";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function makeHeader(chunkSize = MIN_CHUNK_SIZE_V2): V2Header {
  return {
    version: VERSION_V2,
    contentCipherId: CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
    contentKeyScheduleId: CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
    chunkSize,
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
  };
}

function dataRecord(recordNumber: bigint, length: number): Uint8Array {
  return concat(
    encodeDataRecordHeaderV2(
      { recordType: RECORD_TYPE_DATA_V2, recordNumber, plaintextLength: length },
      MAX_CHUNK_SIZE_V2
    ),
    bytes(length, Number(recordNumber) + 1),
    bytes(AUTH_TAG_LENGTH_V2, 0xa0 + Number(recordNumber))
  );
}

function finalRecord(dataRecordCount: bigint, totalPlaintextLength: bigint): Uint8Array {
  return concat(
    encodeFinalRecordHeaderV2({
      recordType: RECORD_TYPE_FINAL_V2,
      dataRecordCount,
      totalPlaintextLength,
    }),
    bytes(AUTH_TAG_LENGTH_V2, 0xf0)
  );
}

function archiveWithOneShortRecord(): Uint8Array {
  return concat(encodeHeaderV2(makeHeader()), dataRecord(0n, 3), finalRecord(1n, 3n));
}

describe("V2 incremental reader", () => {
  it("parses an archive delivered one byte at a time", async () => {
    const items: V2ReaderItem[] = [];
    const reader = new V2IncrementalReader((item) => {
      items.push(item);
    });

    for (const byte of archiveWithOneShortRecord()) {
      await reader.write(Uint8Array.of(byte));
    }
    reader.end();

    expect(items.map((item) => item.kind)).toEqual(["header", "data", "final"]);
    const data = items[1];
    expect(data?.kind).toBe("data");
    if (data?.kind === "data") {
      expect(data.header.recordNumber).toBe(0n);
      expect(data.ciphertext).toEqual(bytes(3, 1));
      expect(data.tag).toEqual(bytes(AUTH_TAG_LENGTH_V2, 0xa0));
    }
  });

  it("applies handler backpressure before consuming the next item", async () => {
    const emitted: string[] = [];
    let releaseHeader!: () => void;
    const headerGate = new Promise<void>((resolve) => {
      releaseHeader = resolve;
    });
    const reader = new V2IncrementalReader(async (item) => {
      emitted.push(item.kind);
      if (item.kind === "header") await headerGate;
    });

    const write = reader.write(archiveWithOneShortRecord());
    await Promise.resolve();
    expect(emitted).toEqual(["header"]);

    releaseHeader();
    await write;
    reader.end();
    expect(emitted).toEqual(["header", "data", "final"]);
  });

  it("keeps its allocation bounded to one declared record", async () => {
    const archive = concat(
      encodeHeaderV2(makeHeader(MAX_CHUNK_SIZE_V2)),
      dataRecord(0n, MAX_CHUNK_SIZE_V2),
      finalRecord(1n, BigInt(MAX_CHUNK_SIZE_V2))
    );
    const reader = new V2IncrementalReader(() => undefined);

    await reader.write(archive);
    reader.end();

    expect(reader.maximumPendingCapacity).toBe(MAX_CHUNK_SIZE_V2 + AUTH_TAG_LENGTH_V2);
  });

  it("rejects a DATA record after the first short record", async () => {
    const archive = concat(
      encodeHeaderV2(makeHeader()),
      dataRecord(0n, 3),
      dataRecord(1n, 2),
      finalRecord(2n, 5n)
    );
    const reader = new V2IncrementalReader(() => undefined);

    await expect(reader.write(archive)).rejects.toThrow(/follow a short DATA record/i);
  });

  it("rejects discontinuous record numbers and inconsistent FINAL totals", async () => {
    const wrongNumber = new V2IncrementalReader(() => undefined);
    await expect(
      wrongNumber.write(
        concat(encodeHeaderV2(makeHeader()), dataRecord(1n, 3), finalRecord(1n, 3n))
      )
    ).rejects.toThrow(/record number/i);

    const wrongCount = new V2IncrementalReader(() => undefined);
    await expect(
      wrongCount.write(
        concat(encodeHeaderV2(makeHeader()), dataRecord(0n, 3), finalRecord(2n, 3n))
      )
    ).rejects.toThrow(/count/i);

    const wrongLength = new V2IncrementalReader(() => undefined);
    await expect(
      wrongLength.write(
        concat(encodeHeaderV2(makeHeader()), dataRecord(0n, 3), finalRecord(1n, 4n))
      )
    ).rejects.toThrow(/plaintext length/i);
  });

  it("requires FINAL and rejects every byte that follows it", async () => {
    const truncated = new V2IncrementalReader(() => undefined);
    await truncated.write(concat(encodeHeaderV2(makeHeader()), dataRecord(0n, 3)));
    expect(() => truncated.end()).toThrow(/before FINAL/i);

    const trailing = new V2IncrementalReader(() => undefined);
    await expect(trailing.write(concat(archiveWithOneShortRecord(), Uint8Array.of(0)))).rejects.toThrow(
      /after the V2 FINAL record/i
    );
  });

  it("rejects unknown record types without allocating a record body", async () => {
    const reader = new V2IncrementalReader(() => undefined);
    await expect(reader.write(concat(encodeHeaderV2(makeHeader()), Uint8Array.of(0xff)))).rejects.toThrow(
      /unknown V2 record type/i
    );
    expect(reader.maximumPendingCapacity).toBe(encodeHeaderV2(makeHeader()).length);
  });
});
