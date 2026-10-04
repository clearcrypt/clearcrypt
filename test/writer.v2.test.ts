import { describe, expect, it } from "vitest";
import {
  V2BoundedMemoryDestination,
  V2CountingDestination,
  V2IncrementalWriter,
  type V2ByteDestination,
} from "../src/v2/writer";
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
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function makeHeader(): V2Header {
  return {
    version: VERSION_V2,
    contentCipherId: CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
    contentKeyScheduleId: CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
    chunkSize: MIN_CHUNK_SIZE_V2,
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

describe("V2 incremental writer", () => {
  it("emits an exact CFENC002 byte sequence without joining records internally", async () => {
    const archiveHeader = makeHeader();
    const dataHeader = {
      recordType: RECORD_TYPE_DATA_V2,
      recordNumber: 0n,
      plaintextLength: 3,
    } as const;
    const finalHeader = {
      recordType: RECORD_TYPE_FINAL_V2,
      dataRecordCount: 1n,
      totalPlaintextLength: 3n,
    } as const;
    const ciphertext = bytes(3, 0x80);
    const dataTag = bytes(AUTH_TAG_LENGTH_V2, 0xa0);
    const finalTag = bytes(AUTH_TAG_LENGTH_V2, 0xf0);
    const expected = concat(
      encodeHeaderV2(archiveHeader),
      encodeDataRecordHeaderV2(dataHeader, archiveHeader.chunkSize),
      ciphertext,
      dataTag,
      encodeFinalRecordHeaderV2(finalHeader),
      finalTag
    );
    const destination = new V2BoundedMemoryDestination(expected.length);
    const writer = new V2IncrementalWriter(destination);

    await writer.writeHeader(archiveHeader);
    await writer.writeDataRecord(dataHeader, ciphertext, dataTag);
    await writer.writeFinalRecord(finalHeader, finalTag);

    expect(destination.toUint8Array()).toEqual(expected);
    expect(destination.bytesWritten).toBe(expected.length);
  });

  it("awaits a slow destination and rejects concurrent production", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let writes = 0;
    let completed = false;
    const destination: V2ByteDestination = {
      async write() {
        writes += 1;
        await gate;
      },
    };
    const writer = new V2IncrementalWriter(destination);

    const pending = writer.writeHeader(makeHeader()).then(() => {
      completed = true;
    });
    await Promise.resolve();

    expect(writes).toBe(1);
    expect(completed).toBe(false);
    await expect(
      writer.writeFinalRecord(
        { recordType: RECORD_TYPE_FINAL_V2, dataRecordCount: 0n, totalPlaintextLength: 0n },
        bytes(AUTH_TAG_LENGTH_V2, 0xf0)
      )
    ).rejects.toThrow(/concurrent writes/i);

    release();
    await pending;
    expect(completed).toBe(true);
  });

  it("propagates a destination failure and performs no later write", async () => {
    const failure = new Error("destination unavailable");
    let writes = 0;
    const destination: V2ByteDestination = {
      write() {
        writes += 1;
        if (writes === 3) throw failure;
      },
    };
    const writer = new V2IncrementalWriter(destination);
    await writer.writeHeader(makeHeader());

    let received: unknown;
    try {
      await writer.writeDataRecord(
        { recordType: RECORD_TYPE_DATA_V2, recordNumber: 0n, plaintextLength: 3 },
        bytes(3, 1),
        bytes(AUTH_TAG_LENGTH_V2, 2)
      );
    } catch (error) {
      received = error;
    }

    expect(received).toBe(failure);
    expect(writes).toBe(3);
    await expect(
      writer.writeFinalRecord(
        { recordType: RECORD_TYPE_FINAL_V2, dataRecordCount: 0n, totalPlaintextLength: 0n },
        bytes(AUTH_TAG_LENGTH_V2, 3)
      )
    ).rejects.toThrow(/failed V2 writer/i);
    expect(writes).toBe(3);
  });

  it("validates ordering, lengths, tags and FINAL counters", async () => {
    const beforeHeader = new V2IncrementalWriter(new V2CountingDestination());
    await expect(
      beforeHeader.writeFinalRecord(
        { recordType: RECORD_TYPE_FINAL_V2, dataRecordCount: 0n, totalPlaintextLength: 0n },
        bytes(AUTH_TAG_LENGTH_V2, 1)
      )
    ).rejects.toThrow(/requires a header/i);

    const badLength = new V2IncrementalWriter(new V2CountingDestination());
    await badLength.writeHeader(makeHeader());
    await expect(
      badLength.writeDataRecord(
        { recordType: RECORD_TYPE_DATA_V2, recordNumber: 0n, plaintextLength: 2 },
        bytes(3, 1),
        bytes(AUTH_TAG_LENGTH_V2, 2)
      )
    ).rejects.toThrow(/ciphertext length/i);

    const badTag = new V2IncrementalWriter(new V2CountingDestination());
    await badTag.writeHeader(makeHeader());
    await expect(
      badTag.writeDataRecord(
        { recordType: RECORD_TYPE_DATA_V2, recordNumber: 0n, plaintextLength: 3 },
        bytes(3, 1),
        bytes(AUTH_TAG_LENGTH_V2 - 1, 2)
      )
    ).rejects.toThrow(/tag must be exactly/i);

    const badFinal = new V2IncrementalWriter(new V2CountingDestination());
    await badFinal.writeHeader(makeHeader());
    await expect(
      badFinal.writeFinalRecord(
        { recordType: RECORD_TYPE_FINAL_V2, dataRecordCount: 1n, totalPlaintextLength: 0n },
        bytes(AUTH_TAG_LENGTH_V2, 3)
      )
    ).rejects.toThrow(/record count/i);
  });

  it("copies into bounded memory and rejects overflow before retaining it", () => {
    const destination = new V2BoundedMemoryDestination(3);
    const original = Uint8Array.of(1, 2);
    destination.write(original);
    original[0] = 9;

    expect(destination.toUint8Array()).toEqual(Uint8Array.of(1, 2));
    expect(() => destination.write(Uint8Array.of(3, 4))).toThrow(/limit exceeded/i);
    expect(destination.bytesWritten).toBe(2);
  });

  it("counts output without retaining chunks", () => {
    const destination = new V2CountingDestination();
    destination.write(new Uint8Array(10));
    destination.write(new Uint8Array(20));

    expect(destination.bytesWritten).toBe(30n);
    expect(destination.writes).toBe(2n);
    expect(Object.keys(destination).sort()).toEqual(["bytesWritten", "writes"]);
  });
});
