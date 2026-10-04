import { describe, expect, it } from "vitest";
import { aeadDecryptAes256Gcm } from "../src/v1/aead";
import {
  buildDataAadV2,
  buildDataNonceV2,
  deriveSegmentKeyV2,
  encryptDataRecordV2,
  getDataRecordPositionV2,
} from "../src/v2/data-record-crypto";
import {
  encodeDataRecordHeaderV2,
  encodeHeaderV2,
} from "../src/v2/spec/codec";
import {
  ARCHIVE_KEY_WRAP_AES_256_GCM_V2,
  CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
  CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
  MAX_DATA_RECORDS_V2,
  MIN_CHUNK_SIZE_V2,
  PASSWORD_KDF_ARGON2ID_V2,
  RECORD_TYPE_DATA_V2,
  VERSION_V2,
} from "../src/v2/spec/constants";
import type { V2Header } from "../src/v2/spec/types";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function fromHex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
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

describe("V2 DATA record encryption", () => {
  it("matches a deterministic HKDF-SHA-256 and AES-256-GCM vector", async () => {
    const archiveAad = encodeHeaderV2(makeHeader());
    const archiveMasterKey = bytes(32, 0);
    const plaintext = new TextEncoder().encode("ClearCrypt V2 test block");

    const encrypted = await encryptDataRecordV2({
      archiveAad,
      archiveMasterKey,
      recordNumber: 0n,
      plaintext,
    });

    expect(encrypted.ciphertext).toEqual(
      fromHex("d20805df39f2a04f25acd8e8618b5212a96de951ee70f6e1")
    );
    expect(encrypted.tag).toEqual(fromHex("560ebdc5e6db488d94efe88f111d6c0b"));
    expect(encrypted.header.plaintextLength).toBe(plaintext.length);
  });

  it("uses a new key and resets the local nonce at a segment boundary", () => {
    const recordsPerSegment = 1n << 14n;

    expect(getDataRecordPositionV2(recordsPerSegment - 1n, MIN_CHUNK_SIZE_V2)).toEqual({
      recordsPerSegment,
      segmentNumber: 0n,
      localRecordNumber: recordsPerSegment - 1n,
    });
    expect(getDataRecordPositionV2(recordsPerSegment, MIN_CHUNK_SIZE_V2)).toEqual({
      recordsPerSegment,
      segmentNumber: 1n,
      localRecordNumber: 0n,
    });
  });

  it("binds the archive, type, index and length into authentication", async () => {
    const header = makeHeader();
    const archiveAad = encodeHeaderV2(header);
    const archiveMasterKey = bytes(32, 0);
    const plaintext = bytes(32, 0x80);
    const encrypted = await encryptDataRecordV2({
      archiveAad,
      archiveMasterKey,
      recordNumber: 0n,
      plaintext,
    });
    const key = await deriveSegmentKeyV2({
      archiveMasterKey,
      archiveId: header.archiveId,
      segmentNumber: 0n,
    });

    const changedIndexHeader = encodeDataRecordHeaderV2(
      { recordType: RECORD_TYPE_DATA_V2, recordNumber: 1n, plaintextLength: plaintext.length },
      header.chunkSize
    );
    const changedLengthHeader = encodeDataRecordHeaderV2(
      { recordType: RECORD_TYPE_DATA_V2, recordNumber: 0n, plaintextLength: plaintext.length + 1 },
      header.chunkSize
    );
    const changedTypeHeader = encrypted.headerBytes.slice();
    changedTypeHeader[0] = 0x02;
    const changedArchive = archiveAad.slice();
    const lastArchiveByte = changedArchive.length - 1;
    changedArchive[lastArchiveByte] = changedArchive[lastArchiveByte]! ^ 1;

    const attempts = [
      {
        nonce: buildDataNonceV2(header.contentNoncePrefix, 1n),
        aad: buildDataAadV2(archiveAad, changedIndexHeader),
      },
      {
        nonce: buildDataNonceV2(header.contentNoncePrefix, 0n),
        aad: buildDataAadV2(archiveAad, changedLengthHeader),
      },
      {
        nonce: buildDataNonceV2(header.contentNoncePrefix, 0n),
        aad: buildDataAadV2(archiveAad, changedTypeHeader),
      },
      {
        nonce: buildDataNonceV2(header.contentNoncePrefix, 0n),
        aad: buildDataAadV2(changedArchive, encrypted.headerBytes),
      },
    ];

    for (const attempt of attempts) {
      await expect(
        aeadDecryptAes256Gcm({
          key,
          nonce: attempt.nonce,
          ciphertext: encrypted.ciphertext,
          tag: encrypted.tag,
          associatedAuthenticatedData: attempt.aad,
        })
      ).rejects.toThrow(/authentication failed/i);
    }
  });

  it("accepts short and full blocks but rejects an empty or oversized DATA block", async () => {
    const archiveAad = encodeHeaderV2(makeHeader());
    const archiveMasterKey = bytes(32, 0);

    await expect(
      encryptDataRecordV2({ archiveAad, archiveMasterKey, recordNumber: 0n, plaintext: bytes(1, 1) })
    ).resolves.toMatchObject({ header: { plaintextLength: 1 } });
    await expect(
      encryptDataRecordV2({
        archiveAad,
        archiveMasterKey,
        recordNumber: 0n,
        plaintext: new Uint8Array(MIN_CHUNK_SIZE_V2),
      })
    ).resolves.toMatchObject({ header: { plaintextLength: MIN_CHUNK_SIZE_V2 } });
    await expect(
      encryptDataRecordV2({
        archiveAad,
        archiveMasterKey,
        recordNumber: 0n,
        plaintext: new Uint8Array(0),
      })
    ).rejects.toThrow(/plaintextLength/i);
    await expect(
      encryptDataRecordV2({
        archiveAad,
        archiveMasterKey,
        recordNumber: 0n,
        plaintext: new Uint8Array(MIN_CHUNK_SIZE_V2 + 1),
      })
    ).rejects.toThrow(/plaintextLength/i);
  });

  it("rejects key, record and nonce parameters outside protocol bounds", async () => {
    const archiveAad = encodeHeaderV2(makeHeader());
    await expect(
      encryptDataRecordV2({
        archiveAad,
        archiveMasterKey: new Uint8Array(31),
        recordNumber: 0n,
        plaintext: bytes(1, 1),
      })
    ).rejects.toThrow(/master key/i);
    await expect(
      encryptDataRecordV2({
        archiveAad,
        archiveMasterKey: bytes(32, 0),
        recordNumber: MAX_DATA_RECORDS_V2,
        plaintext: bytes(1, 1),
      })
    ).rejects.toThrow(/recordNumber|record number/i);
    expect(() => buildDataNonceV2(new Uint8Array(3), 0n)).toThrow(/nonce prefix/i);
  });
});
