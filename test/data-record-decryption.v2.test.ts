import { describe, expect, it } from "vitest";
import { AuthenticationError, InvalidParamsError } from "../src/v1/errors";
import {
  decryptDataRecordV2,
  encryptDataRecordV2,
} from "../src/v2/data-record-crypto";
import { encodeHeaderV2 } from "../src/v2/spec/codec";
import {
  ARCHIVE_KEY_WRAP_AES_256_GCM_V2,
  CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
  CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
  MIN_CHUNK_SIZE_V2,
  PASSWORD_KDF_ARGON2ID_V2,
  VERSION_V2,
} from "../src/v2/spec/constants";
import type { V2Header } from "../src/v2/spec/types";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
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

async function makeRecord(recordNumber: bigint, plaintext: Uint8Array) {
  const archiveAad = encodeHeaderV2(makeHeader());
  const archiveMasterKey = bytes(32, 0);
  const encrypted = await encryptDataRecordV2({
    archiveAad,
    archiveMasterKey,
    recordNumber,
    plaintext,
  });
  return { archiveAad, archiveMasterKey, plaintext, ...encrypted };
}

describe("V2 DATA record decryption", () => {
  it.each([
    ["short", 0n, 31],
    ["full", 0n, MIN_CHUNK_SIZE_V2],
    ["first record of segment one", 1n << 14n, 29],
  ])("decrypts a %s block exactly", async (_name, recordNumber, length) => {
    const record = await makeRecord(recordNumber, bytes(length, 0x80));

    await expect(
      decryptDataRecordV2({
        archiveAad: record.archiveAad,
        archiveMasterKey: record.archiveMasterKey,
        headerBytes: record.headerBytes,
        ciphertext: record.ciphertext,
        tag: record.tag,
      })
    ).resolves.toEqual(record.plaintext);
  });

  it("reports the same authentication error for a wrong key, ciphertext or tag", async () => {
    const record = await makeRecord(0n, bytes(32, 0x80));
    const changedCiphertext = record.ciphertext.slice();
    changedCiphertext[0] = changedCiphertext[0]! ^ 1;
    const changedTag = record.tag.slice();
    changedTag[0] = changedTag[0]! ^ 1;

    const attempts = [
      { archiveMasterKey: bytes(32, 1), ciphertext: record.ciphertext, tag: record.tag },
      { archiveMasterKey: record.archiveMasterKey, ciphertext: changedCiphertext, tag: record.tag },
      { archiveMasterKey: record.archiveMasterKey, ciphertext: record.ciphertext, tag: changedTag },
    ];

    for (const attempt of attempts) {
      let received: unknown;
      try {
        await decryptDataRecordV2({
          archiveAad: record.archiveAad,
          archiveMasterKey: attempt.archiveMasterKey,
          headerBytes: record.headerBytes,
          ciphertext: attempt.ciphertext,
          tag: attempt.tag,
        });
      } catch (error) {
        received = error;
      }
      expect(received).toBeInstanceOf(AuthenticationError);
      expect((received as Error).message).toBe("Authentication failed");
    }
  });

  it("authenticates the exact archive and DATA header bytes", async () => {
    const record = await makeRecord(0n, bytes(32, 0x80));
    const changedArchive = record.archiveAad.slice();
    changedArchive[changedArchive.length - 1] = changedArchive.at(-1)! ^ 1;
    const changedRecordHeader = record.headerBytes.slice();
    changedRecordHeader[8] = 1;

    await expect(
      decryptDataRecordV2({
        archiveAad: changedArchive,
        archiveMasterKey: record.archiveMasterKey,
        headerBytes: record.headerBytes,
        ciphertext: record.ciphertext,
        tag: record.tag,
      })
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      decryptDataRecordV2({
        archiveAad: record.archiveAad,
        archiveMasterKey: record.archiveMasterKey,
        headerBytes: changedRecordHeader,
        ciphertext: record.ciphertext,
        tag: record.tag,
      })
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it("rejects malformed lengths before attempting authentication", async () => {
    const record = await makeRecord(0n, bytes(32, 0x80));

    await expect(
      decryptDataRecordV2({
        archiveAad: record.archiveAad,
        archiveMasterKey: record.archiveMasterKey,
        headerBytes: record.headerBytes,
        ciphertext: record.ciphertext.subarray(1),
        tag: record.tag,
      })
    ).rejects.toBeInstanceOf(InvalidParamsError);
    await expect(
      decryptDataRecordV2({
        archiveAad: record.archiveAad,
        archiveMasterKey: record.archiveMasterKey,
        headerBytes: record.headerBytes,
        ciphertext: record.ciphertext,
        tag: record.tag.subarray(1),
      })
    ).rejects.toBeInstanceOf(InvalidParamsError);
  });
});
