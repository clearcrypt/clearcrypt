import { InvalidParamsError } from "../v1/errors";
import { deriveKekArgon2id } from "../v1/kdf";
import { wipeBytesBestEffort } from "../v1/memory";
import { validatePublicPassword } from "../v1/password";
import {
  enforceDecryptResourcePolicy,
  type DecryptResourcePolicy,
} from "../v1/resource-policy";
import {
  unwrapArchiveMasterKeyV2,
  verifyFinalRecordV2,
} from "./archive-crypto";
import {
  decryptDataRecordV2,
  deriveSegmentKeyV2,
  getDataRecordPositionV2,
} from "./data-record-crypto";
import type { V2OperationResult } from "./encrypt-stream";
import { V2IncrementalReader } from "./reader";
import type { V2Header } from "./spec/types";

export type V2DecryptPipelineOptions = {
  resourcePolicy?: Partial<DecryptResourcePolicy>;
};

export type V2DecryptStreamDependencies = {
  deriveKek?: typeof deriveKekArgon2id;
};

async function ignoreFailure(operation: () => Promise<unknown>): Promise<void> {
  try {
    await operation();
  } catch {
    // Cleanup errors must not replace the original pipeline error.
  }
}

export async function decryptStreamV2(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  password: Uint8Array | string,
  options: V2DecryptPipelineOptions = {},
  dependencies: V2DecryptStreamDependencies = {}
): Promise<V2OperationResult> {
  if (!source || typeof source.getReader !== "function") {
    throw new InvalidParamsError("V2 decryption source must be a ReadableStream");
  }
  if (!destination || typeof destination.getWriter !== "function") {
    throw new InvalidParamsError("V2 decryption destination must be a WritableStream");
  }

  const passwordBytes = validatePublicPassword(password);
  const ownsPasswordBytes = typeof password === "string";
  const deriveKek = dependencies.deriveKek ?? deriveKekArgon2id;

  let sourceReader: ReadableStreamDefaultReader<Uint8Array>;
  try {
    sourceReader = source.getReader();
  } catch (error) {
    if (ownsPasswordBytes) wipeBytesBestEffort(passwordBytes);
    throw error;
  }
  let destinationWriter: WritableStreamDefaultWriter<Uint8Array>;
  try {
    destinationWriter = destination.getWriter();
  } catch (error) {
    sourceReader.releaseLock();
    if (ownsPasswordBytes) wipeBytesBestEffort(passwordBytes);
    throw error;
  }

  let sourceFinished = false;
  let destinationClosed = false;
  let kek: Uint8Array | undefined;
  let archiveMasterKey: Uint8Array | undefined;
  let archiveAad: Uint8Array | undefined;
  let archiveHeader: V2Header | undefined;
  let currentSegmentKey: CryptoKey | undefined;
  let currentSegmentNumber: bigint | undefined;
  let finalAuthenticated = false;
  let inputBytes = 0n;
  let outputBytes = 0n;
  let records = 0n;

  try {
    const archiveReader = new V2IncrementalReader(async (item) => {
      if (item.kind === "header") {
        archiveAad = item.bytes;
        archiveHeader = item.header;
        enforceDecryptResourcePolicy(
          {
            kdfId: item.header.passwordKdfId,
            salt: item.header.passwordSalt,
            timeCost: item.header.timeCost,
            memoryCost: item.header.memoryCostKiB,
            parallelism: item.header.parallelism,
          },
          options.resourcePolicy
        );
        kek = await deriveKek({
          password: passwordBytes,
          salt: item.header.passwordSalt,
          timeCost: item.header.timeCost,
          memoryCost: item.header.memoryCostKiB,
          parallelism: item.header.parallelism,
        });
        try {
          archiveMasterKey = await unwrapArchiveMasterKeyV2({
            archiveAad: item.bytes,
            kekRaw32: kek,
          });
        } finally {
          wipeBytesBestEffort(kek);
          kek = undefined;
        }
        return;
      }

      if (!archiveAad || !archiveHeader || !archiveMasterKey) {
        throw new InvalidParamsError("V2 archive key is unavailable");
      }

      if (item.kind === "data") {
        const position = getDataRecordPositionV2(
          item.header.recordNumber,
          archiveHeader.chunkSize
        );
        if (currentSegmentNumber !== position.segmentNumber || !currentSegmentKey) {
          currentSegmentKey = await deriveSegmentKeyV2({
            archiveMasterKey,
            archiveId: archiveHeader.archiveId,
            segmentNumber: position.segmentNumber,
          });
          currentSegmentNumber = position.segmentNumber;
        }
        const plaintext = await decryptDataRecordV2({
          archiveAad,
          archiveMasterKey,
          headerBytes: item.headerBytes,
          ciphertext: item.ciphertext,
          tag: item.tag,
          segmentKey: currentSegmentKey,
        });
        await destinationWriter.write(plaintext);
        outputBytes += BigInt(plaintext.length);
        records += 1n;
        return;
      }

      currentSegmentKey = undefined;
      currentSegmentNumber = undefined;
      await verifyFinalRecordV2({
        archiveAad,
        archiveMasterKey,
        headerBytes: item.headerBytes,
        tag: item.tag,
      });
      finalAuthenticated = true;
    });

    while (true) {
      const read = await sourceReader.read();
      if (read.done) {
        sourceFinished = true;
        break;
      }
      if (!(read.value instanceof Uint8Array)) {
        throw new InvalidParamsError("V2 decryption source must emit Uint8Array chunks");
      }
      inputBytes += BigInt(read.value.length);
      await archiveReader.write(read.value);
    }
    archiveReader.end();
    if (!finalAuthenticated) {
      throw new InvalidParamsError("V2 FINAL record was not authenticated");
    }

    await destinationWriter.close();
    destinationClosed = true;
    return { format: "CFENC002", inputBytes, outputBytes, records };
  } catch (error) {
    if (!sourceFinished) {
      await ignoreFailure(() => sourceReader.cancel(error));
    }
    if (!destinationClosed) {
      await ignoreFailure(() => destinationWriter.abort(error));
    }
    throw error;
  } finally {
    currentSegmentKey = undefined;
    wipeBytesBestEffort(archiveMasterKey);
    wipeBytesBestEffort(kek);
    if (ownsPasswordBytes) wipeBytesBestEffort(passwordBytes);
    sourceReader.releaseLock();
    destinationWriter.releaseLock();
  }
}
