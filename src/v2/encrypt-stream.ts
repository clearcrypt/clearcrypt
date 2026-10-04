import { secureRandomBytes } from "../v1/crypto-runtime";
import { InvalidParamsError } from "../v1/errors";
import { assertValidArgon2idParams, deriveKekArgon2id } from "../v1/kdf";
import { wipeBytesBestEffort } from "../v1/memory";
import { validatePublicPassword } from "../v1/password";
import {
  authenticateFinalRecordV2,
  createWrappedHeaderV2,
} from "./archive-crypto";
import {
  deriveSegmentKeyV2,
  encryptDataRecordV2,
  getDataRecordPositionV2,
} from "./data-record-crypto";
import { encodeHeaderV2 } from "./spec/codec";
import {
  ARCHIVE_KEY_WRAP_AES_256_GCM_V2,
  ARCHIVE_MASTER_KEY_LENGTH_V2,
  CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
  CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
  DEFAULT_CHUNK_SIZE_V2,
  MAX_DATA_RECORDS_V2,
  MAX_PLAINTEXT_LENGTH_V2,
  PASSWORD_KDF_ARGON2ID_V2,
  VERSION_V2,
} from "./spec/constants";
import { V2IncrementalWriter } from "./writer";

export type V2EncryptKdfOptions = {
  timeCost?: number;
  memoryCostKiB?: number;
  parallelism?: number;
};

export type V2EncryptPipelineOptions = {
  chunkSize?: number;
  kdf?: V2EncryptKdfOptions;
};

export type V2OperationResult = {
  format: "CFENC002";
  inputBytes: bigint;
  outputBytes: bigint;
  records: bigint;
};

export type V2EncryptStreamDependencies = {
  randomBytes?: (length: number) => Uint8Array;
  deriveKek?: typeof deriveKekArgon2id;
};

const DEFAULT_KDF_V2 = {
  timeCost: 2,
  memoryCostKiB: 64 * 1024,
  parallelism: 2,
} as const;

function checkedRandomBytes(
  randomBytes: (length: number) => Uint8Array,
  length: number
): Uint8Array {
  const value = randomBytes(length);
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new InvalidParamsError(`V2 random source must return exactly ${length} bytes`);
  }
  return value.slice();
}

async function ignoreFailure(operation: () => Promise<unknown>): Promise<void> {
  try {
    await operation();
  } catch {
    // Cleanup errors must not replace the original pipeline error.
  }
}

export async function encryptStreamV2(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  password: Uint8Array | string,
  options: V2EncryptPipelineOptions = {},
  dependencies: V2EncryptStreamDependencies = {}
): Promise<V2OperationResult> {
  if (!source || typeof source.getReader !== "function") {
    throw new InvalidParamsError("V2 encryption source must be a ReadableStream");
  }
  if (!destination || typeof destination.getWriter !== "function") {
    throw new InvalidParamsError("V2 encryption destination must be a WritableStream");
  }

  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE_V2;
  getDataRecordPositionV2(0n, chunkSize);
  const kdf = {
    timeCost: options.kdf?.timeCost ?? DEFAULT_KDF_V2.timeCost,
    memoryCostKiB: options.kdf?.memoryCostKiB ?? DEFAULT_KDF_V2.memoryCostKiB,
    parallelism: options.kdf?.parallelism ?? DEFAULT_KDF_V2.parallelism,
  };
  const passwordBytes = validatePublicPassword(password);
  const ownsPasswordBytes = typeof password === "string";
  const randomBytes = dependencies.randomBytes ?? secureRandomBytes;
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
  let workBuffer: Uint8Array | undefined;
  let currentSegmentKey: CryptoKey | undefined;
  let inputBytes = 0n;
  let outputBytes = 0n;
  let records = 0n;
  let totalPlaintextLength = 0n;

  try {
    const archiveId = checkedRandomBytes(randomBytes, 16);
    const contentNoncePrefix = checkedRandomBytes(randomBytes, 4);
    const passwordSalt = checkedRandomBytes(randomBytes, 16);
    const wrapNonce = checkedRandomBytes(randomBytes, 12);
    archiveMasterKey = checkedRandomBytes(randomBytes, ARCHIVE_MASTER_KEY_LENGTH_V2);

    assertValidArgon2idParams({
      salt: passwordSalt,
      timeCost: kdf.timeCost,
      memoryCost: kdf.memoryCostKiB,
      parallelism: kdf.parallelism,
    });
    kek = await deriveKek({
      password: passwordBytes,
      salt: passwordSalt,
      timeCost: kdf.timeCost,
      memoryCost: kdf.memoryCostKiB,
      parallelism: kdf.parallelism,
    });

    const header = await createWrappedHeaderV2({
      fields: {
        version: VERSION_V2,
        contentCipherId: CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
        contentKeyScheduleId: CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
        chunkSize,
        archiveId,
        contentNoncePrefix,
        passwordKdfId: PASSWORD_KDF_ARGON2ID_V2,
        passwordSalt,
        timeCost: kdf.timeCost,
        memoryCostKiB: kdf.memoryCostKiB,
        parallelism: kdf.parallelism,
        archiveKeyWrapCipherId: ARCHIVE_KEY_WRAP_AES_256_GCM_V2,
        wrapNonce,
      },
      archiveMasterKey,
      kekRaw32: kek,
    });
    const archiveAad = encodeHeaderV2(header);
    const archiveWriter = new V2IncrementalWriter({
      async write(chunk) {
        await destinationWriter.write(chunk);
        outputBytes += BigInt(chunk.length);
      },
    });
    await archiveWriter.writeHeader(header);

    workBuffer = new Uint8Array(chunkSize);
    let buffered = 0;
    let currentSegmentNumber: bigint | undefined;

    const emitDataRecord = async (plaintext: Uint8Array): Promise<void> => {
      if (records >= MAX_DATA_RECORDS_V2) {
        throw new InvalidParamsError("V2 DATA record count exceeds the format limit");
      }
      const nextTotal = totalPlaintextLength + BigInt(plaintext.length);
      if (nextTotal > MAX_PLAINTEXT_LENGTH_V2) {
        throw new InvalidParamsError("V2 plaintext length exceeds the format limit");
      }

      const position = getDataRecordPositionV2(records, chunkSize);
      if (currentSegmentNumber !== position.segmentNumber || !currentSegmentKey) {
        currentSegmentKey = await deriveSegmentKeyV2({
          archiveMasterKey: archiveMasterKey!,
          archiveId,
          segmentNumber: position.segmentNumber,
        });
        currentSegmentNumber = position.segmentNumber;
      }
      const encrypted = await encryptDataRecordV2({
        archiveAad,
        archiveMasterKey: archiveMasterKey!,
        recordNumber: records,
        plaintext,
        segmentKey: currentSegmentKey,
      });
      await archiveWriter.writeDataRecord(
        encrypted.header,
        encrypted.ciphertext,
        encrypted.tag
      );
      records += 1n;
      totalPlaintextLength = nextTotal;
    };

    while (true) {
      const read = await sourceReader.read();
      if (read.done) {
        sourceFinished = true;
        break;
      }
      if (!(read.value instanceof Uint8Array)) {
        throw new InvalidParamsError("V2 encryption source must emit Uint8Array chunks");
      }
      const nextInputBytes = inputBytes + BigInt(read.value.length);
      if (nextInputBytes > MAX_PLAINTEXT_LENGTH_V2) {
        throw new InvalidParamsError("V2 plaintext length exceeds the format limit");
      }
      inputBytes = nextInputBytes;

      let sourceOffset = 0;
      while (sourceOffset < read.value.length) {
        const copied = Math.min(chunkSize - buffered, read.value.length - sourceOffset);
        workBuffer.set(read.value.subarray(sourceOffset, sourceOffset + copied), buffered);
        sourceOffset += copied;
        buffered += copied;

        if (buffered === chunkSize) {
          await emitDataRecord(workBuffer);
          workBuffer.fill(0);
          buffered = 0;
        }
      }
    }

    if (buffered > 0) {
      await emitDataRecord(workBuffer.subarray(0, buffered));
      workBuffer.fill(0);
    }
    currentSegmentKey = undefined;

    const finalRecord = await authenticateFinalRecordV2({
      archiveAad,
      archiveMasterKey,
      dataRecordCount: records,
      totalPlaintextLength,
    });
    await archiveWriter.writeFinalRecord(finalRecord.header, finalRecord.tag);
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
    wipeBytesBestEffort(workBuffer);
    wipeBytesBestEffort(archiveMasterKey);
    wipeBytesBestEffort(kek);
    if (ownsPasswordBytes) wipeBytesBestEffort(passwordBytes);
    sourceReader.releaseLock();
    destinationWriter.releaseLock();
  }
}
