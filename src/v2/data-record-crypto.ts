import { aeadDecryptAes256Gcm, aeadEncryptAes256Gcm } from "../v1/aead";
import { getWebCrypto } from "../v1/crypto-runtime";
import { CryptoOperationError, InvalidParamsError } from "../v1/errors";
import {
  decodeHeaderV2,
  decodeDataRecordHeaderV2,
  encodeDataRecordHeaderV2,
  encodeU64BE,
} from "./spec/codec";
import {
  ARCHIVE_MASTER_KEY_LENGTH_V2,
  AUTH_TAG_LENGTH_V2,
  CONTENT_NONCE_PREFIX_LENGTH_V2,
  MAX_CHUNK_SIZE_V2,
  MAX_DATA_RECORDS_V2,
  MAX_SEGMENTS_V2,
  MIN_CHUNK_SIZE_V2,
  RECORD_TYPE_DATA_V2,
  SEGMENT_KEY_INFO_LABEL_V2,
  SEGMENT_PLAINTEXT_SIZE_V2,
  V2_DATA_RECORD_HEADER_LENGTH,
  V2_HEADER_LENGTH,
} from "./spec/constants";
import type { V2DataRecordHeader } from "./spec/types";

const SEGMENT_KEY_INFO_LABEL_BYTES_V2 = new TextEncoder().encode(
  SEGMENT_KEY_INFO_LABEL_V2
);

function toWebCryptoBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.buffer instanceof ArrayBuffer) {
    return bytes as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(bytes);
}

function concatBytes(first: Uint8Array, second: Uint8Array): Uint8Array {
  const result = new Uint8Array(first.length + second.length);
  result.set(first, 0);
  result.set(second, first.length);
  return result;
}

export type V2DataRecordPosition = {
  recordsPerSegment: bigint;
  segmentNumber: bigint;
  localRecordNumber: bigint;
};

export type V2EncryptedDataRecord = {
  header: V2DataRecordHeader;
  headerBytes: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
};

export function getDataRecordPositionV2(
  recordNumber: bigint,
  chunkSize: number
): V2DataRecordPosition {
  if (recordNumber < 0n || recordNumber >= MAX_DATA_RECORDS_V2) {
    throw new InvalidParamsError("V2 DATA record number is outside its supported range");
  }
  if (
    !Number.isSafeInteger(chunkSize) ||
    chunkSize < MIN_CHUNK_SIZE_V2 ||
    chunkSize > MAX_CHUNK_SIZE_V2 ||
    (chunkSize & (chunkSize - 1)) !== 0 ||
    SEGMENT_PLAINTEXT_SIZE_V2 % BigInt(chunkSize) !== 0n
  ) {
    throw new InvalidParamsError("Invalid V2 chunk size for segmented key derivation");
  }

  const recordsPerSegment = SEGMENT_PLAINTEXT_SIZE_V2 / BigInt(chunkSize);
  const segmentNumber = recordNumber / recordsPerSegment;
  if (segmentNumber >= MAX_SEGMENTS_V2) {
    throw new InvalidParamsError("V2 DATA segment number exceeds the format limit");
  }

  return {
    recordsPerSegment,
    segmentNumber,
    localRecordNumber: recordNumber % recordsPerSegment,
  };
}

export function buildDataNonceV2(
  contentNoncePrefix: Uint8Array,
  localRecordNumber: bigint
): Uint8Array {
  if (
    !(contentNoncePrefix instanceof Uint8Array) ||
    contentNoncePrefix.length !== CONTENT_NONCE_PREFIX_LENGTH_V2
  ) {
    throw new InvalidParamsError(
      `V2 content nonce prefix must be ${CONTENT_NONCE_PREFIX_LENGTH_V2} bytes`
    );
  }
  return concatBytes(contentNoncePrefix, encodeU64BE(localRecordNumber));
}

export function buildDataAadV2(
  archiveAad: Uint8Array,
  dataRecordHeader: Uint8Array
): Uint8Array {
  if (!(archiveAad instanceof Uint8Array) || archiveAad.length !== V2_HEADER_LENGTH) {
    throw new InvalidParamsError(`V2 archive AAD must be ${V2_HEADER_LENGTH} bytes`);
  }
  if (
    !(dataRecordHeader instanceof Uint8Array) ||
    dataRecordHeader.length !== V2_DATA_RECORD_HEADER_LENGTH
  ) {
    throw new InvalidParamsError(
      `V2 DATA record header must be ${V2_DATA_RECORD_HEADER_LENGTH} bytes`
    );
  }
  return concatBytes(archiveAad, dataRecordHeader);
}

export async function deriveSegmentKeyV2(params: {
  archiveMasterKey: Uint8Array;
  archiveId: Uint8Array;
  segmentNumber: bigint;
}): Promise<CryptoKey> {
  const { archiveMasterKey, archiveId, segmentNumber } = params;
  if (
    !(archiveMasterKey instanceof Uint8Array) ||
    archiveMasterKey.length !== ARCHIVE_MASTER_KEY_LENGTH_V2
  ) {
    throw new InvalidParamsError(
      `V2 archive master key must be ${ARCHIVE_MASTER_KEY_LENGTH_V2} bytes`
    );
  }
  if (!(archiveId instanceof Uint8Array) || archiveId.length !== 16) {
    throw new InvalidParamsError("V2 archive ID must be 16 bytes");
  }
  if (segmentNumber < 0n || segmentNumber >= MAX_SEGMENTS_V2) {
    throw new InvalidParamsError("V2 segment number is outside its supported range");
  }

  const info = concatBytes(SEGMENT_KEY_INFO_LABEL_BYTES_V2, encodeU64BE(segmentNumber));
  try {
    const crypto = getWebCrypto();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      toWebCryptoBytes(archiveMasterKey),
      "HKDF",
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: toWebCryptoBytes(archiveId),
        info: toWebCryptoBytes(info),
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } catch (cause) {
    throw new CryptoOperationError("Unable to derive V2 DATA segment key", cause);
  }
}

export async function encryptDataRecordV2(params: {
  archiveAad: Uint8Array;
  archiveMasterKey: Uint8Array;
  recordNumber: bigint;
  plaintext: Uint8Array;
  segmentKey?: CryptoKey;
}): Promise<V2EncryptedDataRecord> {
  const { archiveAad, archiveMasterKey, recordNumber, plaintext, segmentKey } = params;
  if (!(archiveAad instanceof Uint8Array)) {
    throw new InvalidParamsError("V2 archive AAD must be a Uint8Array");
  }
  if (!(plaintext instanceof Uint8Array)) {
    throw new InvalidParamsError("V2 DATA plaintext must be a Uint8Array");
  }

  const archiveHeader = decodeHeaderV2(archiveAad);
  const header: V2DataRecordHeader = {
    recordType: RECORD_TYPE_DATA_V2,
    recordNumber,
    plaintextLength: plaintext.length,
  };
  const headerBytes = encodeDataRecordHeaderV2(header, archiveHeader.chunkSize);
  const position = getDataRecordPositionV2(recordNumber, archiveHeader.chunkSize);
  const nonce = buildDataNonceV2(
    archiveHeader.contentNoncePrefix,
    position.localRecordNumber
  );
  const aad = buildDataAadV2(archiveAad, headerBytes);
  const key =
    segmentKey ??
    (await deriveSegmentKeyV2({
      archiveMasterKey,
      archiveId: archiveHeader.archiveId,
      segmentNumber: position.segmentNumber,
    }));
  const { ciphertext, tag } = await aeadEncryptAes256Gcm({
    key,
    nonce,
    plaintext,
    associatedAuthenticatedData: aad,
  });

  return { header, headerBytes, ciphertext, tag };
}

export async function decryptDataRecordV2(params: {
  archiveAad: Uint8Array;
  archiveMasterKey: Uint8Array;
  headerBytes: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}): Promise<Uint8Array> {
  const { archiveAad, archiveMasterKey, headerBytes, ciphertext, tag } = params;
  if (!(archiveAad instanceof Uint8Array)) {
    throw new InvalidParamsError("V2 archive AAD must be a Uint8Array");
  }
  if (!(headerBytes instanceof Uint8Array)) {
    throw new InvalidParamsError("V2 DATA record header must be a Uint8Array");
  }
  if (!(ciphertext instanceof Uint8Array)) {
    throw new InvalidParamsError("V2 DATA ciphertext must be a Uint8Array");
  }
  if (!(tag instanceof Uint8Array) || tag.length !== AUTH_TAG_LENGTH_V2) {
    throw new InvalidParamsError(
      `V2 DATA tag must be exactly ${AUTH_TAG_LENGTH_V2} bytes`
    );
  }

  const archiveHeader = decodeHeaderV2(archiveAad);
  const recordHeader = decodeDataRecordHeaderV2(headerBytes, archiveHeader.chunkSize);
  if (ciphertext.length !== recordHeader.plaintextLength) {
    throw new InvalidParamsError(
      "V2 DATA ciphertext length does not match its record header"
    );
  }

  const position = getDataRecordPositionV2(
    recordHeader.recordNumber,
    archiveHeader.chunkSize
  );
  const nonce = buildDataNonceV2(
    archiveHeader.contentNoncePrefix,
    position.localRecordNumber
  );
  const aad = buildDataAadV2(archiveAad, headerBytes);
  const key = await deriveSegmentKeyV2({
    archiveMasterKey,
    archiveId: archiveHeader.archiveId,
    segmentNumber: position.segmentNumber,
  });

  return aeadDecryptAes256Gcm({
    key,
    nonce,
    ciphertext,
    tag,
    associatedAuthenticatedData: aad,
  });
}
