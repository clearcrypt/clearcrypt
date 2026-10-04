import {
  FormatError,
  InvalidParamsError,
  UnsupportedAlgorithmError,
  UnsupportedFormatError,
} from "../../v1/errors";
import {
  ARCHIVE_ID_LENGTH_V2,
  ARCHIVE_KEY_WRAP_AES_256_GCM_V2,
  ARCHIVE_MASTER_KEY_LENGTH_V2,
  AUTH_TAG_LENGTH_V2,
  CONTENT_CIPHER_AES_256_GCM_RECORDS_V2,
  CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2,
  CONTENT_NONCE_PREFIX_LENGTH_V2,
  MAGIC_V2,
  MAX_CHUNK_SIZE_V2,
  MAX_DATA_RECORDS_V2,
  MAX_MEMORY_COST_KIB_V2,
  MAX_PARALLELISM_V2,
  MAX_PLAINTEXT_LENGTH_V2,
  MAX_TIME_COST_V2,
  MIN_CHUNK_SIZE_V2,
  MIN_MEMORY_COST_KIB_V2,
  MIN_PARALLELISM_V2,
  MIN_TIME_COST_V2,
  PASSWORD_KDF_ARGON2ID_V2,
  PASSWORD_SALT_LENGTH_V2,
  RECORD_TYPE_DATA_V2,
  RECORD_TYPE_FINAL_V2,
  U32_MAX,
  U64_MAX,
  V2_DATA_RECORD_HEADER_LENGTH,
  V2_FINAL_RECORD_HEADER_LENGTH,
  V2_HEADER_LENGTH,
  V2_HEADER_OFFSETS,
  VERSION_V2,
  WRAP_NONCE_LENGTH_V2,
} from "./constants";
import type {
  V2DataRecordHeader,
  V2FinalRecordHeader,
  V2Header,
} from "./types";

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function isPowerOfTwo(value: number): boolean {
  return value > 0 && Number.isSafeInteger(value) && Math.log2(value) % 1 === 0;
}

function assertEncodeInteger(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new InvalidParamsError(`${name} must be an integer from ${min} through ${max}`);
  }
}

function assertDecodeInteger(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new FormatError(`Invalid ${name}`);
  }
}

function assertEncodeBytes(name: string, value: Uint8Array, length: number): void {
  if (value.length !== length) {
    throw new InvalidParamsError(`${name} must be ${length} bytes`);
  }
}

function assertChunkSizeForEncode(chunkSize: number): void {
  if (
    !isPowerOfTwo(chunkSize) ||
    chunkSize < MIN_CHUNK_SIZE_V2 ||
    chunkSize > MAX_CHUNK_SIZE_V2
  ) {
    throw new InvalidParamsError("chunkSize must be a power of two from 64 KiB through 16 MiB");
  }
}

function assertChunkSizeForDecode(chunkSize: number): void {
  if (
    !isPowerOfTwo(chunkSize) ||
    chunkSize < MIN_CHUNK_SIZE_V2 ||
    chunkSize > MAX_CHUNK_SIZE_V2
  ) {
    throw new FormatError("Invalid V2 chunk size");
  }
}

function assertEncodeBigInt(name: string, value: bigint, max: bigint): void {
  if (value < 0n || value > max) {
    throw new InvalidParamsError(`${name} is outside its supported range`);
  }
}

function assertExactDecodeLength(name: string, bytes: Uint8Array, length: number): void {
  if (bytes.length !== length) {
    throw new FormatError(`${name} must be exactly ${length} bytes`);
  }
}

function setBytes(target: Uint8Array, offset: number, value: Uint8Array): void {
  target.set(value, offset);
}

export function encodeU32BE(value: number): Uint8Array {
  assertEncodeInteger("u32 value", value, 0, U32_MAX);
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

export function decodeU32BE(bytes: Uint8Array): number {
  assertExactDecodeLength("u32 value", bytes, 4);
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
}

export function encodeU64BE(value: bigint): Uint8Array {
  assertEncodeBigInt("u64 value", value, U64_MAX);
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);
  return bytes;
}

export function decodeU64BE(bytes: Uint8Array): bigint {
  assertExactDecodeLength("u64 value", bytes, 8);
  return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, false);
}

function validateHeaderForEncode(header: V2Header): void {
  if (header.version !== VERSION_V2) {
    throw new InvalidParamsError("version must identify CFENC002");
  }
  if (header.contentCipherId !== CONTENT_CIPHER_AES_256_GCM_RECORDS_V2) {
    throw new InvalidParamsError("Unsupported V2 content cipher");
  }
  if (header.contentKeyScheduleId !== CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2) {
    throw new InvalidParamsError("Unsupported V2 content key schedule");
  }
  if (header.passwordKdfId !== PASSWORD_KDF_ARGON2ID_V2) {
    throw new InvalidParamsError("Unsupported V2 password KDF");
  }
  if (header.archiveKeyWrapCipherId !== ARCHIVE_KEY_WRAP_AES_256_GCM_V2) {
    throw new InvalidParamsError("Unsupported V2 archive-key wrap cipher");
  }

  assertChunkSizeForEncode(header.chunkSize);
  assertEncodeBytes("archiveId", header.archiveId, ARCHIVE_ID_LENGTH_V2);
  assertEncodeBytes(
    "contentNoncePrefix",
    header.contentNoncePrefix,
    CONTENT_NONCE_PREFIX_LENGTH_V2
  );
  assertEncodeBytes("passwordSalt", header.passwordSalt, PASSWORD_SALT_LENGTH_V2);
  assertEncodeInteger("timeCost", header.timeCost, MIN_TIME_COST_V2, MAX_TIME_COST_V2);
  assertEncodeInteger(
    "memoryCostKiB",
    header.memoryCostKiB,
    MIN_MEMORY_COST_KIB_V2,
    MAX_MEMORY_COST_KIB_V2
  );
  assertEncodeInteger(
    "parallelism",
    header.parallelism,
    MIN_PARALLELISM_V2,
    MAX_PARALLELISM_V2
  );
  assertEncodeBytes("wrapNonce", header.wrapNonce, WRAP_NONCE_LENGTH_V2);
  assertEncodeBytes(
    "wrappedArchiveKeyCiphertext",
    header.wrappedArchiveKeyCiphertext,
    ARCHIVE_MASTER_KEY_LENGTH_V2
  );
  assertEncodeBytes("wrappedArchiveKeyTag", header.wrappedArchiveKeyTag, AUTH_TAG_LENGTH_V2);
}

export function encodeHeaderV2(header: V2Header): Uint8Array {
  validateHeaderForEncode(header);

  const bytes = new Uint8Array(V2_HEADER_LENGTH);
  const view = new DataView(bytes.buffer);

  setBytes(bytes, V2_HEADER_OFFSETS.magic, MAGIC_V2);
  bytes[V2_HEADER_OFFSETS.version] = header.version;
  bytes[V2_HEADER_OFFSETS.contentCipherId] = header.contentCipherId;
  bytes[V2_HEADER_OFFSETS.contentKeyScheduleId] = header.contentKeyScheduleId;
  view.setUint32(V2_HEADER_OFFSETS.chunkSize, header.chunkSize, false);
  setBytes(bytes, V2_HEADER_OFFSETS.archiveId, header.archiveId);
  setBytes(bytes, V2_HEADER_OFFSETS.contentNoncePrefix, header.contentNoncePrefix);
  bytes[V2_HEADER_OFFSETS.passwordKdfId] = header.passwordKdfId;
  setBytes(bytes, V2_HEADER_OFFSETS.passwordSalt, header.passwordSalt);
  view.setUint32(V2_HEADER_OFFSETS.timeCost, header.timeCost, false);
  view.setUint32(V2_HEADER_OFFSETS.memoryCostKiB, header.memoryCostKiB, false);
  bytes[V2_HEADER_OFFSETS.parallelism] = header.parallelism;
  bytes[V2_HEADER_OFFSETS.archiveKeyWrapCipherId] = header.archiveKeyWrapCipherId;
  setBytes(bytes, V2_HEADER_OFFSETS.wrapNonce, header.wrapNonce);
  setBytes(
    bytes,
    V2_HEADER_OFFSETS.wrappedArchiveKeyCiphertext,
    header.wrappedArchiveKeyCiphertext
  );
  setBytes(bytes, V2_HEADER_OFFSETS.wrappedArchiveKeyTag, header.wrappedArchiveKeyTag);

  return bytes;
}

export function decodeHeaderV2(bytes: Uint8Array): V2Header {
  assertExactDecodeLength("CFENC002 header", bytes, V2_HEADER_LENGTH);

  if (!equalBytes(bytes.subarray(0, MAGIC_V2.length), MAGIC_V2)) {
    throw new FormatError("Invalid CFENC002 magic");
  }

  const version = bytes[V2_HEADER_OFFSETS.version]!;
  if (version !== VERSION_V2) {
    throw new UnsupportedFormatError(`Unsupported format version: ${version}`);
  }

  const contentCipherId = bytes[V2_HEADER_OFFSETS.contentCipherId]!;
  const contentKeyScheduleId = bytes[V2_HEADER_OFFSETS.contentKeyScheduleId]!;
  const passwordKdfId = bytes[V2_HEADER_OFFSETS.passwordKdfId]!;
  const archiveKeyWrapCipherId = bytes[V2_HEADER_OFFSETS.archiveKeyWrapCipherId]!;

  if (contentCipherId !== CONTENT_CIPHER_AES_256_GCM_RECORDS_V2) {
    throw new UnsupportedAlgorithmError("Unsupported V2 content cipher");
  }
  if (contentKeyScheduleId !== CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2) {
    throw new UnsupportedAlgorithmError("Unsupported V2 content key schedule");
  }
  if (passwordKdfId !== PASSWORD_KDF_ARGON2ID_V2) {
    throw new UnsupportedAlgorithmError("Unsupported V2 password KDF");
  }
  if (archiveKeyWrapCipherId !== ARCHIVE_KEY_WRAP_AES_256_GCM_V2) {
    throw new UnsupportedAlgorithmError("Unsupported V2 archive-key wrap cipher");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunkSize = view.getUint32(V2_HEADER_OFFSETS.chunkSize, false);
  const timeCost = view.getUint32(V2_HEADER_OFFSETS.timeCost, false);
  const memoryCostKiB = view.getUint32(V2_HEADER_OFFSETS.memoryCostKiB, false);
  const parallelism = bytes[V2_HEADER_OFFSETS.parallelism]!;

  assertChunkSizeForDecode(chunkSize);
  assertDecodeInteger("timeCost", timeCost, MIN_TIME_COST_V2, MAX_TIME_COST_V2);
  assertDecodeInteger(
    "memoryCostKiB",
    memoryCostKiB,
    MIN_MEMORY_COST_KIB_V2,
    MAX_MEMORY_COST_KIB_V2
  );
  assertDecodeInteger(
    "parallelism",
    parallelism,
    MIN_PARALLELISM_V2,
    MAX_PARALLELISM_V2
  );

  return {
    version,
    contentCipherId,
    contentKeyScheduleId,
    chunkSize,
    archiveId: bytes.subarray(V2_HEADER_OFFSETS.archiveId, V2_HEADER_OFFSETS.contentNoncePrefix),
    contentNoncePrefix: bytes.subarray(
      V2_HEADER_OFFSETS.contentNoncePrefix,
      V2_HEADER_OFFSETS.passwordKdfId
    ),
    passwordKdfId,
    passwordSalt: bytes.subarray(V2_HEADER_OFFSETS.passwordSalt, V2_HEADER_OFFSETS.timeCost),
    timeCost,
    memoryCostKiB,
    parallelism,
    archiveKeyWrapCipherId,
    wrapNonce: bytes.subarray(
      V2_HEADER_OFFSETS.wrapNonce,
      V2_HEADER_OFFSETS.wrappedArchiveKeyCiphertext
    ),
    wrappedArchiveKeyCiphertext: bytes.subarray(
      V2_HEADER_OFFSETS.wrappedArchiveKeyCiphertext,
      V2_HEADER_OFFSETS.wrappedArchiveKeyTag
    ),
    wrappedArchiveKeyTag: bytes.subarray(
      V2_HEADER_OFFSETS.wrappedArchiveKeyTag,
      V2_HEADER_LENGTH
    ),
  };
}

export function encodeDataRecordHeaderV2(
  header: V2DataRecordHeader,
  chunkSize: number
): Uint8Array {
  assertChunkSizeForEncode(chunkSize);
  if (header.recordType !== RECORD_TYPE_DATA_V2) {
    throw new InvalidParamsError("recordType must identify a V2 DATA record");
  }
  assertEncodeBigInt("recordNumber", header.recordNumber, MAX_DATA_RECORDS_V2 - 1n);
  assertEncodeInteger("plaintextLength", header.plaintextLength, 1, chunkSize);

  const bytes = new Uint8Array(V2_DATA_RECORD_HEADER_LENGTH);
  const view = new DataView(bytes.buffer);
  bytes[0] = RECORD_TYPE_DATA_V2;
  view.setBigUint64(1, header.recordNumber, false);
  view.setUint32(9, header.plaintextLength, false);
  return bytes;
}

export function decodeDataRecordHeaderV2(
  bytes: Uint8Array,
  chunkSize: number
): V2DataRecordHeader {
  assertExactDecodeLength("V2 DATA record header", bytes, V2_DATA_RECORD_HEADER_LENGTH);
  assertChunkSizeForDecode(chunkSize);
  if (bytes[0] !== RECORD_TYPE_DATA_V2) {
    throw new FormatError("Expected a V2 DATA record");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const recordNumber = view.getBigUint64(1, false);
  const plaintextLength = view.getUint32(9, false);
  if (recordNumber >= MAX_DATA_RECORDS_V2) {
    throw new FormatError("V2 DATA record number exceeds the format limit");
  }
  assertDecodeInteger("DATA plaintext length", plaintextLength, 1, chunkSize);

  return { recordType: RECORD_TYPE_DATA_V2, recordNumber, plaintextLength };
}

export function encodeFinalRecordHeaderV2(header: V2FinalRecordHeader): Uint8Array {
  if (header.recordType !== RECORD_TYPE_FINAL_V2) {
    throw new InvalidParamsError("recordType must identify a V2 FINAL record");
  }
  assertEncodeBigInt("dataRecordCount", header.dataRecordCount, MAX_DATA_RECORDS_V2);
  assertEncodeBigInt(
    "totalPlaintextLength",
    header.totalPlaintextLength,
    MAX_PLAINTEXT_LENGTH_V2
  );

  const bytes = new Uint8Array(V2_FINAL_RECORD_HEADER_LENGTH);
  const view = new DataView(bytes.buffer);
  bytes[0] = RECORD_TYPE_FINAL_V2;
  view.setBigUint64(1, header.dataRecordCount, false);
  view.setBigUint64(9, header.totalPlaintextLength, false);
  return bytes;
}

export function decodeFinalRecordHeaderV2(bytes: Uint8Array): V2FinalRecordHeader {
  assertExactDecodeLength("V2 FINAL record header", bytes, V2_FINAL_RECORD_HEADER_LENGTH);
  if (bytes[0] !== RECORD_TYPE_FINAL_V2) {
    throw new FormatError("Expected a V2 FINAL record");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const dataRecordCount = view.getBigUint64(1, false);
  const totalPlaintextLength = view.getBigUint64(9, false);
  if (dataRecordCount > MAX_DATA_RECORDS_V2) {
    throw new FormatError("V2 DATA record count exceeds the format limit");
  }
  if (totalPlaintextLength > MAX_PLAINTEXT_LENGTH_V2) {
    throw new FormatError("V2 plaintext length exceeds the format limit");
  }

  return {
    recordType: RECORD_TYPE_FINAL_V2,
    dataRecordCount,
    totalPlaintextLength,
  };
}
