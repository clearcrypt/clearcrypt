export const MAGIC_V2 = new TextEncoder().encode("CFENC002");
export const VERSION_V2 = 0x02;

export const CONTENT_CIPHER_AES_256_GCM_RECORDS_V2 = 0x01;
export const CONTENT_KEY_SCHEDULE_HKDF_SHA256_SEGMENTS_V2 = 0x01;
export const PASSWORD_KDF_ARGON2ID_V2 = 0x01;
export const ARCHIVE_KEY_WRAP_AES_256_GCM_V2 = 0x01;

export const RECORD_TYPE_DATA_V2 = 0x01;
export const RECORD_TYPE_FINAL_V2 = 0x02;

export const V2_HEADER_LENGTH = 122;
export const V2_WRAP_AAD_LENGTH = 74;
export const V2_DATA_RECORD_HEADER_LENGTH = 13;
export const V2_FINAL_RECORD_HEADER_LENGTH = 17;
export const V2_FINAL_RECORD_LENGTH = 33;

export const ARCHIVE_ID_LENGTH_V2 = 16;
export const CONTENT_NONCE_PREFIX_LENGTH_V2 = 4;
export const PASSWORD_SALT_LENGTH_V2 = 16;
export const WRAP_NONCE_LENGTH_V2 = 12;
export const ARCHIVE_MASTER_KEY_LENGTH_V2 = 32;
export const AUTH_TAG_LENGTH_V2 = 16;

export const MIN_CHUNK_SIZE_V2 = 1 << 16;
export const DEFAULT_CHUNK_SIZE_V2 = 1 << 22;
export const MAX_CHUNK_SIZE_V2 = 1 << 24;

export const MIN_TIME_COST_V2 = 1;
export const MAX_TIME_COST_V2 = 10;
export const MIN_MEMORY_COST_KIB_V2 = 8_192;
export const MAX_MEMORY_COST_KIB_V2 = 262_144;
export const MIN_PARALLELISM_V2 = 1;
export const MAX_PARALLELISM_V2 = 16;

export const SEGMENT_PLAINTEXT_SIZE_V2 = 1n << 30n;
export const MAX_DATA_INVOCATIONS_PER_SEGMENT_KEY_V2 = 1n << 14n;
export const MAX_PLAINTEXT_LENGTH_V2 = 1n << 50n;
export const MAX_SEGMENTS_V2 = 1n << 20n;
export const MAX_DATA_RECORDS_V2 = 1n << 34n;
export const U32_MAX = 0xffff_ffff;
export const U64_MAX = (1n << 64n) - 1n;

export const SEGMENT_KEY_INFO_LABEL_V2 = "ClearCrypt/CFENC002/segment-key";
export const FINAL_KEY_INFO_LABEL_V2 = "ClearCrypt/CFENC002/final-key";

export const V2_HEADER_OFFSETS = {
  magic: 0,
  version: 8,
  contentCipherId: 9,
  contentKeyScheduleId: 10,
  chunkSize: 11,
  archiveId: 15,
  contentNoncePrefix: 31,
  passwordKdfId: 35,
  passwordSalt: 36,
  timeCost: 52,
  memoryCostKiB: 56,
  parallelism: 60,
  archiveKeyWrapCipherId: 61,
  wrapNonce: 62,
  wrappedArchiveKeyCiphertext: 74,
  wrappedArchiveKeyTag: 106,
} as const;
