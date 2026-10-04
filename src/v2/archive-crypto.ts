import {
  aeadDecryptAes256Gcm,
  aeadEncryptAes256Gcm,
  importAesGcmKey,
} from "../v1/aead";
import { getWebCrypto } from "../v1/crypto-runtime";
import { CryptoOperationError, InvalidParamsError } from "../v1/errors";
import { buildDataNonceV2 } from "./data-record-crypto";
import {
  decodeHeaderV2,
  decodeFinalRecordHeaderV2,
  encodeFinalRecordHeaderV2,
  encodeHeaderV2,
} from "./spec/codec";
import {
  ARCHIVE_MASTER_KEY_LENGTH_V2,
  AUTH_TAG_LENGTH_V2,
  FINAL_KEY_INFO_LABEL_V2,
  MAX_DATA_RECORDS_V2,
  MAX_PLAINTEXT_LENGTH_V2,
  RECORD_TYPE_FINAL_V2,
  V2_WRAP_AAD_LENGTH,
} from "./spec/constants";
import type { V2FinalRecordHeader, V2Header } from "./spec/types";

const FINAL_KEY_INFO_BYTES_V2 = new TextEncoder().encode(FINAL_KEY_INFO_LABEL_V2);

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

export type V2HeaderWithoutWrappedKey = Omit<
  V2Header,
  "wrappedArchiveKeyCiphertext" | "wrappedArchiveKeyTag"
>;

export async function createWrappedHeaderV2(params: {
  fields: V2HeaderWithoutWrappedKey;
  archiveMasterKey: Uint8Array;
  kekRaw32: Uint8Array;
}): Promise<V2Header> {
  const { fields, archiveMasterKey, kekRaw32 } = params;
  if (
    !(archiveMasterKey instanceof Uint8Array) ||
    archiveMasterKey.length !== ARCHIVE_MASTER_KEY_LENGTH_V2
  ) {
    throw new InvalidParamsError(
      `V2 archive master key must be ${ARCHIVE_MASTER_KEY_LENGTH_V2} bytes`
    );
  }

  const placeholder: V2Header = {
    ...fields,
    wrappedArchiveKeyCiphertext: new Uint8Array(ARCHIVE_MASTER_KEY_LENGTH_V2),
    wrappedArchiveKeyTag: new Uint8Array(AUTH_TAG_LENGTH_V2),
  };
  const wrapAad = encodeHeaderV2(placeholder).slice(0, V2_WRAP_AAD_LENGTH);
  const key = await importAesGcmKey(kekRaw32);
  const wrapped = await aeadEncryptAes256Gcm({
    key,
    nonce: fields.wrapNonce,
    plaintext: archiveMasterKey,
    associatedAuthenticatedData: wrapAad,
  });
  if (
    wrapped.ciphertext.length !== ARCHIVE_MASTER_KEY_LENGTH_V2 ||
    wrapped.tag.length !== AUTH_TAG_LENGTH_V2
  ) {
    throw new CryptoOperationError("Invalid V2 wrapped archive key length");
  }

  return {
    ...fields,
    wrappedArchiveKeyCiphertext: wrapped.ciphertext,
    wrappedArchiveKeyTag: wrapped.tag,
  };
}

export async function unwrapArchiveMasterKeyV2(params: {
  archiveAad: Uint8Array;
  kekRaw32: Uint8Array;
}): Promise<Uint8Array> {
  const { archiveAad, kekRaw32 } = params;
  const header = decodeHeaderV2(archiveAad);
  const key = await importAesGcmKey(kekRaw32);
  const archiveMasterKey = await aeadDecryptAes256Gcm({
    key,
    nonce: header.wrapNonce,
    ciphertext: header.wrappedArchiveKeyCiphertext,
    tag: header.wrappedArchiveKeyTag,
    associatedAuthenticatedData: archiveAad.subarray(0, V2_WRAP_AAD_LENGTH),
  });
  if (archiveMasterKey.length !== ARCHIVE_MASTER_KEY_LENGTH_V2) {
    throw new CryptoOperationError("Invalid V2 unwrapped archive key length");
  }
  return archiveMasterKey;
}

export async function deriveFinalKeyV2(params: {
  archiveMasterKey: Uint8Array;
  archiveId: Uint8Array;
}): Promise<CryptoKey> {
  const { archiveMasterKey, archiveId } = params;
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
        info: toWebCryptoBytes(FINAL_KEY_INFO_BYTES_V2),
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } catch (cause) {
    throw new CryptoOperationError("Unable to derive V2 FINAL key", cause);
  }
}

export async function authenticateFinalRecordV2(params: {
  archiveAad: Uint8Array;
  archiveMasterKey: Uint8Array;
  dataRecordCount: bigint;
  totalPlaintextLength: bigint;
}): Promise<{ header: V2FinalRecordHeader; headerBytes: Uint8Array; tag: Uint8Array }> {
  const {
    archiveAad,
    archiveMasterKey,
    dataRecordCount,
    totalPlaintextLength,
  } = params;
  if (dataRecordCount < 0n || dataRecordCount > MAX_DATA_RECORDS_V2) {
    throw new InvalidParamsError("V2 FINAL record count is outside its supported range");
  }
  if (totalPlaintextLength < 0n || totalPlaintextLength > MAX_PLAINTEXT_LENGTH_V2) {
    throw new InvalidParamsError("V2 FINAL plaintext length is outside its supported range");
  }

  const archiveHeader = decodeHeaderV2(archiveAad);
  const header: V2FinalRecordHeader = {
    recordType: RECORD_TYPE_FINAL_V2,
    dataRecordCount,
    totalPlaintextLength,
  };
  const headerBytes = encodeFinalRecordHeaderV2(header);
  const aad = concatBytes(archiveAad, headerBytes);
  const nonce = buildDataNonceV2(archiveHeader.contentNoncePrefix, 0n);
  const key = await deriveFinalKeyV2({
    archiveMasterKey,
    archiveId: archiveHeader.archiveId,
  });
  const result = await aeadEncryptAes256Gcm({
    key,
    nonce,
    plaintext: new Uint8Array(0),
    associatedAuthenticatedData: aad,
  });
  if (result.ciphertext.length !== 0 || result.tag.length !== AUTH_TAG_LENGTH_V2) {
    throw new CryptoOperationError("Invalid V2 FINAL authentication output");
  }
  return { header, headerBytes, tag: result.tag };
}

export async function verifyFinalRecordV2(params: {
  archiveAad: Uint8Array;
  archiveMasterKey: Uint8Array;
  headerBytes: Uint8Array;
  tag: Uint8Array;
}): Promise<void> {
  const { archiveAad, archiveMasterKey, headerBytes, tag } = params;
  const archiveHeader = decodeHeaderV2(archiveAad);
  decodeFinalRecordHeaderV2(headerBytes);
  if (!(tag instanceof Uint8Array) || tag.length !== AUTH_TAG_LENGTH_V2) {
    throw new InvalidParamsError(
      `V2 FINAL tag must be exactly ${AUTH_TAG_LENGTH_V2} bytes`
    );
  }
  const key = await deriveFinalKeyV2({
    archiveMasterKey,
    archiveId: archiveHeader.archiveId,
  });
  const plaintext = await aeadDecryptAes256Gcm({
    key,
    nonce: buildDataNonceV2(archiveHeader.contentNoncePrefix, 0n),
    ciphertext: new Uint8Array(0),
    tag,
    associatedAuthenticatedData: concatBytes(archiveAad, headerBytes),
  });
  if (plaintext.length !== 0) {
    throw new CryptoOperationError("Invalid V2 FINAL authentication plaintext");
  }
}
