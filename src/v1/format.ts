import {
  aeadDecryptAes256Gcm,
  aeadEncryptAes256Gcm,
  importAesGcmKey
} from "./aead";
import { deriveKekArgon2id } from "./kdf";
import { Reader } from "./reader";
import { CIPHER_AES_256_GCM, KDF_ARGON2ID, MAGIC, VERSION_V1 } from "./spec/constants";
import type { V1Decoded, V1Header, V1KdfParams, V1Metadata, V1Wrap } from "./spec/types";
import { unwrapDekWithKek, wrapDekWithKek } from "./wrap";
import { Writer } from "./writer";
import { enforceDecryptResourcePolicy } from "./resource-policy";
import type { DecryptResourcePolicy } from "./resource-policy";

/* =========
 * Encode
 * ========= */

export function encodeAadV1(
  header: V1Header,
  kdf: V1KdfParams,
  wrappedDek: V1Wrap,
  w: Writer
): number {
  if (header.nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }
  if (kdf.salt.length !== 16) {
    throw new Error("Salt must be 16 bytes");
  }
  if (wrappedDek.wrapNonce.length !== 12) {
    throw new Error("Wrapped DEK nonce must be 12 bytes");
  }
  if (wrappedDek.wrappedDekCiphertext.length !== 32) {
    throw new Error("Wrapped DEK must be 32 bytes");
  }
  if (wrappedDek.wrapTag.length !== 16) {
    throw new Error("Wrapped DEK tag must be 16 bytes");
  }

  // --- AAD bytes ---
  w.writeBytes(MAGIC);
  w.writeU8(header.version);
  w.writeU8(header.cipherId);
  w.writeBytes(header.nonce);

  w.writeU8(kdf.kdfId);
  w.writeBytes(kdf.salt);
  w.writeU32BE(kdf.timeCost);
  w.writeU32BE(kdf.memoryCost);
  w.writeU8(kdf.parallelism);

  w.writeU8(wrappedDek.wrapCipherId);
  w.writeBytes(wrappedDek.wrapNonce);
  w.writeBytes(wrappedDek.wrappedDekCiphertext);
  w.writeBytes(wrappedDek.wrapTag);

  const aadLength = w.length;

  return aadLength;
}

export function encodeV1(
  header: V1Header,
  kdf: V1KdfParams,
  wrappedDek: V1Wrap,
  ciphertext: Uint8Array,
  authTag: Uint8Array
): { bytes: Uint8Array; aadLength: number } {
  if (authTag.length !== 16) {
    throw new Error("Auth tag must be 16 bytes");
  }
  const w = new Writer();
  const aadLength = encodeAadV1(header, kdf, wrappedDek, w);

  // --- Encrypted payload ---
  w.writeBytes(ciphertext);
  w.writeBytes(authTag);

  return {
    bytes: w.concat(),
    aadLength
  };
}

export async function encryptV1WithDek(params: {
  header: V1Header;
  kdf: V1KdfParams;
  wrappedDek: V1Wrap;
  dek: Uint8Array;
  plaintext: Uint8Array;
}): Promise<{ bytes: Uint8Array; aadLength: number }> {

  const { header, kdf, wrappedDek, dek, plaintext } = params;
  const key = await importAesGcmKey(dek);
  const w = new Writer();
  const aadLength = encodeAadV1(header, kdf, wrappedDek, w);
  const aad = w.concat();
  const { ciphertext, tag } = await aeadEncryptAes256Gcm({
    key,
    nonce: header.nonce,
    plaintext,
    associatedAuthenticatedData: aad,
  });

  w.writeBytes(ciphertext);
  w.writeBytes(tag)

  return { bytes: w.concat(), aadLength };
}

/* =========
 * Decode
 * ========= */

function readV1Metadata(data: Uint8Array): { metadata: V1Metadata; reader: Reader } {
  const r = new Reader(data);

  const magic = r.readBytes(8);
  if (!equalBytes(magic, MAGIC)) {
    throw new Error("Invalid magic header");
  }

  const version = r.readU8();
  if (version !== VERSION_V1) {
    throw new Error(`Unsupported version: ${version}`);
  }

  const cipherId = r.readU8();
  const nonce = r.readBytes(12);

  const kdfId = r.readU8();
  const salt = r.readBytes(16);
  const timeCost = r.readU32BE();
  const memoryCost = r.readU32BE();
  const parallelism = r.readU8();

  const wrapCipherId = r.readU8();
  const wrapNonce = r.readBytes(12)
  const wrappedDekCiphertext = r.readBytes(32);
  const wrapTag = r.readBytes(16);

  const wrappedDek : V1Wrap = { wrapCipherId, wrapNonce, wrappedDekCiphertext, wrapTag };

  if (r.remainingLength() < 16) {
    throw new Error("Invalid payload");
  }

  return {
    metadata: {
      header: { version, cipherId, nonce },
      kdf: { kdfId, salt, timeCost, memoryCost, parallelism },
      wrappedDek,
    },
    reader: r,
  };
}

export function decodeV1Metadata(data: Uint8Array): V1Metadata {
  return readV1Metadata(data).metadata;
}

export function decodeV1(data: Uint8Array): V1Decoded {
  const { metadata, reader } = readV1Metadata(data);
  const { header, kdf, wrappedDek } = metadata;

  const remaining = reader.remaining();

  const ciphertext = remaining.slice(0, remaining.length - 16);
  const authTag = remaining.slice(remaining.length - 16);

  return {
    header,
    kdf,
    wrappedDek,
    ciphertext,
    authTag
  };
}

export async function decryptV1WithDek(params: {
  data: Uint8Array;
  dek: Uint8Array;
}): Promise<{
  plaintext: Uint8Array;
  header: V1Header;
  kdf: V1KdfParams;
  wrappedDek: V1Wrap;
}> {
  const { data, dek } = params;

  const decoded = decodeV1(data);
  const { header, kdf, wrappedDek, ciphertext, authTag } = decoded;

  if (header.version !== VERSION_V1) {
    throw new Error("Unsupported version for V1 decryption");
  }
  if (header.cipherId !== CIPHER_AES_256_GCM) {
    throw new Error("Unsupported cipher for V1 decryption");
  }

  const w = new Writer();
  encodeAadV1(header, kdf, wrappedDek, w);
  const aad = w.concat();

  const key = await importAesGcmKey(dek);
  const plaintext = await aeadDecryptAes256Gcm({
    key,
    nonce: header.nonce,
    ciphertext,
    tag: authTag,
    associatedAuthenticatedData: aad,
  });

  return { plaintext, header, kdf, wrappedDek };
}

export async function encryptV1WithKek(params: {
  header: V1Header;
  kdf: V1KdfParams;
  kekRaw32: Uint8Array;
  wrapNonce: Uint8Array;
  plaintext: Uint8Array;
}): Promise<{ bytes: Uint8Array; aadLength: number }> {
  const { header, kdf, kekRaw32, wrapNonce, plaintext } = params;

  const dek = crypto.getRandomValues(new Uint8Array(32));
  const wrappedDek = await wrapDekWithKek({ dek, kekRaw32, wrapNonce });

  return encryptV1WithDek({
    header,
    kdf,
    wrappedDek,
    dek,
    plaintext,
  });
}

export async function decryptV1WithKek(params: {
  data: Uint8Array;
  kekRaw32: Uint8Array;
}): Promise<{
  plaintext: Uint8Array;
  header: V1Header;
  kdf: V1KdfParams;
  wrappedDek: V1Wrap;
}> {
  const { data, kekRaw32 } = params;

  const decoded = decodeV1(data);
  const dek = await unwrapDekWithKek({ wrap: decoded.wrappedDek, kekRaw32 });

  return decryptV1WithDek({ data, dek });
}

export async function encryptV1WithPassword(params: {
  header: V1Header;
  kdf: V1KdfParams;
  password: Uint8Array | string;
  wrapNonce: Uint8Array;
  plaintext: Uint8Array;
}): Promise<{ bytes: Uint8Array; aadLength: number }> {
  const { header, kdf, password, wrapNonce, plaintext } = params;
  if (kdf.kdfId !== KDF_ARGON2ID) {
    throw new Error("Unsupported KDF for V1 encryption");
  }

  const kekRaw32 = await deriveKekArgon2id({
    password,
    salt: kdf.salt,
    timeCost: kdf.timeCost,
    memoryCost: kdf.memoryCost,
    parallelism: kdf.parallelism,
  });

  return encryptV1WithKek({
    header,
    kdf,
    kekRaw32,
    wrapNonce,
    plaintext,
  });
}

export async function decryptV1WithPassword(params: {
  data: Uint8Array;
  password: Uint8Array | string;
  resourcePolicy?: Partial<DecryptResourcePolicy>;
}): Promise<{
  plaintext: Uint8Array;
  header: V1Header;
  kdf: V1KdfParams;
  wrappedDek: V1Wrap;
}> {
  const { data, password, resourcePolicy } = params;

  const metadata = decodeV1Metadata(data);
  if (metadata.header.cipherId !== CIPHER_AES_256_GCM) {
    throw new Error("Unsupported cipher for V1 decryption");
  }
  if (metadata.kdf.kdfId !== KDF_ARGON2ID) {
    throw new Error("Unsupported KDF for V1 decryption");
  }
  if (metadata.wrappedDek.wrapCipherId !== CIPHER_AES_256_GCM) {
    throw new Error("Unsupported wrap cipher for V1 decryption");
  }
  enforceDecryptResourcePolicy(metadata.kdf, resourcePolicy);

  const kekRaw32 = await deriveKekArgon2id({
    password,
    salt: metadata.kdf.salt,
    timeCost: metadata.kdf.timeCost,
    memoryCost: metadata.kdf.memoryCost,
    parallelism: metadata.kdf.parallelism,
  });

  const dek = await unwrapDekWithKek({ wrap: metadata.wrappedDek, kekRaw32 });
  return decryptV1WithDek({ data, dek });
}



/* =========
 * Utils
 * ========= */

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

