import {
  aeadDecryptAes256Gcm,
  aeadEncryptAes256Gcm,
  importAesGcmKey
} from "./aead";
import { deriveKekArgon2id } from "./kdf";
import { Reader } from "./reader";
import { CIPHER_AES_256_GCM, KDF_ARGON2ID, MAGIC, VERSION_V1 } from "./spec/constants";
import type { DecodedEnvelopeV1, V1Decoded, V1Header, V1KdfParams, V1Wrap } from "./spec/types";
import { unwrapDekWithKek, wrapDekWithKek } from "./wrap";
import { Writer } from "./writer";
import { enforceDecryptResourcePolicy } from "./resource-policy";
import type { DecryptResourcePolicy } from "./resource-policy";
import { secureRandomBytes } from "./crypto-runtime";
import {
  FormatError,
  InvalidParamsError,
  UnsupportedAlgorithmError,
  UnsupportedFormatError,
} from "./errors";

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
    throw new InvalidParamsError("Nonce must be 12 bytes");
  }
  if (kdf.salt.length !== 16) {
    throw new InvalidParamsError("Salt must be 16 bytes");
  }
  if (wrappedDek.wrapNonce.length !== 12) {
    throw new InvalidParamsError("Wrapped DEK nonce must be 12 bytes");
  }
  if (wrappedDek.wrappedDekCiphertext.length !== 32) {
    throw new InvalidParamsError("Wrapped DEK must be 32 bytes");
  }
  if (wrappedDek.wrapTag.length !== 16) {
    throw new InvalidParamsError("Wrapped DEK tag must be 16 bytes");
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
    throw new InvalidParamsError("Auth tag must be 16 bytes");
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

export function decodeEnvelopeV1(data: Uint8Array): DecodedEnvelopeV1 {
  const r = new Reader(data);

  const magic = r.readBytes(8);
  if (!equalBytes(magic, MAGIC)) {
    throw new FormatError("Invalid magic header");
  }

  const version = r.readU8();
  if (version !== VERSION_V1) {
    throw new UnsupportedFormatError(`Unsupported version: ${version}`);
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

  const aad = data.subarray(0, r.position);
  if (r.remainingLength() < 16) {
    throw new FormatError("Invalid payload");
  }
  const payload = r.remainingView();
  const ciphertext = payload.subarray(0, payload.length - 16);
  const tag = payload.subarray(payload.length - 16);

  return {
    header: { version, cipherId, nonce },
    kdf: { kdfId, salt, timeCost, memoryCost, parallelism },
    wrap: wrappedDek,
    aad,
    ciphertext,
    tag,
  };
}

export function decodeV1(data: Uint8Array): V1Decoded {
  const envelope = decodeEnvelopeV1(data);

  return {
    header: envelope.header,
    kdf: envelope.kdf,
    wrappedDek: envelope.wrap,
    ciphertext: envelope.ciphertext,
    authTag: envelope.tag,
  };
}

async function decryptEnvelopeV1WithDek(
  envelope: DecodedEnvelopeV1,
  dek: Uint8Array
): Promise<Uint8Array> {
  const key = await importAesGcmKey(dek);
  return aeadDecryptAes256Gcm({
    key,
    nonce: envelope.header.nonce,
    ciphertext: envelope.ciphertext,
    tag: envelope.tag,
    associatedAuthenticatedData: envelope.aad,
  });
}

function assertSupportedEnvelopeV1(envelope: DecodedEnvelopeV1): void {
  if (envelope.header.cipherId !== CIPHER_AES_256_GCM) {
    throw new UnsupportedAlgorithmError("Unsupported cipher for V1 decryption");
  }
  if (envelope.kdf.kdfId !== KDF_ARGON2ID) {
    throw new UnsupportedAlgorithmError("Unsupported KDF for V1 decryption");
  }
  if (envelope.wrap.wrapCipherId !== CIPHER_AES_256_GCM) {
    throw new UnsupportedAlgorithmError("Unsupported wrap cipher for V1 decryption");
  }
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

  const envelope = decodeEnvelopeV1(data);
  const { header, kdf, wrap: wrappedDek } = envelope;
  assertSupportedEnvelopeV1(envelope);

  const plaintext = await decryptEnvelopeV1WithDek(envelope, dek);

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

  const dek = secureRandomBytes(32);
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

  const envelope = decodeEnvelopeV1(data);
  assertSupportedEnvelopeV1(envelope);
  const dek = await unwrapDekWithKek({ wrap: envelope.wrap, kekRaw32 });

  const plaintext = await decryptEnvelopeV1WithDek(envelope, dek);
  return {
    plaintext,
    header: envelope.header,
    kdf: envelope.kdf,
    wrappedDek: envelope.wrap,
  };
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
    throw new InvalidParamsError("Unsupported KDF for V1 encryption");
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

  const envelope = decodeEnvelopeV1(data);
  assertSupportedEnvelopeV1(envelope);
  enforceDecryptResourcePolicy(envelope.kdf, resourcePolicy);

  const kekRaw32 = await deriveKekArgon2id({
    password,
    salt: envelope.kdf.salt,
    timeCost: envelope.kdf.timeCost,
    memoryCost: envelope.kdf.memoryCost,
    parallelism: envelope.kdf.parallelism,
  });

  const dek = await unwrapDekWithKek({ wrap: envelope.wrap, kekRaw32 });
  const plaintext = await decryptEnvelopeV1WithDek(envelope, dek);
  return {
    plaintext,
    header: envelope.header,
    kdf: envelope.kdf,
    wrappedDek: envelope.wrap,
  };
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

