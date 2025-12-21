import { Reader } from "./reader";
import { MAGIC, VERSION_V1 } from "./spec/constants";
import type { V1Decoded, V1Header, V1KdfParams } from "./spec/types";
import { Writer } from "./writer";

export function encodeV1(
  header: V1Header,
  kdf: V1KdfParams,
  wrappedDek: Uint8Array,
  ciphertext: Uint8Array,
  authTag: Uint8Array
): Uint8Array {
  if (header.nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }
  if (kdf.salt.length !== 16) {
    throw new Error("Salt must be 16 bytes");
  }
  if (wrappedDek.length !== 32) {
    throw new Error("Wrapped DEK must be 32 bytes");
  }
  if (authTag.length !== 16) {
    throw new Error("Auth tag must be 16 bytes");
  }

  const w = new Writer();

  w.writeBytes(MAGIC);
  w.writeU8(header.version);
  w.writeU8(header.cipherId);
  w.writeBytes(header.nonce);

  w.writeU8(kdf.kdfId);
  w.writeBytes(kdf.salt);
  w.writeU32BE(kdf.timeCost);
  w.writeU32BE(kdf.memoryCost);
  w.writeU8(kdf.parallelism);

  w.writeBytes(wrappedDek);
  w.writeBytes(ciphertext);
  w.writeBytes(authTag);

  return w.concat();
}

/* =========
 * Decode
 * ========= */

export function decodeV1(data: Uint8Array): V1Decoded {
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

  const wrappedDek = r.readBytes(32);

  const remaining = r.remaining();
  if (remaining.length < 16) {
    throw new Error("Invalid payload");
  }

  const ciphertext = remaining.slice(0, remaining.length - 16);
  const authTag = remaining.slice(remaining.length - 16);

  return {
    header: { version, cipherId, nonce },
    kdf: { kdfId, salt, timeCost, memoryCost, parallelism },
    wrappedDek,
    ciphertext,
    authTag
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
