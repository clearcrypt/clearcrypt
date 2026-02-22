import { CIPHER_AES_256_GCM, KDF_ARGON2ID, VERSION_V1 } from "../src/v1/spec/constants";
import type { V1Header, V1KdfParams, V1Wrap } from "../src/v1/spec/types";

export function bytes(len: number, fn: (i: number) => number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = fn(i) & 0xff;
  return out;
}

export function makeHeader(overrides: Partial<V1Header> = {}): V1Header {
  return {
    version: VERSION_V1,
    cipherId: CIPHER_AES_256_GCM,
    nonce: bytes(12, (i) => i + 1),
    ...overrides,
  };
}

export function makeKdf(overrides: Partial<V1KdfParams> = {}): V1KdfParams {
  return {
    kdfId: KDF_ARGON2ID,
    salt: bytes(16, (i) => 0xa0 + i),
    timeCost: 2,
    memoryCost: 64 * 1024,
    parallelism: 2,
    ...overrides,
  };
}

export function makeWrap(overrides: Partial<V1Wrap> = {}): V1Wrap {
  return {
    wrapCipherId: CIPHER_AES_256_GCM,
    wrapNonce: bytes(12, (i) => 0x11 + i),
    wrappedDekCiphertext: bytes(32, (i) => 0x10 + i),
    wrapTag: bytes(16, (i) => 0xee - i),
    ...overrides,
  };
}
