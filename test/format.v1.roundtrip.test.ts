import { describe, expect, it } from "vitest";

// Adapte l'import selon ton organisation actuelle :
// - si tu as encore tout dans src/v1/format.ts : garde ceci
import { decodeV1, encodeV1 } from "../src/v1/format";
import { CIPHER_AES_256_GCM, KDF_ARGON2ID, VERSION_V1 } from "../src/v1/spec/constants";

// Si tu as refactoré constants.ts/types.ts, alors tu importeras plutôt :
// import { VERSION_V1, CIPHER_AES_256_GCM, KDF_ARGON2ID } from "../src/v1/constants";
// import { encodeV1, decodeV1 } from "../src/v1/format";

function bytes(len: number, fn: (i: number) => number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = fn(i) & 0xff;
  return out;
}

describe("V1 format", () => {
  it("encodes then decodes the same fields", () => {
    const header = {
      version: VERSION_V1,
      cipherId: CIPHER_AES_256_GCM,
      nonce: bytes(12, (i) => i + 1),
    };

    const kdf = {
      kdfId: KDF_ARGON2ID,
      salt: bytes(16, (i) => 0xa0 + i),
      timeCost: 2,
      memoryCost: 64 * 1024,
      parallelism: 2,
    };

    const wrappedDek = bytes(32, (i) => 0x10 + i);
    const ciphertext = bytes(50, (i) => 0x55 ^ i);
    const authTag = bytes(16, (i) => 0xee - i);

    const encoded = encodeV1(header, kdf, wrappedDek, ciphertext, authTag);
    const decoded = decodeV1(encoded);

    expect(decoded.header.version).toBe(header.version);
    expect(decoded.header.cipherId).toBe(header.cipherId);
    expect([...decoded.header.nonce]).toEqual([...header.nonce]);

    expect(decoded.kdf.kdfId).toBe(kdf.kdfId);
    expect([...decoded.kdf.salt]).toEqual([...kdf.salt]);
    expect(decoded.kdf.timeCost).toBe(kdf.timeCost);
    expect(decoded.kdf.memoryCost).toBe(kdf.memoryCost);
    expect(decoded.kdf.parallelism).toBe(kdf.parallelism);

    expect([...decoded.wrappedDek]).toEqual([...wrappedDek]);
    expect([...decoded.ciphertext]).toEqual([...ciphertext]);
    expect([...decoded.authTag]).toEqual([...authTag]);
  });

  it("rejects invalid magic/version", () => {
    const header = {
      version: VERSION_V1,
      cipherId: CIPHER_AES_256_GCM,
      nonce: new Uint8Array(12),
    };
    const kdf = {
      kdfId: KDF_ARGON2ID,
      salt: new Uint8Array(16),
      timeCost: 2,
      memoryCost: 64 * 1024,
      parallelism: 2,
    };

    const wrappedDek = new Uint8Array(32);
    const ciphertext = new Uint8Array([1, 2, 3]);
    const authTag = new Uint8Array(16);

    const encoded = encodeV1(header, kdf, wrappedDek, ciphertext, authTag);


    const corruptedMagic = encoded.slice();
    corruptedMagic[0] = corruptedMagic[0]! ^ 0xff;
    expect(() => decodeV1(corruptedMagic)).toThrow(/magic/i);


    const corruptedVersion = encoded.slice();
    corruptedVersion[8] = 0xff;
    expect(() => decodeV1(corruptedVersion)).toThrow(/version/i);
  });

  it("rejects payload shorter than auth tag", () => {

    const header = {
      version: VERSION_V1,
      cipherId: CIPHER_AES_256_GCM,
      nonce: new Uint8Array(12),
    };
    const kdf = {
      kdfId: KDF_ARGON2ID,
      salt: new Uint8Array(16),
      timeCost: 2,
      memoryCost: 64 * 1024,
      parallelism: 2,
    };
    const wrappedDek = new Uint8Array(32);

    const encoded = encodeV1(header, kdf, wrappedDek, new Uint8Array(0), new Uint8Array(16));

    const truncated = encoded.slice(0, encoded.length - 10);
    expect(() => decodeV1(truncated)).toThrow(/payload/i);
  });
});
