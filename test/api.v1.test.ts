import { describe, expect, it } from "vitest";
import {
  ClearcryptError,
  decryptBytesV1,
  encryptBytesV1,
} from "../src/index";
import type { V1EncryptOptions } from "../src/index";
import { decodeV1 } from "../src/v1/format";
import { bytes } from "./helpers";

const FAST_KDF = {
  timeCost: 1,
  memoryCost: 8 * 1024,
  parallelism: 1,
};

describe("V1 public API", () => {
  it("encrypts then decrypts bytes with a password", async () => {
    const plaintext = bytes(48, (i) => 0xaa ^ i);
    const password = "password-123";

    const encrypted = await encryptBytesV1(plaintext, password, { kdf: FAST_KDF });
    const decrypted = await decryptBytesV1(encrypted, password);

    expect([...decrypted]).toEqual([...plaintext]);
  });

  it("writes the selected public KDF settings", async () => {
    const encrypted = await encryptBytesV1(bytes(16, (i) => i), "pw", {
      kdfProfile: "interactive",
      kdf: { timeCost: 2, memoryCost: 16 * 1024, parallelism: 2 },
    });
    const decoded = decodeV1(encrypted);

    expect(decoded.kdf.kdfId).toBe(1);
    expect(decoded.kdf.timeCost).toBe(2);
    expect(decoded.kdf.memoryCost).toBe(16 * 1024);
    expect(decoded.kdf.parallelism).toBe(2);
    expect(decoded.header.nonce).toHaveLength(12);
    expect(decoded.kdf.salt).toHaveLength(16);
    expect(decoded.wrappedDek.wrapNonce).toHaveLength(12);
  });

  it("generates fresh salt and nonces for every encryption", async () => {
    const plaintext = bytes(24, (i) => i);
    const options = { kdf: FAST_KDF };

    const first = await encryptBytesV1(plaintext, "same-password", options);
    const second = await encryptBytesV1(plaintext, "same-password", options);
    const firstDecoded = decodeV1(first);
    const secondDecoded = decodeV1(second);

    expect(first).not.toEqual(second);
    expect(firstDecoded.kdf.salt).not.toEqual(secondDecoded.kdf.salt);
    expect(firstDecoded.header.nonce).not.toEqual(secondDecoded.header.nonce);
    expect(firstDecoded.wrappedDek.wrapNonce).not.toEqual(
      secondDecoded.wrappedDek.wrapNonce
    );
  });

  it("ignores removed random-value overrides supplied by untyped JavaScript", async () => {
    const removedOptions = {
      nonce: new Uint8Array(12),
      salt: new Uint8Array(16),
      wrapNonce: new Uint8Array(12),
      kdf: FAST_KDF,
    } as unknown as V1EncryptOptions;

    const first = decodeV1(await encryptBytesV1(new Uint8Array(), "pw", removedOptions));
    const second = decodeV1(await encryptBytesV1(new Uint8Array(), "pw", removedOptions));

    expect(first.kdf.salt).not.toEqual(second.kdf.salt);
    expect(first.header.nonce).not.toEqual(second.header.nonce);
    expect(first.wrappedDek.wrapNonce).not.toEqual(second.wrappedDek.wrapNonce);
  });

  it("fails with wrong password", async () => {
    const encrypted = await encryptBytesV1(bytes(24, (i) => 0x5a ^ i), "correct", {
      kdf: FAST_KDF,
    });

    await expect(decryptBytesV1(encrypted, "wrong")).rejects.toThrow();
  });

  it("returns AUTH_FAILED when data is tampered", async () => {
    const encrypted = await encryptBytesV1(bytes(32, (i) => 0x3c ^ i), "secret", {
      kdf: FAST_KDF,
    });
    const tampered = encrypted.slice();
    tampered[25] = (tampered[25]! ^ 0xff) & 0xff;

    let err: unknown;
    try {
      await decryptBytesV1(tampered, "secret");
    } catch (caught) {
      err = caught;
    }

    expect(err).toBeInstanceOf(ClearcryptError);
    expect((err as ClearcryptError).code).toBe("AUTH_FAILED");
  });

  it("returns INVALID_PARAMS for an unknown KDF profile at runtime", async () => {
    let err: unknown;
    try {
      await encryptBytesV1(new Uint8Array(), "secret", {
        kdfProfile: "future-profile",
        kdf: FAST_KDF,
      } as unknown as V1EncryptOptions);
    } catch (caught) {
      err = caught;
    }

    expect(err).toBeInstanceOf(ClearcryptError);
    expect((err as ClearcryptError).code).toBe("INVALID_PARAMS");
  });
});
