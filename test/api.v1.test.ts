import { describe, expect, it } from "vitest";
import { ClearcryptError, decryptBytesV1, encryptBytesV1 } from "../src/index";
import { decodeV1 } from "../src/v1/format";
import { bytes } from "./helpers";

describe("V1 public API", () => {
  it("encrypts then decrypts bytes with a password", async () => {
    const plaintext = bytes(48, (i) => 0xaa ^ i);
    const password = "password-123";

    const encrypted = await encryptBytesV1(plaintext, password, {
      nonce: bytes(12, (i) => 0x10 + i),
      salt: bytes(16, (i) => 0x20 + i),
      wrapNonce: bytes(12, (i) => 0x30 + i),
      kdf: { timeCost: 1, memoryCost: 8 * 1024, parallelism: 1 },
    });

    const decrypted = await decryptBytesV1(encrypted, password);

    expect([...decrypted]).toEqual([...plaintext]);
  });

  it("writes header and kdf fields from options", async () => {
    const plaintext = bytes(16, (i) => i);
    const password = "pw";
    const nonce = bytes(12, (i) => 0x41 + i);
    const salt = bytes(16, (i) => 0x51 + i);
    const wrapNonce = bytes(12, (i) => 0x61 + i);

    const encrypted = await encryptBytesV1(plaintext, password, {
      nonce,
      salt,
      wrapNonce,
      kdf: { timeCost: 2, memoryCost: 16 * 1024, parallelism: 2 },
    });

    const decoded = decodeV1(encrypted);

    expect([...decoded.header.nonce]).toEqual([...nonce]);
    expect([...decoded.kdf.salt]).toEqual([...salt]);
    expect(decoded.kdf.timeCost).toBe(2);
    expect(decoded.kdf.memoryCost).toBe(16 * 1024);
    expect(decoded.kdf.parallelism).toBe(2);
    expect([...decoded.wrappedDek.wrapNonce]).toEqual([...wrapNonce]);
  });

  it("fails with wrong password", async () => {
    const plaintext = bytes(24, (i) => 0x5a ^ i);

    const encrypted = await encryptBytesV1(plaintext, "correct", {
      nonce: bytes(12, (i) => 0x10 + i),
      salt: bytes(16, (i) => 0x20 + i),
      wrapNonce: bytes(12, (i) => 0x30 + i),
      kdf: { timeCost: 1, memoryCost: 8 * 1024, parallelism: 1 },
    });

    await expect(decryptBytesV1(encrypted, "wrong")).rejects.toThrow();
  });

  it("returns AUTH_FAILED when data is tampered", async () => {
    const plaintext = bytes(32, (i) => 0x3c ^ i);
    const encrypted = await encryptBytesV1(plaintext, "secret", {
      nonce: bytes(12, (i) => 0x10 + i),
      salt: bytes(16, (i) => 0x20 + i),
      wrapNonce: bytes(12, (i) => 0x30 + i),
      kdf: { timeCost: 1, memoryCost: 8 * 1024, parallelism: 1 },
    });

    const tampered = encrypted.slice();
    tampered[25] = (tampered[25]! ^ 0xff) & 0xff;

    let err: unknown;
    try {
      await decryptBytesV1(tampered, "secret");
    } catch (e) {
      err = e;
    }

    expect(err).toBeInstanceOf(ClearcryptError);
    expect((err as ClearcryptError).code).toBe("AUTH_FAILED");
  });
});
