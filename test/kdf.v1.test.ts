import { describe, expect, it } from "vitest";
import { deriveKekArgon2id } from "../src/v1/kdf";
import { bytes } from "./helpers";

describe("V1 KDF (Argon2id)", () => {
  it("derives a 32-byte key deterministically", async () => {
    const params = {
      password: "correct-horse-battery-staple",
      salt: bytes(16, (i) => 0x10 + i),
      timeCost: 1,
      memoryCost: 8 * 1024,
      parallelism: 1,
    };

    const k1 = await deriveKekArgon2id(params);
    const k2 = await deriveKekArgon2id(params);

    expect(k1.length).toBe(32);
    expect([...k1]).toEqual([...k2]);
  });

  it("changes when salt changes", async () => {
    const base = {
      password: "pass-123",
      timeCost: 1,
      memoryCost: 8 * 1024,
      parallelism: 1,
    };

    const k1 = await deriveKekArgon2id({
      ...base,
      salt: bytes(16, (i) => 0x20 + i),
    });
    const k2 = await deriveKekArgon2id({
      ...base,
      salt: bytes(16, (i) => 0x21 + i),
    });

    expect([...k1]).not.toEqual([...k2]);
  });

  it("rejects invalid salt length", async () => {
    await expect(
      deriveKekArgon2id({
        password: "password",
        salt: bytes(15, (i) => i),
        timeCost: 1,
        memoryCost: 8 * 1024,
        parallelism: 1,
      })
    ).rejects.toThrow(/salt/i);
  });

  it("rejects invalid KDF cost ranges", async () => {
    await expect(
      deriveKekArgon2id({
        password: "password",
        salt: bytes(16, (i) => i),
        timeCost: 0,
        memoryCost: 8 * 1024,
        parallelism: 1,
      })
    ).rejects.toThrow(/timeCost/i);

    await expect(
      deriveKekArgon2id({
        password: "password",
        salt: bytes(16, (i) => i),
        timeCost: 1,
        memoryCost: 7 * 1024,
        parallelism: 1,
      })
    ).rejects.toThrow(/memoryCost/i);

    await expect(
      deriveKekArgon2id({
        password: "password",
        salt: bytes(16, (i) => i),
        timeCost: 1,
        memoryCost: 8 * 1024,
        parallelism: 0,
      })
    ).rejects.toThrow(/parallelism/i);
  });
});
