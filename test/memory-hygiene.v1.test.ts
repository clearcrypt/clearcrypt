import { beforeEach, describe, expect, it, vi } from "vitest";

import { bytes, makeHeader, makeKdf, makeWrap } from "./helpers";

const controlled = vi.hoisted(() => ({
  generatedDek: undefined as Uint8Array | undefined,
  derivedKek: undefined as Uint8Array | undefined,
  unwrappedDek: undefined as Uint8Array | undefined,
}));

vi.mock("../src/v1/crypto-runtime", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/v1/crypto-runtime")>();
  return {
    ...actual,
    secureRandomBytes: vi.fn((length: number) => {
      if (length !== 32 || !controlled.generatedDek) {
        throw new Error("Unexpected random-byte request");
      }
      return controlled.generatedDek;
    }),
  };
});

vi.mock("../src/v1/kdf", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/v1/kdf")>();
  return {
    ...actual,
    deriveKekArgon2id: vi.fn(async () => {
      if (!controlled.derivedKek) {
        throw new Error("Missing test KEK");
      }
      return controlled.derivedKek;
    }),
  };
});

vi.mock("../src/v1/wrap", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/v1/wrap")>();
  return {
    ...actual,
    unwrapDekWithKek: vi.fn(async () => {
      if (!controlled.unwrappedDek) {
        throw new Error("Missing test DEK");
      }
      return controlled.unwrappedDek;
    }),
  };
});

import {
  decryptV1WithKek,
  encryptV1WithDek,
  encryptV1WithKek,
  encryptV1WithPassword,
} from "../src/v1/format";
import { wipeBytesBestEffort } from "../src/v1/memory";

const ZERO_32 = new Array<number>(32).fill(0);

describe("best-effort memory hygiene", () => {
  beforeEach(() => {
    controlled.generatedDek = undefined;
    controlled.derivedKek = undefined;
    controlled.unwrappedDek = undefined;
  });

  it("overwrites a controlled byte buffer", () => {
    const secret = bytes(32, (index) => index + 1);
    wipeBytesBestEffort(secret);
    expect(Array.from(secret)).toEqual(ZERO_32);
  });

  it("wipes a generated DEK after successful encryption", async () => {
    controlled.generatedDek = bytes(32, (index) => 0x40 + index);

    await encryptV1WithKek({
      header: makeHeader(),
      kdf: makeKdf(),
      kekRaw32: bytes(32, (index) => 0x20 + index),
      wrapNonce: bytes(12, (index) => 0x60 + index),
      plaintext: bytes(16, (index) => index),
    });

    expect(Array.from(controlled.generatedDek)).toEqual(ZERO_32);
  });

  it("wipes generated DEK and derived KEK when encryption fails", async () => {
    controlled.generatedDek = bytes(32, (index) => 0x40 + index);
    controlled.derivedKek = bytes(32, (index) => 0x20 + index);

    await expect(
      encryptV1WithPassword({
        header: makeHeader(),
        kdf: makeKdf(),
        password: "temporary password",
        wrapNonce: new Uint8Array(11),
        plaintext: new Uint8Array(),
      })
    ).rejects.toThrow();

    expect(Array.from(controlled.generatedDek)).toEqual(ZERO_32);
    expect(Array.from(controlled.derivedKek)).toEqual(ZERO_32);
  });

  it("wipes an unwrapped DEK after successful decryption", async () => {
    const dek = bytes(32, (index) => 0x70 + index);
    const header = makeHeader();
    const kdf = makeKdf();
    const wrappedDek = makeWrap();
    const plaintext = bytes(24, (index) => 0x90 ^ index);
    const { bytes: archive } = await encryptV1WithDek({
      header,
      kdf,
      wrappedDek,
      dek,
      plaintext,
    });
    controlled.unwrappedDek = dek.slice();

    const result = await decryptV1WithKek({
      data: archive,
      kekRaw32: new Uint8Array(32),
    });

    expect(result.plaintext).toEqual(plaintext);
    expect(Array.from(controlled.unwrappedDek)).toEqual(ZERO_32);
  });
});
