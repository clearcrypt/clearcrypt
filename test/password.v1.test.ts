import { describe, expect, it } from "vitest";
import {
  ClearcryptError,
  decryptBytesV1,
  encryptBytesV1,
} from "../src/index";
import { MAX_PUBLIC_PASSWORD_BYTES } from "../src/v1/password";
import { bytes } from "./helpers";

const FAST_KDF = {
  timeCost: 1,
  memoryCost: 8 * 1024,
  parallelism: 1,
};

async function expectCode(
  promise: Promise<unknown>,
  code: ClearcryptError["code"]
): Promise<ClearcryptError> {
  let error: unknown;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ClearcryptError);
  expect((error as ClearcryptError).code).toBe(code);
  return error as ClearcryptError;
}

describe("V1 public password policy", () => {
  it("preserves spaces, case, accents, emoji, and combining characters", async () => {
    const cases = [
      { exact: "  Secret  ", altered: "Secret" },
      { exact: "CaseSensitive", altered: "casesensitive" },
      { exact: "Café🔐", altered: "Cafe🔐" },
      { exact: "e\u0301", altered: "é" },
    ];

    for (const { exact, altered } of cases) {
      const plaintext = bytes(12, (i) => i * 7);
      const archive = await encryptBytesV1(plaintext, exact, { kdf: FAST_KDF });

      await expectCode(decryptBytesV1(archive, altered), "AUTH_FAILED");
      await expect(decryptBytesV1(archive, exact)).resolves.toEqual(plaintext);
    }
  });

  it("rejects empty strings and empty byte arrays", async () => {
    await expectCode(
      encryptBytesV1(new Uint8Array(), "", { kdf: FAST_KDF }),
      "INVALID_PARAMS"
    );
    await expectCode(
      encryptBytesV1(new Uint8Array(), new Uint8Array(), { kdf: FAST_KDF }),
      "INVALID_PARAMS"
    );
    await expectCode(decryptBytesV1(new Uint8Array(), ""), "INVALID_PARAMS");
  });

  it("accepts exactly 1024 bytes", async () => {
    const password = new Uint8Array(MAX_PUBLIC_PASSWORD_BYTES).fill(0x61);
    const originalPassword = password.slice();
    const plaintext = bytes(8, (i) => 0xa0 + i);
    const archive = await encryptBytesV1(plaintext, password, { kdf: FAST_KDF });

    expect(password).toEqual(originalPassword);
    await expect(decryptBytesV1(archive, password)).resolves.toEqual(plaintext);
    expect(password).toEqual(originalPassword);
  });

  it("measures string limits after UTF-8 encoding", async () => {
    const oversizedPassword = "🔐".repeat(257);
    expect(new TextEncoder().encode(oversizedPassword)).toHaveLength(1028);

    const error = await expectCode(
      encryptBytesV1(new Uint8Array(), oversizedPassword, { kdf: FAST_KDF }),
      "INVALID_PARAMS"
    );
    expect(error.message).toBe("Password must not exceed 1024 UTF-8 bytes");
    expect(error.message).not.toContain(oversizedPassword);
  });
});
