import { describe, expect, it, vi } from "vitest";
import { encodeV1 } from "../src/v1/format";
import { makeHeader, makeKdf, makeWrap } from "./helpers";

const { deriveKekMock } = vi.hoisted(() => ({
  deriveKekMock: vi.fn(() => {
    throw new Error("Argon2id must not run");
  }),
}));

vi.mock("../src/v1/kdf", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/v1/kdf")>();
  return { ...actual, deriveKekArgon2id: deriveKekMock };
});

import { ClearcryptError, decryptBytesV1 } from "../src/index";

function archiveWithKdf(
  overrides: Parameters<typeof makeKdf>[0],
  wrapOverrides: Parameters<typeof makeWrap>[0] = {}
): Uint8Array {
  return encodeV1(
    makeHeader(),
    makeKdf(overrides),
    makeWrap(wrapOverrides),
    new Uint8Array(),
    new Uint8Array(16)
  ).bytes;
}

async function expectErrorCode(
  promise: Promise<unknown>,
  code: ClearcryptError["code"]
): Promise<void> {
  let error: unknown;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }

  expect(error).toBeInstanceOf(ClearcryptError);
  expect((error as ClearcryptError).code).toBe(code);
}

describe("V1 decryption resource policy", () => {
  it("rejects the maximum format costs before Argon2id", async () => {
    const archive = archiveWithKdf({
      memoryCost: 256 * 1024,
      timeCost: 10,
      parallelism: 16,
    });

    await expectErrorCode(decryptBytesV1(archive, "password"), "RESOURCE_LIMIT");
    expect(deriveKekMock).not.toHaveBeenCalled();
  });

  it("applies partial local policy overrides before Argon2id", async () => {
    const archive = archiveWithKdf({ memoryCost: 64 * 1024 });

    await expectErrorCode(
      decryptBytesV1(archive, "password", {
        resourcePolicy: { maxMemoryCostKiB: 32 * 1024 },
      }),
      "RESOURCE_LIMIT"
    );
    expect(deriveKekMock).not.toHaveBeenCalled();
  });

  it("returns INVALID_PARAMS for an invalid local policy", async () => {
    const archive = archiveWithKdf({ memoryCost: 64 * 1024 });

    await expectErrorCode(
      decryptBytesV1(archive, "password", {
        resourcePolicy: { maxTimeCost: 0 },
      }),
      "INVALID_PARAMS"
    );
    expect(deriveKekMock).not.toHaveBeenCalled();
  });

  it("returns INVALID_FORMAT for KDF values outside the V1 format bounds", async () => {
    const archive = archiveWithKdf({ memoryCost: 256 * 1024 + 1 });

    await expectErrorCode(decryptBytesV1(archive, "password"), "INVALID_FORMAT");
    expect(deriveKekMock).not.toHaveBeenCalled();
  });

  it("rejects an unsupported wrap algorithm before Argon2id", async () => {
    const archive = archiveWithKdf({}, { wrapCipherId: 0xff });

    await expectErrorCode(decryptBytesV1(archive, "password"), "UNSUPPORTED_FORMAT");
    expect(deriveKekMock).not.toHaveBeenCalled();
  });
});
