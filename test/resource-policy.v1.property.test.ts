import fc from "fast-check";
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

function archiveWithCosts(costs: {
  timeCost: number;
  memoryCost: number;
  parallelism: number;
}): Uint8Array {
  return encodeV1(
    makeHeader(),
    makeKdf(costs),
    makeWrap(),
    new Uint8Array(),
    new Uint8Array(16)
  ).bytes;
}

describe("resource-policy properties", () => {
  it("rejects every valid-but-excessive KDF cost before Argon2 allocation", async () => {
    deriveKekMock.mockClear();

    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.record({
            timeCost: fc.integer({ min: 1, max: 4 }),
            memoryCost: fc.integer({
              min: 128 * 1024 + 1,
              max: 256 * 1024,
            }),
            parallelism: fc.integer({ min: 1, max: 4 }),
          }),
          fc.record({
            timeCost: fc.integer({ min: 5, max: 10 }),
            memoryCost: fc.integer({
              min: 8 * 1024,
              max: 128 * 1024,
            }),
            parallelism: fc.integer({ min: 1, max: 4 }),
          }),
          fc.record({
            timeCost: fc.integer({ min: 1, max: 4 }),
            memoryCost: fc.integer({
              min: 8 * 1024,
              max: 128 * 1024,
            }),
            parallelism: fc.integer({ min: 5, max: 16 }),
          })
        ),
        async (costs) => {
          let error: unknown;
          try {
            await decryptBytesV1(archiveWithCosts(costs), "password");
          } catch (caught) {
            error = caught;
          }
          expect(error).toBeInstanceOf(ClearcryptError);
          expect((error as ClearcryptError).code).toBe("RESOURCE_LIMIT");
        }
      ),
      { numRuns: 250, seed: 0x0cf001 }
    );

    expect(deriveKekMock).not.toHaveBeenCalled();
  });

  it("rejects out-of-format integer extremes before Argon2 allocation", async () => {
    deriveKekMock.mockClear();
    const invalidCosts = fc.oneof(
      fc.record({
        timeCost: fc.constantFrom(0, 11, 0xffff_ffff),
        memoryCost: fc.integer({ min: 8 * 1024, max: 256 * 1024 }),
        parallelism: fc.integer({ min: 1, max: 16 }),
      }),
      fc.record({
        timeCost: fc.integer({ min: 1, max: 10 }),
        memoryCost: fc.constantFrom(0, 1, 8 * 1024 - 1, 256 * 1024 + 1, 0xffff_ffff),
        parallelism: fc.integer({ min: 1, max: 16 }),
      }),
      fc.record({
        timeCost: fc.integer({ min: 1, max: 10 }),
        memoryCost: fc.integer({ min: 8 * 1024, max: 256 * 1024 }),
        parallelism: fc.constantFrom(0, 17, 0xff),
      })
    );

    await fc.assert(
      fc.asyncProperty(invalidCosts, async (costs) => {
        let error: unknown;
        try {
          await decryptBytesV1(archiveWithCosts(costs), "password");
        } catch (caught) {
          error = caught;
        }
        expect(error).toBeInstanceOf(ClearcryptError);
        expect((error as ClearcryptError).code).toBe("INVALID_FORMAT");
      }),
      { numRuns: 250, seed: 0x0cf001 }
    );

    expect(deriveKekMock).not.toHaveBeenCalled();
  });
});
