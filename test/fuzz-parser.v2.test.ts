import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { FormatError, UnsupportedFormatError } from "../src/v1/errors";
import { V2IncrementalReader, type V2ReaderItem } from "../src/v2/reader";
import { AUTH_TAG_LENGTH_V2, MAX_CHUNK_SIZE_V2 } from "../src/v2/spec/constants";

const DEFAULT_RUNS = 1000;
const DEFAULT_SEED = 0x0cf002;

function readPositiveInteger(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

const runs = readPositiveInteger("CLEARCRYPT_FUZZ_RUNS", DEFAULT_RUNS);
const seed = readPositiveInteger("CLEARCRYPT_FUZZ_SEED", DEFAULT_SEED);

async function assertParserOutcome(data: Uint8Array): Promise<void> {
  const items: V2ReaderItem[] = [];
  const reader = new V2IncrementalReader((item) => {
    items.push(item);
  });

  try {
    await reader.write(data);
    reader.end();
    expect(items.at(0)?.kind).toBe("header");
    expect(items.at(-1)?.kind).toBe("final");
  } catch (error) {
    expect(
      error instanceof FormatError || error instanceof UnsupportedFormatError
    ).toBe(true);
  }

  expect(reader.maximumPendingCapacity).toBeLessThanOrEqual(
    MAX_CHUNK_SIZE_V2 + AUTH_TAG_LENGTH_V2
  );
}

describe("CFENC002 parser fuzzing", () => {
  it("never allocates beyond one validated record or throws an unclassified error", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 16 * 1024 }), async (data) => {
        await assertParserOutcome(data);

        const padded = new Uint8Array(data.length + 7);
        padded.set(data, 3);
        await assertParserOutcome(padded.subarray(3, 3 + data.length));
      }),
      { numRuns: runs, seed, endOnFailure: true }
    );
  });

  it("targets structured mutations around a valid archive", async () => {
    const vector = JSON.parse(
      readFileSync(resolve("test/vectors/v2/unicode-binary.json"), "utf8")
    ) as { archiveBase64: string };
    const valid = new Uint8Array(Buffer.from(vector.archiveBase64, "base64"));
    const mutation = fc.record({
      offset: fc.integer({ min: 0, max: valid.length + 32 }),
      replacement: fc.uint8Array({ maxLength: 64 }),
      truncateAt: fc.option(fc.integer({ min: 0, max: valid.length + 64 }), {
        nil: undefined,
      }),
    });

    await fc.assert(
      fc.asyncProperty(mutation, async ({ offset, replacement, truncateAt }) => {
        const length = Math.max(valid.length, offset + replacement.length);
        const mutated = new Uint8Array(length);
        mutated.set(valid);
        mutated.set(replacement, offset);
        const candidate =
          truncateAt === undefined
            ? mutated
            : mutated.subarray(0, Math.min(truncateAt, mutated.length));
        await assertParserOutcome(candidate);
      }),
      { numRuns: runs, seed: seed ^ 0x51f15e, endOnFailure: true }
    );
  });
});
