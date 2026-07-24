import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { FormatError, UnsupportedFormatError } from "../src/v1/errors";
import { decodeEnvelopeV1, encodeV1 } from "../src/v1/format";
import { makeHeader, makeKdf, makeWrap } from "./helpers";

const AAD_LENGTH = 109;
const DEFAULT_RUNS = 1000;
const DEFAULT_SEED = 0x0cf001;

function readPositiveInteger(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

const runs = readPositiveInteger("CLEARCRYPT_FUZZ_RUNS", DEFAULT_RUNS);
const seed = readPositiveInteger("CLEARCRYPT_FUZZ_SEED", DEFAULT_SEED);

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error("Invalid hexadecimal corpus entry");
  }
  return Uint8Array.from(
    { length: hex.length / 2 },
    (_, index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  );
}

function assertParserOutcome(data: Uint8Array): void {
  try {
    const envelope = decodeEnvelopeV1(data);
    expect(envelope.aad.byteLength).toBe(AAD_LENGTH);
    expect(envelope.tag.byteLength).toBe(16);
    expect(
      envelope.aad.byteLength +
        envelope.ciphertext.byteLength +
        envelope.tag.byteLength
    ).toBe(data.byteLength);

    for (const view of [
      envelope.aad,
      envelope.header.nonce,
      envelope.kdf.salt,
      envelope.wrap.wrapNonce,
      envelope.wrap.wrappedDekCiphertext,
      envelope.wrap.wrapTag,
      envelope.ciphertext,
      envelope.tag,
    ]) {
      expect(view.buffer).toBe(data.buffer);
      expect(view.byteOffset).toBeGreaterThanOrEqual(data.byteOffset);
      expect(view.byteOffset + view.byteLength).toBeLessThanOrEqual(
        data.byteOffset + data.byteLength
      );
    }
  } catch (error) {
    expect(
      error instanceof FormatError || error instanceof UnsupportedFormatError
    ).toBe(true);
  }
}

describe("CFENC001 parser fuzzing", () => {
  it("never escapes its input or throws an unclassified error", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ maxLength: 16 * 1024 }),
        (data) => {
          assertParserOutcome(data);

          const padded = new Uint8Array(data.length + 7);
          padded.set(data, 3);
          assertParserOutcome(padded.subarray(3, 3 + data.length));
        }
      ),
      { numRuns: runs, seed, endOnFailure: true }
    );
  });

  it("targets structured mutations around a valid archive", () => {
    const valid = encodeV1(
      makeHeader(),
      makeKdf(),
      makeWrap(),
      new Uint8Array(64),
      new Uint8Array(16)
    ).bytes;
    const mutation = fc.record({
      offset: fc.integer({ min: 0, max: valid.length + 32 }),
      replacement: fc.uint8Array({ maxLength: 64 }),
      truncateAt: fc.option(
        fc.integer({ min: 0, max: valid.length + 64 }),
        { nil: undefined }
      ),
    });

    fc.assert(
      fc.property(mutation, ({ offset, replacement, truncateAt }) => {
        const length = Math.max(valid.length, offset + replacement.length);
        const mutated = new Uint8Array(length);
        mutated.set(valid);
        mutated.set(replacement, offset);
        const candidate =
          truncateAt === undefined
            ? mutated
            : mutated.subarray(0, Math.min(truncateAt, mutated.length));
        assertParserOutcome(candidate);
      }),
      { numRuns: runs, seed: seed ^ 0x51f15e, endOnFailure: true }
    );
  });

  it("keeps the checked-in invalid corpus rejected", () => {
    const corpus = JSON.parse(
      readFileSync(
        resolve("test/corpus/v1-invalid.json"),
        "utf8"
      )
    ) as Array<{ label: string; hex: string }>;

    for (const { label, hex } of corpus) {
      expect(
        () => decodeEnvelopeV1(fromHex(hex)),
        label
      ).toThrow();
    }
  });
});
