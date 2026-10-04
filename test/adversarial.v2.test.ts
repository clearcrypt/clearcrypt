import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  mapInternalError,
  type ClearcryptErrorCode,
} from "../src/v1/api";
import { FormatError, UnsupportedFormatError } from "../src/v1/errors";
import { decryptStreamV2Internal } from "../src/v2/decrypt-stream";
import { V2IncrementalReader } from "../src/v2/reader";
import {
  AUTH_TAG_LENGTH_V2,
  MAX_CHUNK_SIZE_V2,
  V2_DATA_RECORD_HEADER_LENGTH,
  V2_HEADER_LENGTH,
} from "../src/v2/spec/constants";

type Vector = {
  password: { value: string };
  plaintext: {
    encoding: "hex" | "counter-mod-256";
    valueHex?: string;
    length: number;
    start?: number;
  };
  kdf: { timeCost: number; memoryCostKiB: number; parallelism: number };
  intermediates: { kekHex: string };
  records: Array<{ archiveOffset: number; plaintextLength: number }>;
  final: { archiveOffset: number };
  archiveBase64: string;
};

type CorpusEntry = {
  label: string;
  vector?: "unicode-binary";
  hex?: string;
  patches?: Array<{ offset: number; hex: string }>;
  xor?: Array<{ offset: number; value: number }>;
  truncateAt?: number;
  appendHex?: string;
  expectedCode: ClearcryptErrorCode;
};

const PROPERTY_SEED = 0x0cf002;
const unicodeVector = readVector("unicode-binary");
const multipleVector = readVector("multiple-blocks");

function readVector(name: string): Vector {
  return JSON.parse(
    readFileSync(resolve(`test/vectors/v2/${name}.json`), "utf8")
  ) as Vector;
}

function fromHex(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "hex"));
}

function archiveOf(vector: Vector): Uint8Array {
  return new Uint8Array(Buffer.from(vector.archiveBase64, "base64"));
}

function plaintextOf(vector: Vector): Uint8Array {
  if (vector.plaintext.encoding === "hex") {
    return fromHex(vector.plaintext.valueHex ?? "");
  }
  return Uint8Array.from(
    { length: vector.plaintext.length },
    (_, index) => ((vector.plaintext.start ?? 0) + index) & 0xff
  );
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function readable(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
}

function collector() {
  const chunks: Uint8Array[] = [];
  let closed = false;
  let aborted = false;
  return {
    stream: new WritableStream<Uint8Array>({
      write(chunk) {
        chunks.push(chunk.slice());
      },
      close() {
        closed = true;
      },
      abort() {
        aborted = true;
      },
    }),
    bytes: () => concat(...chunks),
    closed: () => closed,
    aborted: () => aborted,
  };
}

function splitBySizes(bytes: Uint8Array, sizes: number[]): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  let offset = 0;
  let index = 0;
  while (offset < bytes.length) {
    const size = sizes[index % sizes.length]!;
    const end = Math.min(offset + size, bytes.length);
    chunks.push(bytes.subarray(offset, end));
    offset = end;
    index += 1;
  }
  return chunks;
}

async function decryptWithVector(
  archive: Uint8Array,
  chunks: Uint8Array[],
  vector: Vector
) {
  const destination = collector();
  const operation = decryptStreamV2Internal(
    readable(chunks),
    destination.stream,
    vector.password.value,
    {
      resourcePolicy: {
        maxMemoryCostKiB: vector.kdf.memoryCostKiB,
        maxTimeCost: vector.kdf.timeCost,
        maxParallelism: vector.kdf.parallelism,
      },
    },
    { deriveKek: async () => fromHex(vector.intermediates.kekHex) }
  );
  return { archive, destination, operation };
}

async function expectInvalidArchive(
  archive: Uint8Array,
  vector: Vector,
  expectedCode?: ClearcryptErrorCode
): Promise<void> {
  const result = await decryptWithVector(archive, [archive], vector);
  let error: unknown;
  try {
    await result.operation;
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeDefined();
  expect(result.destination.closed()).toBe(false);
  expect(result.destination.aborted()).toBe(true);
  if (expectedCode) expect(mapInternalError(error).code).toBe(expectedCode);
}

function applyCorpusEntry(entry: CorpusEntry): Uint8Array {
  let bytes = entry.hex
    ? fromHex(entry.hex)
    : archiveOf(unicodeVector).slice();
  for (const patch of entry.patches ?? []) {
    bytes.set(fromHex(patch.hex), patch.offset);
  }
  for (const mutation of entry.xor ?? []) {
    bytes[mutation.offset] = bytes[mutation.offset]! ^ mutation.value;
  }
  if (entry.truncateAt !== undefined) bytes = bytes.slice(0, entry.truncateAt);
  if (entry.appendHex) bytes = concat(bytes, fromHex(entry.appendHex));
  return bytes;
}

describe("CFENC002 adversarial and property tests", () => {
  it("rejects every truncation point of the small normative vectors", async () => {
    for (const name of ["empty", "unicode-binary"] as const) {
      const archive = archiveOf(readVector(name));
      for (let length = 0; length < archive.length; length += 1) {
        const reader = new V2IncrementalReader(() => undefined);
        let rejected = false;
        try {
          await reader.write(archive.subarray(0, length));
          reader.end();
        } catch (error) {
          rejected = error instanceof FormatError || error instanceof UnsupportedFormatError;
        }
        expect(rejected, `${name} truncation at ${length}`).toBe(true);
      }
    }
  });

  it(
    "decrypts arbitrary reproducible stream splits",
    async () => {
      const archive = archiveOf(multipleVector);
      const expected = plaintextOf(multipleVector);

      await fc.assert(
        fc.asyncProperty(
          fc.array(fc.integer({ min: 1, max: 8192 }), {
            minLength: 1,
            maxLength: 32,
          }),
          async (sizes) => {
            const result = await decryptWithVector(
              archive,
              splitBySizes(archive, sizes),
              multipleVector
            );
            await expect(result.operation).resolves.toMatchObject({ records: 3n });
            expect(result.destination.bytes()).toEqual(expected);
            expect(result.destination.closed()).toBe(true);
          }
        ),
        { numRuns: 25, seed: PROPERTY_SEED, endOnFailure: true }
      );
    },
    30_000
  );

  it("rejects removal, duplication, reordering and splicing of DATA records", async () => {
    const archive = archiveOf(multipleVector);
    const offsets = multipleVector.records.map((record) => record.archiveOffset);
    const finalOffset = multipleVector.final.archiveOffset;
    const header = archive.subarray(0, offsets[0]);
    const first = archive.subarray(offsets[0], offsets[1]);
    const second = archive.subarray(offsets[1], offsets[2]);
    const thirdAndFinal = archive.subarray(offsets[2]);
    const secondHeader = second.subarray(0, V2_DATA_RECORD_HEADER_LENGTH);
    const firstBody = first.subarray(V2_DATA_RECORD_HEADER_LENGTH);
    const secondSpliced = concat(secondHeader, firstBody);
    const final = archive.subarray(finalOffset);

    const mutations = [
      concat(header, first, thirdAndFinal),
      concat(header, first, first, second, thirdAndFinal),
      concat(header, second, first, thirdAndFinal),
      concat(header, first, secondSpliced, archive.subarray(offsets[2], finalOffset), final),
    ];

    for (const mutation of mutations) {
      await expectInvalidArchive(mutation, multipleVector);
    }
  });

  it("rejects hostile lengths and counters before allocating their declared size", async () => {
    const header = archiveOf(unicodeVector).subarray(0, V2_HEADER_LENGTH);
    const hostileRecords = [
      concat(Uint8Array.of(1), new Uint8Array(8), fromHex("00000000")),
      concat(Uint8Array.of(1), new Uint8Array(8), fromHex("ffffffff")),
      concat(Uint8Array.of(1), fromHex("ffffffffffffffff"), fromHex("00010000")),
      concat(Uint8Array.of(2), fromHex("ffffffffffffffff"), new Uint8Array(8), new Uint8Array(16)),
      concat(Uint8Array.of(2), new Uint8Array(8), fromHex("ffffffffffffffff"), new Uint8Array(16)),
    ];

    for (const hostileRecord of hostileRecords) {
      const reader = new V2IncrementalReader(() => undefined);
      await expect(reader.write(concat(header, hostileRecord))).rejects.toBeInstanceOf(FormatError);
      expect(reader.maximumPendingCapacity).toBe(V2_HEADER_LENGTH);
    }

    const hostileHeader = header.slice();
    hostileHeader.set(fromHex("ffffffff"), 11);
    const reader = new V2IncrementalReader(() => undefined);
    await expect(reader.write(hostileHeader)).rejects.toBeInstanceOf(FormatError);
    expect(reader.maximumPendingCapacity).toBe(V2_HEADER_LENGTH);
    expect(reader.maximumPendingCapacity).toBeLessThan(MAX_CHUNK_SIZE_V2 + AUTH_TAG_LENGTH_V2);
  });

  it("keeps the checked-in invalid corpus rejected with stable public codes", async () => {
    const corpus = JSON.parse(
      readFileSync(resolve("test/corpus/v2-invalid.json"), "utf8")
    ) as CorpusEntry[];

    for (const entry of corpus) {
      await expectInvalidArchive(
        applyCorpusEntry(entry),
        unicodeVector,
        entry.expectedCode
      );
    }
  });
});
