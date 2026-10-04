import { describe, expect, it, vi } from "vitest";
import {
  AuthenticationError,
  FormatError,
  ResourcePolicyError,
} from "../src/v1/errors";
import { decryptStreamV2Internal } from "../src/v2/decrypt-stream";
import { encryptStreamV2Internal } from "../src/v2/encrypt-stream";
import {
  MIN_CHUNK_SIZE_V2,
  V2_HEADER_LENGTH,
} from "../src/v2/spec/constants";

const FAST_KDF = { timeCost: 1, memoryCostKiB: 8 * 1024, parallelism: 1 };
const DATA_RECORD_LENGTH = 13 + MIN_CHUNK_SIZE_V2 + 16;

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
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

function outputDestination() {
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

function cryptoFixture() {
  const archiveMasterKey = bytes(32, 0x90);
  const kek = bytes(32, 0x60);
  const randomValues = [
    bytes(16, 0x10),
    bytes(4, 0x20),
    bytes(16, 0x30),
    bytes(12, 0x40),
    archiveMasterKey,
  ];
  return {
    kek,
    encryption: {
      randomBytes(length: number) {
        const value = randomValues.shift();
        if (!value || value.length !== length) throw new Error("unexpected random request");
        return value;
      },
      deriveKek: vi.fn(async () => kek.slice()),
    },
    decryption() {
      return { deriveKek: vi.fn(async () => kek.slice()) };
    },
  };
}

async function encryptedArchive(plaintext: Uint8Array): Promise<{
  archive: Uint8Array;
  fixture: ReturnType<typeof cryptoFixture>;
}> {
  const fixture = cryptoFixture();
  const destination = outputDestination();
  await encryptStreamV2Internal(
    readable([plaintext]),
    destination.stream,
    "password",
    { chunkSize: MIN_CHUNK_SIZE_V2, kdf: FAST_KDF },
    fixture.encryption
  );
  return { archive: destination.bytes(), fixture };
}

async function decryptArchive(
  archiveChunks: Uint8Array[],
  fixture: ReturnType<typeof cryptoFixture>
) {
  const destination = outputDestination();
  const dependencies = fixture.decryption();
  const operation = decryptStreamV2Internal(
    readable(archiveChunks),
    destination.stream,
    "password",
    {
      resourcePolicy: {
        maxMemoryCostKiB: 8 * 1024,
        maxTimeCost: 1,
        maxParallelism: 1,
      },
    },
    dependencies
  );
  return { operation, destination, deriveKek: dependencies.deriveKek };
}

describe("V2 decryption stream", () => {
  it("round-trips with the real Argon2id implementation", async () => {
    const plaintext = bytes(47, 0xa0);
    const encryptedDestination = outputDestination();
    await encryptStreamV2Internal(
      readable([plaintext]),
      encryptedDestination.stream,
      "real-password",
      { chunkSize: MIN_CHUNK_SIZE_V2, kdf: FAST_KDF }
    );
    const archive = encryptedDestination.bytes();
    const decryptedDestination = outputDestination();

    await expect(
      decryptStreamV2Internal(
        readable([archive]),
        decryptedDestination.stream,
        "real-password",
        {
          resourcePolicy: {
            maxMemoryCostKiB: 8 * 1024,
            maxTimeCost: 1,
            maxParallelism: 1,
          },
        }
      )
    ).resolves.toMatchObject({
      format: "CFENC002",
      outputBytes: BigInt(plaintext.length),
      records: 1n,
    });
    expect(decryptedDestination.bytes()).toEqual(plaintext);
  });

  it.each([
    ["empty", 0],
    ["one short block", 31],
    ["several blocks", MIN_CHUNK_SIZE_V2 * 2 + 17],
  ])("round-trips plaintext case: %s", async (_name, length) => {
    const plaintext = bytes(length, 0x70);
    const { archive, fixture } = await encryptedArchive(plaintext);
    const cuts = [1, 119, V2_HEADER_LENGTH + 7, archive.length - 2]
      .filter((offset) => offset > 0 && offset < archive.length)
      .sort((a, b) => a - b);
    const chunks: Uint8Array[] = [];
    let offset = 0;
    for (const cut of cuts) {
      chunks.push(archive.subarray(offset, cut));
      offset = cut;
    }
    chunks.push(archive.subarray(offset));
    const decrypted = await decryptArchive(chunks, fixture);

    await expect(decrypted.operation).resolves.toEqual({
      format: "CFENC002",
      inputBytes: BigInt(archive.length),
      outputBytes: BigInt(plaintext.length),
      records: BigInt(Math.ceil(plaintext.length / MIN_CHUNK_SIZE_V2)),
    });
    expect(decrypted.destination.bytes()).toEqual(plaintext);
    expect(decrypted.destination.closed()).toBe(true);
    expect(decrypted.destination.aborted()).toBe(false);
    expect(decrypted.deriveKek).toHaveBeenCalledTimes(1);
  });

  it("applies the resource policy before running Argon2id", async () => {
    const { archive, fixture } = await encryptedArchive(bytes(17, 1));
    const destination = outputDestination();
    const deriveKek = vi.fn(async () => fixture.kek.slice());

    await expect(
      decryptStreamV2Internal(
        readable([archive]),
        destination.stream,
        "password",
        { resourcePolicy: { maxMemoryCostKiB: 4 * 1024 } },
        { deriveKek }
      )
    ).rejects.toBeInstanceOf(ResourcePolicyError);
    expect(deriveKek).not.toHaveBeenCalled();
    expect(destination.bytes()).toHaveLength(0);
    expect(destination.closed()).toBe(false);
  });

  it("rejects deleted, repeated and reordered DATA records", async () => {
    const plaintext = bytes(MIN_CHUNK_SIZE_V2 * 2 + 17, 0x40);
    const { archive, fixture } = await encryptedArchive(plaintext);
    const header = archive.subarray(0, V2_HEADER_LENGTH);
    const first = archive.subarray(V2_HEADER_LENGTH, V2_HEADER_LENGTH + DATA_RECORD_LENGTH);
    const second = archive.subarray(
      V2_HEADER_LENGTH + DATA_RECORD_LENGTH,
      V2_HEADER_LENGTH + DATA_RECORD_LENGTH * 2
    );
    const tail = archive.subarray(V2_HEADER_LENGTH + DATA_RECORD_LENGTH * 2);
    const mutations = [
      concat(header, second, tail),
      concat(header, first, first, second, tail),
      concat(header, second, first, tail),
    ];

    for (const mutation of mutations) {
      const decrypted = await decryptArchive([mutation], fixture);
      await expect(decrypted.operation).rejects.toBeInstanceOf(FormatError);
      expect(decrypted.destination.closed()).toBe(false);
    }
  });

  it("never writes a DATA block whose authentication fails", async () => {
    const { archive, fixture } = await encryptedArchive(bytes(31, 0x20));
    const altered = archive.slice();
    const dataTagByte = V2_HEADER_LENGTH + 13 + 31;
    altered[dataTagByte] = altered[dataTagByte]! ^ 1;
    const decrypted = await decryptArchive([altered], fixture);

    await expect(decrypted.operation).rejects.toBeInstanceOf(AuthenticationError);
    expect(decrypted.destination.bytes()).toHaveLength(0);
    expect(decrypted.destination.closed()).toBe(false);
    expect(decrypted.destination.aborted()).toBe(true);
  });

  it("rejects truncation after a valid block, an invalid FINAL tag and trailing bytes", async () => {
    const plaintext = bytes(MIN_CHUNK_SIZE_V2 + 17, 0x30);
    const { archive, fixture } = await encryptedArchive(plaintext);
    const afterFirstRecord = V2_HEADER_LENGTH + DATA_RECORD_LENGTH;
    const truncated = archive.subarray(0, afterFirstRecord);
    const invalidFinal = archive.slice();
    invalidFinal[invalidFinal.length - 1] = invalidFinal.at(-1)! ^ 1;
    const trailing = concat(archive, Uint8Array.of(0));

    const truncatedResult = await decryptArchive([truncated], fixture);
    await expect(truncatedResult.operation).rejects.toBeInstanceOf(FormatError);
    expect(truncatedResult.destination.bytes()).toEqual(
      plaintext.subarray(0, MIN_CHUNK_SIZE_V2)
    );
    expect(truncatedResult.destination.closed()).toBe(false);

    const invalidFinalResult = await decryptArchive([invalidFinal], fixture);
    await expect(invalidFinalResult.operation).rejects.toBeInstanceOf(AuthenticationError);
    expect(invalidFinalResult.destination.closed()).toBe(false);

    const trailingResult = await decryptArchive([trailing], fixture);
    await expect(trailingResult.operation).rejects.toBeInstanceOf(FormatError);
    expect(trailingResult.destination.closed()).toBe(false);
  });
});
