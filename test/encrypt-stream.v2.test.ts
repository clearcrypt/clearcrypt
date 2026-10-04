import { describe, expect, it, vi } from "vitest";
import { aeadDecryptAes256Gcm, importAesGcmKey } from "../src/v1/aead";
import { deriveFinalKeyV2 } from "../src/v2/archive-crypto";
import {
  buildDataNonceV2,
  decryptDataRecordV2,
} from "../src/v2/data-record-crypto";
import { encryptStreamV2Internal } from "../src/v2/encrypt-stream";
import { V2IncrementalReader, type V2ReaderItem } from "../src/v2/reader";
import { decodeHeaderV2 } from "../src/v2/spec/codec";
import {
  MIN_CHUNK_SIZE_V2,
  V2_WRAP_AAD_LENGTH,
} from "../src/v2/spec/constants";

const FAST_KDF = { timeCost: 1, memoryCostKiB: 8 * 1024, parallelism: 1 };

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

function streamFromChunks(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
}

function collectingDestination(limit: number): {
  stream: WritableStream<Uint8Array>;
  bytes: () => Uint8Array;
  closed: () => boolean;
} {
  const chunks: Uint8Array[] = [];
  let length = 0;
  let isClosed = false;
  return {
    stream: new WritableStream({
      write(chunk) {
        if (chunk.length > limit - length) throw new Error("test destination overflow");
        chunks.push(chunk.slice());
        length += chunk.length;
      },
      close() {
        isClosed = true;
      },
    }),
    bytes: () => concat(...chunks),
    closed: () => isClosed,
  };
}

function deterministicDependencies() {
  const archiveMasterKey = bytes(32, 0x90);
  const kek = bytes(32, 0x60);
  const randomValues = [
    bytes(16, 0x10),
    bytes(4, 0x20),
    bytes(16, 0x30),
    bytes(12, 0x40),
    archiveMasterKey,
  ];
  const deriveKek = vi.fn(async () => kek.slice());
  return {
    archiveMasterKey,
    kek,
    deriveKek,
    dependencies: {
      randomBytes(length: number) {
        const value = randomValues.shift();
        if (!value || value.length !== length) throw new Error("unexpected random request");
        return value;
      },
      deriveKek,
    },
  };
}

async function parseArchive(archive: Uint8Array): Promise<V2ReaderItem[]> {
  const items: V2ReaderItem[] = [];
  const reader = new V2IncrementalReader((item) => {
    items.push(item);
  });
  await reader.write(archive);
  reader.end();
  return items;
}

async function verifyFinal(
  archiveAad: Uint8Array,
  archiveMasterKey: Uint8Array,
  item: Extract<V2ReaderItem, { kind: "final" }>
): Promise<void> {
  const header = decodeHeaderV2(archiveAad);
  const key = await deriveFinalKeyV2({
    archiveMasterKey,
    archiveId: header.archiveId,
  });
  await aeadDecryptAes256Gcm({
    key,
    nonce: buildDataNonceV2(header.contentNoncePrefix, 0n),
    ciphertext: new Uint8Array(0),
    tag: item.tag,
    associatedAuthenticatedData: concat(archiveAad, item.headerBytes),
  });
}

describe("V2 encryption stream", () => {
  it("creates and closes a valid authenticated empty archive", async () => {
    const fixture = deterministicDependencies();
    const destination = collectingDestination(1024);

    const result = await encryptStreamV2Internal(
      streamFromChunks([]),
      destination.stream,
      "password",
      { chunkSize: MIN_CHUNK_SIZE_V2, kdf: FAST_KDF },
      fixture.dependencies
    );
    const archive = destination.bytes();
    const items = await parseArchive(archive);

    expect(result).toEqual({ format: "CFENC002", inputBytes: 0n, outputBytes: 155n, records: 0n });
    expect(destination.closed()).toBe(true);
    expect(items.map((item) => item.kind)).toEqual(["header", "final"]);
    expect(fixture.deriveKek).toHaveBeenCalledTimes(1);

    const header = items[0];
    const final = items[1];
    if (header?.kind !== "header" || final?.kind !== "final") throw new Error("invalid archive");
    const wrapKey = await importAesGcmKey(fixture.kek);
    await expect(
      aeadDecryptAes256Gcm({
        key: wrapKey,
        nonce: header.header.wrapNonce,
        ciphertext: header.header.wrappedArchiveKeyCiphertext,
        tag: header.header.wrappedArchiveKeyTag,
        associatedAuthenticatedData: header.bytes.subarray(0, V2_WRAP_AAD_LENGTH),
      })
    ).resolves.toEqual(fixture.archiveMasterKey);
    await expect(verifyFinal(header.bytes, fixture.archiveMasterKey, final)).resolves.toBeUndefined();
  });

  it("groups arbitrary source chunks into full records and one final short record", async () => {
    const fixture = deterministicDependencies();
    const plaintext = bytes(MIN_CHUNK_SIZE_V2 * 2 + 17, 0x70);
    const source = streamFromChunks([
      plaintext.subarray(0, 7),
      plaintext.subarray(7, MIN_CHUNK_SIZE_V2 + 123),
      new Uint8Array(0),
      plaintext.subarray(MIN_CHUNK_SIZE_V2 + 123),
    ]);
    const destination = collectingDestination(plaintext.length + 1024);

    const result = await encryptStreamV2Internal(
      source,
      destination.stream,
      "password",
      { chunkSize: MIN_CHUNK_SIZE_V2, kdf: FAST_KDF },
      fixture.dependencies
    );
    const items = await parseArchive(destination.bytes());
    const header = items[0];
    if (header?.kind !== "header") throw new Error("missing header");
    const dataItems = items.filter(
      (item): item is Extract<V2ReaderItem, { kind: "data" }> => item.kind === "data"
    );
    const decrypted: Uint8Array[] = [];
    for (const item of dataItems) {
      decrypted.push(
        await decryptDataRecordV2({
          archiveAad: header.bytes,
          archiveMasterKey: fixture.archiveMasterKey,
          headerBytes: item.headerBytes,
          ciphertext: item.ciphertext,
          tag: item.tag,
        })
      );
    }

    expect(concat(...decrypted)).toEqual(plaintext);
    expect(dataItems.map((item) => item.header.plaintextLength)).toEqual([
      MIN_CHUNK_SIZE_V2,
      MIN_CHUNK_SIZE_V2,
      17,
    ]);
    expect(result.inputBytes).toBe(BigInt(plaintext.length));
    expect(result.outputBytes).toBe(BigInt(plaintext.length + 155 + 29 * 3));
    expect(result.records).toBe(3n);
    expect(fixture.deriveKek).toHaveBeenCalledTimes(1);
  });

  it("processes many blocks with a counting destination that retains no archive", async () => {
    const fixture = deterministicDependencies();
    const recordCount = 64;
    const sourceChunk = bytes(MIN_CHUNK_SIZE_V2, 0x50);
    let produced = 0;
    const source = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          if (produced === recordCount) {
            controller.close();
            return;
          }
          controller.enqueue(sourceChunk);
          produced += 1;
        },
      },
      { highWaterMark: 0 }
    );
    let counted = 0n;
    let writes = 0;
    const destination = new WritableStream<Uint8Array>({
      write(chunk) {
        counted += BigInt(chunk.length);
        writes += 1;
      },
    });

    const result = await encryptStreamV2Internal(
      source,
      destination,
      "password",
      { chunkSize: MIN_CHUNK_SIZE_V2, kdf: FAST_KDF },
      fixture.dependencies
    );
    const plaintextLength = BigInt(recordCount * MIN_CHUNK_SIZE_V2);

    expect(result.inputBytes).toBe(plaintextLength);
    expect(result.records).toBe(BigInt(recordCount));
    expect(result.outputBytes).toBe(plaintextLength + 155n + 29n * BigInt(recordCount));
    expect(counted).toBe(result.outputBytes);
    expect(writes).toBe(1 + recordCount * 3 + 2);
    expect(fixture.deriveKek).toHaveBeenCalledTimes(1);
  });

  it("does not read plaintext while the destination is blocking the header", async () => {
    const fixture = deterministicDependencies();
    let pulls = 0;
    const source = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          pulls += 1;
          controller.enqueue(bytes(17, 1));
          controller.close();
        },
      },
      { highWaterMark: 0 }
    );
    let releaseHeader!: () => void;
    const headerGate = new Promise<void>((resolve) => {
      releaseHeader = resolve;
    });
    let headerWriteStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      headerWriteStarted = resolve;
    });
    let writes = 0;
    const destination = new WritableStream<Uint8Array>({
      async write() {
        writes += 1;
        if (writes === 1) {
          headerWriteStarted();
          await headerGate;
        }
      },
    });

    const operation = encryptStreamV2Internal(
      source,
      destination,
      "password",
      { chunkSize: MIN_CHUNK_SIZE_V2, kdf: FAST_KDF },
      fixture.dependencies
    );
    await started;
    expect(pulls).toBe(0);

    releaseHeader();
    await operation;
    expect(pulls).toBe(1);
  });
});
