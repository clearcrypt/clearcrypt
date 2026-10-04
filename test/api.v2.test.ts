import { describe, expect, it } from "vitest";
import {
  ClearcryptError,
  decryptStreamV2,
  encryptStreamV2,
  type V2Progress,
} from "../src/index";
import { MIN_CHUNK_SIZE_V2 } from "../src/v2/spec/constants";

const FAST_KDF = { timeCost: 1, memoryCostKiB: 8 * 1024, parallelism: 1 };
const RESOURCE_POLICY = {
  maxMemoryCostKiB: 8 * 1024,
  maxTimeCost: 1,
  maxParallelism: 1,
};

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
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
    bytes() {
      const result = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
      let offset = 0;
      for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
      }
      return result;
    },
    closed: () => closed,
    aborted: () => aborted,
  };
}

describe("V2 public streaming API", () => {
  it("round-trips through root exports and reports bounded progress", async () => {
    const plaintext = bytes(MIN_CHUNK_SIZE_V2 + 17, 0x30);
    const encrypted = collector();
    const encryptProgress: V2Progress[] = [];
    const encryptResult = await encryptStreamV2(
      readable([plaintext]),
      encrypted.stream,
      "password",
      {
        chunkSize: MIN_CHUNK_SIZE_V2,
        kdf: FAST_KDF,
        onProgress(progress) {
          encryptProgress.push({ ...progress });
        },
      }
    );
    const decrypted = collector();
    const decryptProgress: V2Progress[] = [];
    const decryptResult = await decryptStreamV2(
      readable([encrypted.bytes()]),
      decrypted.stream,
      "password",
      {
        resourcePolicy: RESOURCE_POLICY,
        onProgress(progress) {
          decryptProgress.push({ ...progress });
        },
      }
    );

    expect(decrypted.bytes()).toEqual(plaintext);
    expect(encryptResult.records).toBe(2n);
    expect(decryptResult.records).toBe(2n);
    expect(encryptProgress.map((progress) => progress.phase)).toEqual([
      "kdf",
      "processing",
      "processing",
      "processing",
      "finalizing",
      "finalizing",
    ]);
    expect(decryptProgress.map((progress) => progress.phase)).toEqual([
      "kdf",
      "processing",
      "processing",
      "processing",
      "finalizing",
      "finalizing",
    ]);
    expect(encryptProgress.at(-1)).toMatchObject({
      inputBytes: encryptResult.inputBytes,
      outputBytes: encryptResult.outputBytes,
      records: encryptResult.records,
    });
    expect(decryptProgress.at(-1)).toMatchObject({
      inputBytes: decryptResult.inputBytes,
      outputBytes: decryptResult.outputBytes,
      records: decryptResult.records,
    });
    expect(encrypted.closed()).toBe(true);
    expect(decrypted.closed()).toBe(true);
  });

  it("rejects an already aborted operation without locking either stream", async () => {
    const controller = new AbortController();
    controller.abort("user cancelled");
    const source = readable([bytes(1, 1)]);
    const destination = collector();

    let received: unknown;
    try {
      await encryptStreamV2(source, destination.stream, "password", {
        signal: controller.signal,
        kdf: FAST_KDF,
      });
    } catch (error) {
      received = error;
    }

    expect(received).toBeInstanceOf(ClearcryptError);
    expect((received as ClearcryptError).code).toBe("ABORTED");
    expect(source.locked).toBe(false);
    expect(destination.stream.locked).toBe(false);
    expect(destination.bytes()).toHaveLength(0);
  });

  it("cancels a pending source and aborts its destination", async () => {
    const controller = new AbortController();
    let pullStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      pullStarted = resolve;
    });
    let cancelled = false;
    const source = new ReadableStream<Uint8Array>(
      {
        pull() {
          pullStarted();
          return new Promise<void>(() => undefined);
        },
        cancel() {
          cancelled = true;
        },
      },
      { highWaterMark: 0 }
    );
    const destination = collector();
    const operation = encryptStreamV2(source, destination.stream, "password", {
      signal: controller.signal,
      chunkSize: MIN_CHUNK_SIZE_V2,
      kdf: FAST_KDF,
    });

    await started;
    controller.abort("stop");
    let received: unknown;
    try {
      await operation;
    } catch (error) {
      received = error;
    }

    expect(received).toBeInstanceOf(ClearcryptError);
    expect((received as ClearcryptError).code).toBe("ABORTED");
    expect(cancelled).toBe(true);
    expect(destination.aborted()).toBe(true);
    expect(destination.closed()).toBe(false);
  });

  it("aborts when the synchronous progress callback throws", async () => {
    const destination = collector();

    let received: unknown;
    try {
      await encryptStreamV2(readable([bytes(17, 1)]), destination.stream, "password", {
        chunkSize: MIN_CHUNK_SIZE_V2,
        kdf: FAST_KDF,
        onProgress(progress) {
          if (progress.phase === "processing") throw new Error("progress callback failed");
        },
      });
    } catch (error) {
      received = error;
    }

    expect(received).toBeInstanceOf(ClearcryptError);
    expect((received as ClearcryptError).code).toBe("INTERNAL");
    expect(destination.aborted()).toBe(true);
    expect(destination.closed()).toBe(false);
  });

  it("maps a wrong password to the stable public authentication error", async () => {
    const encrypted = collector();
    await encryptStreamV2(readable([bytes(17, 1)]), encrypted.stream, "correct", {
      chunkSize: MIN_CHUNK_SIZE_V2,
      kdf: FAST_KDF,
    });
    const destination = collector();

    await expect(
      decryptStreamV2(readable([encrypted.bytes()]), destination.stream, "wrong", {
        resourcePolicy: RESOURCE_POLICY,
      })
    ).rejects.toMatchObject({ code: "AUTH_FAILED" });
    expect(destination.bytes()).toHaveLength(0);
    expect(destination.closed()).toBe(false);
  });
});
