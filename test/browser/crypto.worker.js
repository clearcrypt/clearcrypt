import {
  decryptBytesV1,
  decryptStreamV2,
  encryptBytesV1,
  encryptStreamV2,
} from "../../dist/browser.js";

const V2_CHUNK_SIZE = 64 * 1024;
const V2_QUALIFICATION_CHUNK_SIZE = 4 * 1024 * 1024;
const V2_KDF = { timeCost: 1, memoryCostKiB: 8 * 1024, parallelism: 1 };
const V2_RESOURCE_POLICY = {
  maxMemoryCostKiB: 8 * 1024,
  maxTimeCost: 1,
  maxParallelism: 1,
};

const toBytes = (values) => new Uint8Array(values);
const toValues = (bytes) => Array.from(bytes);
const delay = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

function checksumUpdate(checksum, bytes) {
  let value = checksum;
  for (const byte of bytes) {
    value ^= byte;
    value = Math.imul(value, 0x01000193) >>> 0;
  }
  return value;
}

function createGeneratedSource(totalBytes, options = {}) {
  let offset = 0;
  let checksum = 0x811c9dc5;
  let maxChunkBytes = 0;
  let cancelled = false;
  const stream = new ReadableStream(
    {
      async pull(controller) {
        if (options.delayMilliseconds) await delay(options.delayMilliseconds);
        if (offset === totalBytes) {
          controller.close();
          return;
        }
        const length = Math.min(V2_CHUNK_SIZE, totalBytes - offset);
        const chunk = new Uint8Array(length);
        for (let index = 0; index < length; index += 1) {
          chunk[index] = ((offset + index) * 31 + 17) & 0xff;
        }
        checksum = checksumUpdate(checksum, chunk);
        maxChunkBytes = Math.max(maxChunkBytes, chunk.byteLength);
        offset += length;
        controller.enqueue(chunk);
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 1 }
  );
  return {
    stream,
    metrics: () => ({ checksum, maxChunkBytes, cancelled }),
  };
}

function createInstrumentedDestination(options = {}) {
  const chunks = [];
  let bytes = 0;
  let writes = 0;
  let activeWrites = 0;
  let maxActiveWrites = 0;
  let maxWriteBytes = 0;
  let aborted = false;
  const stream = new WritableStream(
    {
      async write(chunk) {
        activeWrites += 1;
        maxActiveWrites = Math.max(maxActiveWrites, activeWrites);
        maxWriteBytes = Math.max(maxWriteBytes, chunk.byteLength);
        if (options.delayMilliseconds) await delay(options.delayMilliseconds);
        bytes += chunk.byteLength;
        writes += 1;
        if (options.collect) chunks.push(chunk.slice());
        options.onWrite?.(chunk);
        activeWrites -= 1;
      },
      abort() {
        aborted = true;
      },
    },
    { highWaterMark: 1 }
  );
  return {
    stream,
    chunks,
    metrics: () => ({
      bytes,
      writes,
      maxActiveWrites,
      maxWriteBytes,
      aborted,
    }),
  };
}

function streamFromChunks(chunks) {
  let index = 0;
  return new ReadableStream(
    {
      pull(controller) {
        if (index === chunks.length) controller.close();
        else controller.enqueue(chunks[index++]);
      },
    },
    { highWaterMark: 1 }
  );
}

async function v2RoundTrip(totalBytes, password) {
  const source = createGeneratedSource(totalBytes);
  const archive = createInstrumentedDestination({ collect: true });
  const encryption = await encryptStreamV2(source.stream, archive.stream, password, {
    chunkSize: V2_CHUNK_SIZE,
    kdf: V2_KDF,
  });

  let decryptedChecksum = 0x811c9dc5;
  const plaintext = createInstrumentedDestination({
    onWrite(chunk) {
      decryptedChecksum = checksumUpdate(decryptedChecksum, chunk);
    },
  });
  const decryption = await decryptStreamV2(
    streamFromChunks(archive.chunks),
    plaintext.stream,
    password,
    { resourcePolicy: V2_RESOURCE_POLICY }
  );

  return {
    source: source.metrics(),
    archive: archive.metrics(),
    plaintext: plaintext.metrics(),
    decryptedChecksum,
    encryption: {
      inputBytes: Number(encryption.inputBytes),
      outputBytes: Number(encryption.outputBytes),
      records: Number(encryption.records),
    },
    decryption: {
      inputBytes: Number(decryption.inputBytes),
      outputBytes: Number(decryption.outputBytes),
      records: Number(decryption.records),
    },
  };
}

async function v2BoundedProbe(totalBytes, password) {
  const source = createGeneratedSource(totalBytes);
  const destination = createInstrumentedDestination({ delayMilliseconds: 1 });
  let progressEvents = 0;
  const result = await encryptStreamV2(source.stream, destination.stream, password, {
    chunkSize: V2_CHUNK_SIZE,
    kdf: V2_KDF,
    onProgress() {
      progressEvents += 1;
    },
  });
  return {
    source: source.metrics(),
    destination: destination.metrics(),
    progressEvents,
    result: {
      inputBytes: Number(result.inputBytes),
      outputBytes: Number(result.outputBytes),
      records: Number(result.records),
    },
  };
}

async function v2PipedRoundTrip(totalBytes, password) {
  const source = createGeneratedSource(totalBytes);
  const archivePipe = new TransformStream(
    undefined,
    { highWaterMark: 1 },
    { highWaterMark: 1 }
  );
  let decryptedChecksum = 0x811c9dc5;
  const plaintext = createInstrumentedDestination({
    onWrite(chunk) {
      decryptedChecksum = checksumUpdate(decryptedChecksum, chunk);
    },
  });
  const startedAt = performance.now();
  const decryption = decryptStreamV2(
    archivePipe.readable,
    plaintext.stream,
    password,
    { resourcePolicy: V2_RESOURCE_POLICY }
  );
  const encryption = encryptStreamV2(
    source.stream,
    archivePipe.writable,
    password,
    { chunkSize: V2_QUALIFICATION_CHUNK_SIZE, kdf: V2_KDF }
  );
  const [encrypted, decrypted] = await Promise.all([encryption, decryption]);
  const durationMs = performance.now() - startedAt;
  return {
    durationMs,
    throughputMiBPerSecond: totalBytes / (1024 * 1024) / (durationMs / 1000),
    source: source.metrics(),
    plaintext: plaintext.metrics(),
    decryptedChecksum,
    encryption: {
      inputBytes: Number(encrypted.inputBytes),
      outputBytes: Number(encrypted.outputBytes),
      records: Number(encrypted.records),
    },
    decryption: {
      inputBytes: Number(decrypted.inputBytes),
      outputBytes: Number(decrypted.outputBytes),
      records: Number(decrypted.records),
    },
  };
}

let cancelableV2;

async function startCancelableV2(data) {
  if (cancelableV2) throw new Error("A V2 operation is already active");
  const controller = new AbortController();
  const source = createGeneratedSource(data.totalBytes, { delayMilliseconds: 2 });
  const destination = createInstrumentedDestination({ delayMilliseconds: 2 });
  cancelableV2 = { controller, source, destination };
  self.postMessage({ started: true, id: data.id });
  try {
    await encryptStreamV2(source.stream, destination.stream, data.password, {
      chunkSize: V2_CHUNK_SIZE,
      kdf: V2_KDF,
      signal: controller.signal,
    });
    self.postMessage({ ok: true, value: { completed: true }, closing: true });
  } catch (error) {
    self.postMessage({
      ok: false,
      error: {
        name: error instanceof Error ? error.name : typeof error,
        code: error?.code ?? null,
        message: error instanceof Error ? error.message : String(error),
      },
      diagnostics: {
        source: source.metrics(),
        destination: destination.metrics(),
      },
      closing: true,
    });
  } finally {
    cancelableV2 = undefined;
    setTimeout(() => self.close(), 0);
  }
}

self.addEventListener("message", async ({ data }) => {
  if (data.action === "cancelV2") {
    cancelableV2?.controller.abort("Browser test cancellation");
    return;
  }

  try {
    if (data.notifyStarted) self.postMessage({ started: true });

    let value;
    switch (data.action) {
      case "encrypt":
        value = toValues(
          await encryptBytesV1(toBytes(data.plaintext), data.password, data.options)
        );
        break;
      case "roundTrip": {
        const archive = await encryptBytesV1(toBytes(data.plaintext), data.password);
        value = toValues(await decryptBytesV1(archive, data.password));
        break;
      }
      case "v2RoundTrip":
        value = await v2RoundTrip(data.totalBytes, data.password);
        break;
      case "v2BoundedProbe":
        value = await v2BoundedProbe(data.totalBytes, data.password);
        break;
      case "v2PipedRoundTrip":
        value = await v2PipedRoundTrip(data.totalBytes, data.password);
        break;
      case "startCancelableV2":
        await startCancelableV2(data);
        return;
      default:
        throw new Error(`Unknown worker action: ${String(data.action)}`);
    }
    self.postMessage({ ok: true, value, closing: true });
    setTimeout(() => self.close(), 0);
  } catch (error) {
    self.postMessage({
      ok: false,
      error: {
        name: error instanceof Error ? error.name : typeof error,
        code: error?.code ?? null,
        message: error instanceof Error ? error.message : String(error),
      },
      closing: true,
    });
    setTimeout(() => self.close(), 0);
  }
});
