#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rm, stat, statfs } from "node:fs/promises";
import { cpus, freemem, platform, release, totalmem } from "node:os";
import { isAbsolute, relative, resolve, join } from "node:path";
import { Readable, Writable } from "node:stream";

import {
  ClearcryptError,
  decryptStreamV2,
  encryptStreamV2,
} from "../dist/index.js";

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;
const SOURCE_PIECE_BYTES = 256 * 1024;
const CHUNK_SIZE = 4 * MIB;
const PASSWORD = "clearcrypt-v2-node-qualification";
const KDF = { timeCost: 2, memoryCostKiB: 64 * 1024, parallelism: 2 };
const RESOURCE_POLICY = {
  maxMemoryCostKiB: KDF.memoryCostKiB,
  maxTimeCost: KDF.timeCost,
  maxParallelism: KDF.parallelism,
};

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

function positiveInteger(name, fallback, minimum = 1) {
  const value = Number(option(name, fallback));
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer greater than or equal to ${minimum}`);
  }
  return value;
}

function sizesOption() {
  const sizes = String(option("--sizes-gib", "1,10,100"))
    .split(",")
    .map((value) => Number(value.trim()));
  if (
    sizes.length === 0 ||
    sizes.some((value) => !Number.isSafeInteger(value) || value <= 0) ||
    new Set(sizes).size !== sizes.length
  ) {
    throw new Error("--sizes-gib must contain unique positive integer GiB values");
  }
  return sizes;
}

function round(value, digits = 2) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function memorySnapshot() {
  const memory = process.memoryUsage();
  return { rss: memory.rss, arrayBuffers: memory.arrayBuffers };
}

function memoryMiB(memory) {
  return {
    rss: round(memory.rss / MIB),
    arrayBuffers: round(memory.arrayBuffers / MIB),
  };
}

function createMemorySampler() {
  const baseline = memorySnapshot();
  let peak = { ...baseline };
  const sample = () => {
    const current = memorySnapshot();
    peak.rss = Math.max(peak.rss, current.rss);
    peak.arrayBuffers = Math.max(peak.arrayBuffers, current.arrayBuffers);
  };
  const timer = setInterval(sample, 25);
  return {
    finish() {
      clearInterval(timer);
      sample();
      return {
        baselineMiB: memoryMiB(baseline),
        peakMiB: memoryMiB(peak),
        peakDeltaMiB: memoryMiB({
          rss: peak.rss - baseline.rss,
          arrayBuffers: peak.arrayBuffers - baseline.arrayBuffers,
        }),
      };
    },
  };
}

function generatedSource(totalBytes, hash, diagnostics = {}) {
  let offset = 0;
  const pieceLength = Math.min(SOURCE_PIECE_BYTES, totalBytes);
  const fullPieces = [new Uint8Array(pieceLength), new Uint8Array(pieceLength)];
  let pieceIndex = 0;
  const tailLength = totalBytes % SOURCE_PIECE_BYTES;
  const tailPiece = tailLength === 0 ? fullPieces[0] : new Uint8Array(tailLength);
  return new ReadableStream(
    {
      pull(controller) {
        if (offset === totalBytes) {
          controller.close();
          return;
        }
        const length = Math.min(SOURCE_PIECE_BYTES, totalBytes - offset);
      const chunk = length === pieceLength ? fullPieces[pieceIndex] : tailPiece;
      pieceIndex = (pieceIndex + 1) % fullPieces.length;
        chunk.fill(0);
        for (let index = 0; index < length; index += 4096) {
          chunk[index] = ((offset + index) / 4096) & 0xff;
        }
        hash?.update(chunk);
        offset += length;
        diagnostics.bytes = offset;
        controller.enqueue(chunk);
      },
      cancel() {
        diagnostics.cancelled = true;
      },
    },
    { highWaterMark: 1 }
  );
}

function hashingDestination(hash, diagnostics = {}) {
  let bytes = 0;
  return {
    stream: new WritableStream(
      {
        write(chunk) {
          hash?.update(chunk);
          bytes += chunk.length;
          diagnostics.bytes = bytes;
        },
        close() {
          diagnostics.closed = true;
        },
        abort() {
          diagnostics.aborted = true;
        },
      },
      { highWaterMark: 1 }
    ),
    bytes: () => bytes,
  };
}

function progressReporter(label, totalBytes) {
  let lastPercent = -10;
  return (progress) => {
    if (progress.phase !== "processing") return;
    const bytes = label.startsWith("encrypt")
      ? progress.inputBytes
      : progress.outputBytes;
    const percent = Math.floor((Number(bytes) / totalBytes) * 10) * 10;
    if (percent >= lastPercent + 10 && percent <= 100) {
      lastPercent = percent;
      process.stderr.write(`${label}: ${percent}%\n`);
    }
  };
}

async function measure(operation, volumeBytes) {
  globalThis.gc();
  const memory = createMemorySampler();
  const startedAt = performance.now();
  try {
    const value = await operation();
    const durationMs = performance.now() - startedAt;
    return {
      value,
      durationMs: round(durationMs),
      throughputMiBPerSecond: round(volumeBytes / MIB / (durationMs / 1000)),
      memory: memory.finish(),
    };
  } catch (error) {
    memory.finish();
    throw error;
  }
}

async function qualifyFileRoundTrip(sizeGiB, directory) {
  const totalBytes = sizeGiB * GIB;
  const archivePath = join(directory, `qualification-${sizeGiB}gib.cc2`);
  const sourceHash = createHash("sha256");
  const encryption = await measure(
    () => encryptStreamV2(
      generatedSource(totalBytes, sourceHash),
      Writable.toWeb(createWriteStream(archivePath, { flags: "wx" })),
      PASSWORD,
      {
        chunkSize: CHUNK_SIZE,
        kdf: KDF,
        onProgress: progressReporter(`encrypt ${sizeGiB} GiB`, totalBytes),
      }
    ),
    totalBytes
  );
  const expectedHash = sourceHash.digest("hex");
  const archiveBytes = (await stat(archivePath)).size;
  const restoredHash = createHash("sha256");
  const restored = hashingDestination(restoredHash);
  const decryption = await measure(
    () => decryptStreamV2(
      Readable.toWeb(createReadStream(archivePath, { highWaterMark: SOURCE_PIECE_BYTES })),
      restored.stream,
      PASSWORD,
      {
        resourcePolicy: RESOURCE_POLICY,
        onProgress: progressReporter(`decrypt ${sizeGiB} GiB`, totalBytes),
      }
    ),
    totalBytes
  );
  const actualHash = restoredHash.digest("hex");
  await rm(archivePath, { force: true });
  if (actualHash !== expectedHash || restored.bytes() !== totalBytes) {
    throw new Error(`Integrity verification failed for ${sizeGiB} GiB file round-trip`);
  }
  return {
    sizeGiB,
    mode: "archive-file",
    archiveBytes,
    plaintextSha256: expectedHash,
    verified: true,
    encryption: {
      durationMs: encryption.durationMs,
      throughputMiBPerSecond: encryption.throughputMiBPerSecond,
      ...encryption.memory,
    },
    decryption: {
      durationMs: decryption.durationMs,
      throughputMiBPerSecond: decryption.throughputMiBPerSecond,
      ...decryption.memory,
    },
  };
}

async function qualifyPipedRoundTrip(sizeGiB) {
  const totalBytes = sizeGiB * GIB;
  const sourceHash = createHash("sha256");
  const restoredHash = createHash("sha256");
  const restored = hashingDestination(restoredHash);
  const archivePipe = new TransformStream(
    undefined,
    { highWaterMark: 1 },
    { highWaterMark: 1 }
  );
  const roundTrip = await measure(async () => {
    const decryption = decryptStreamV2(
      archivePipe.readable,
      restored.stream,
      PASSWORD,
      {
        resourcePolicy: RESOURCE_POLICY,
        onProgress: progressReporter(`decrypt ${sizeGiB} GiB`, totalBytes),
      }
    );
    const encryption = encryptStreamV2(
      generatedSource(totalBytes, sourceHash),
      archivePipe.writable,
      PASSWORD,
      {
        chunkSize: CHUNK_SIZE,
        kdf: KDF,
        onProgress: progressReporter(`encrypt ${sizeGiB} GiB`, totalBytes),
      }
    );
    return Promise.all([encryption, decryption]);
  }, totalBytes);
  const expectedHash = sourceHash.digest("hex");
  const actualHash = restoredHash.digest("hex");
  if (actualHash !== expectedHash || restored.bytes() !== totalBytes) {
    throw new Error(`Integrity verification failed for ${sizeGiB} GiB piped round-trip`);
  }
  return {
    sizeGiB,
    mode: "bounded-pipe",
    plaintextSha256: expectedHash,
    verified: true,
    durationMs: roundTrip.durationMs,
    endToEndThroughputMiBPerSecond: roundTrip.throughputMiBPerSecond,
    ...roundTrip.memory,
  };
}

async function verifyFailurePaths() {
  const runWriteFailure = async (code) => {
    const diagnostics = {};
    const destination = new WritableStream({
      write() {
        throw Object.assign(new Error(`simulated ${code}`), { code });
      },
      abort() {
        diagnostics.aborted = true;
      },
    });
    let received;
    try {
      await encryptStreamV2(
        generatedSource(16 * MIB, undefined, diagnostics),
        destination,
        PASSWORD,
        { chunkSize: CHUNK_SIZE, kdf: KDF }
      );
    } catch (error) {
      received = error;
    }
    if (!(received instanceof ClearcryptError) || !diagnostics.cancelled) {
      throw new Error(`${code} write failure was not propagated and cancelled`);
    }
    return { simulatedCode: code, publicCode: received.code, sourceCancelled: true };
  };

  const controller = new AbortController();
  const sourceDiagnostics = {};
  const destinationDiagnostics = {};
  let received;
  try {
    await encryptStreamV2(
      generatedSource(64 * MIB, undefined, sourceDiagnostics),
      hashingDestination(undefined, destinationDiagnostics).stream,
      PASSWORD,
      {
        signal: controller.signal,
        chunkSize: CHUNK_SIZE,
        kdf: KDF,
        onProgress(progress) {
          if (progress.inputBytes >= 8n * BigInt(MIB)) controller.abort("qualification");
        },
      }
    );
  } catch (error) {
    received = error;
  }
  if (
    !(received instanceof ClearcryptError) ||
    received.code !== "ABORTED" ||
    !sourceDiagnostics.cancelled ||
    !destinationDiagnostics.aborted
  ) {
    throw new Error("Cancellation qualification failed");
  }
  return {
    cancellation: {
      publicCode: received.code,
      sourceCancelled: true,
      destinationAborted: true,
    },
    noSpace: await runWriteFailure("ENOSPC"),
    writeError: await runWriteFailure("EIO"),
  };
}

if (typeof globalThis.gc !== "function") {
  throw new Error("Run this qualification with node --expose-gc");
}

const sizesGiB = sizesOption();
const fileUpToGiB = positiveInteger("--file-up-to-gib", 10, 0);
const reserveGiB = positiveInteger("--reserve-gib", 16, 0);
const directory = resolve(option("--directory", ".clearcrypt-v2-qualification"));
const workspace = resolve(process.cwd());
const relativeDirectory = relative(workspace, directory);
if (relativeDirectory.startsWith("..") || isAbsolute(relativeDirectory)) {
  throw new Error("Qualification directory must remain inside the workspace");
}
await mkdir(directory, { recursive: true });

try {
  const filesystem = await statfs(directory);
  const freeBytesAtStart = Number(filesystem.bavail) * Number(filesystem.bsize);
  const results = [];
  const failurePaths = await verifyFailurePaths();
  for (const sizeGiB of sizesGiB) {
    const requiredBytes = (sizeGiB + reserveGiB) * GIB;
    const useFile = sizeGiB <= fileUpToGiB && freeBytesAtStart >= requiredBytes;
    results.push(
      useFile
        ? await qualifyFileRoundTrip(sizeGiB, directory)
        : await qualifyPipedRoundTrip(sizeGiB)
    );
  }
  const cpu = cpus()[0];
  console.log(JSON.stringify({
    schema: "clearcrypt-cfenc002-node-qualification-v1",
    createdAt: new Date().toISOString(),
    runtime: {
      node: process.version,
      platform: `${platform()} ${release()}`,
      cpu: cpu?.model ?? "unknown",
      logicalCpus: cpus().length,
      totalMemoryMiB: round(totalmem() / MIB),
      freeMemoryMiBAtReport: round(freemem() / MIB),
      qualificationDirectory: directory,
      freeDiskGiBAtStart: round(freeBytesAtStart / GIB),
    },
    protocol: {
      sizesGiB,
      fileUpToGiB,
      reserveGiB,
      chunkSizeMiB: CHUNK_SIZE / MIB,
      sourcePieceKiB: SOURCE_PIECE_BYTES / 1024,
      kdf: KDF,
      note: "Measured observations only; bounded-pipe results do not include persistent file I/O.",
    },
    failurePaths,
    results,
  }, null, 2));
} finally {
  const target = resolve(directory);
  const relativeTarget = relative(workspace, target);
  if (relativeTarget.startsWith("..") || isAbsolute(relativeTarget)) {
    throw new Error("Refusing to remove a qualification directory outside the workspace");
  }
  await rm(target, { recursive: true, force: true });
}
