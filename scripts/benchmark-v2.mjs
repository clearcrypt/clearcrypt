#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdtemp, open, rm } from "node:fs/promises";
import { cpus, freemem, platform, release, tmpdir, totalmem } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  decryptStreamV2Internal,
  deriveKekArgon2id,
  encryptStreamV2Internal,
} from "../dist/benchmark-v2-internal.js";

const MIB = 1024 * 1024;
const SOURCE_PIECE_BYTES = 256 * 1024;
const FIXED_KEK = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const PASSWORD = "clearcrypt-v2-benchmark";

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

function integerOption(name, fallback, { minimum = 1 } = {}) {
  const value = Number(option(name, fallback));
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer greater than or equal to ${minimum}`);
  }
  return value;
}

function chunkSizesOption() {
  const values = String(option("--chunk-sizes-mib", "1,4,8"))
    .split(",")
    .map((value) => Number(value.trim()));
  if (
    values.length === 0 ||
    values.some((value) => ![1, 4, 8].includes(value)) ||
    new Set(values).size !== values.length
  ) {
    throw new Error("--chunk-sizes-mib must be a unique comma-separated subset of 1,4,8");
  }
  return values;
}

function round(value, digits = 2) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function percentile(values, fraction) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

function summarize(samples) {
  return {
    samples: samples.map((value) => round(value)),
    median: round(percentile(samples, 0.5)),
    p95: round(percentile(samples, 0.95)),
    min: round(Math.min(...samples)),
    max: round(Math.max(...samples)),
  };
}

function memoryMiB(memory) {
  return {
    rss: round(memory.rss / MIB),
    arrayBuffers: round(memory.arrayBuffers / MIB),
  };
}

function generatedSource(totalBytes) {
  let offset = 0;
  const pieceLength = Math.min(SOURCE_PIECE_BYTES, totalBytes);
  const fullPieces = [new Uint8Array(pieceLength), new Uint8Array(pieceLength)];
  let pieceIndex = 0;
  const tailLength = totalBytes % SOURCE_PIECE_BYTES;
  const tailPiece = tailLength === 0 ? fullPieces[0] : new Uint8Array(tailLength);
  return new ReadableStream({
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
      offset += length;
      controller.enqueue(chunk);
    },
  });
}

function countingDestination() {
  let bytes = 0;
  return {
    stream: new WritableStream({
      write(chunk) {
        bytes += chunk.length;
      },
    }),
    bytes: () => bytes,
  };
}

function webFileSource(path) {
  return Readable.toWeb(createReadStream(path, { highWaterMark: SOURCE_PIECE_BYTES }));
}

function webFileDestination(path) {
  return Writable.toWeb(createWriteStream(path, { flags: "w" }));
}

const fixedKekDependency = {
  deriveKek: async () => FIXED_KEK.slice(),
};

async function encrypt(source, destination, chunkSize) {
  return encryptStreamV2Internal(
    source,
    destination,
    PASSWORD,
    {
      chunkSize,
      kdf: { timeCost: 1, memoryCostKiB: 8192, parallelism: 1 },
    },
    fixedKekDependency
  );
}

async function decrypt(source, destination) {
  return decryptStreamV2Internal(
    source,
    destination,
    PASSWORD,
    {
      resourcePolicy: {
        maxMemoryCostKiB: 8192,
        maxTimeCost: 1,
        maxParallelism: 1,
      },
    },
    fixedKekDependency
  );
}

async function writePatternFile(path, totalBytes) {
  const handle = await open(path, "w");
  try {
    const source = generatedSource(totalBytes).getReader();
    let position = 0;
    while (true) {
      const item = await source.read();
      if (item.done) break;
      await handle.write(item.value, 0, item.value.length, position);
      position += item.value.length;
    }
  } finally {
    await handle.close();
  }
}

async function hashFile(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function prepareFiles(directory, sizeBytes, chunkSize) {
  const plaintextPath = join(directory, "plaintext.bin");
  const archivePath = join(directory, "archive.cc2");
  await writePatternFile(plaintextPath, sizeBytes);
  await encrypt(
    webFileSource(plaintextPath),
    webFileDestination(archivePath),
    chunkSize
  );
  return { plaintextPath, archivePath };
}

async function runDataOnce(params) {
  const outputPath = join(params.directory, "output.bin");
  if (params.operation === "copy") {
    const source = webFileSource(params.plaintextPath);
    if (params.scenario === "instrumented") {
      const destination = countingDestination();
      const reader = source.getReader();
      const writer = destination.stream.getWriter();
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        await writer.write(item.value);
      }
      await writer.close();
      if (destination.bytes() !== params.sizeBytes) {
        throw new Error("Instrumented I/O byte count mismatch");
      }
      return;
    }
    await source.pipeTo(webFileDestination(outputPath));
    return;
  }
  if (params.operation === "encrypt") {
    const source =
      params.scenario === "instrumented"
        ? generatedSource(params.sizeBytes)
        : webFileSource(params.plaintextPath);
    if (params.scenario === "instrumented") {
      const destination = countingDestination();
      const result = await encrypt(source, destination.stream, params.chunkSize);
      if (destination.bytes() !== Number(result.outputBytes)) {
        throw new Error("Instrumented encryption byte count mismatch");
      }
      return;
    }
    await encrypt(source, webFileDestination(outputPath), params.chunkSize);
    return;
  }

  const source = webFileSource(params.archivePath);
  if (params.scenario === "instrumented") {
    const destination = countingDestination();
    const result = await decrypt(source, destination.stream);
    if (destination.bytes() !== params.sizeBytes || result.outputBytes !== BigInt(params.sizeBytes)) {
      throw new Error("Instrumented decryption byte count mismatch");
    }
    return;
  }
  await decrypt(source, webFileDestination(outputPath));
}

async function measure(operation, runs, warmups) {
  for (let index = 0; index < warmups; index += 1) await operation();
  globalThis.gc();
  const baseline = process.memoryUsage();
  let peakRss = baseline.rss;
  let peakArrayBuffers = baseline.arrayBuffers;
  const sample = () => {
    const current = process.memoryUsage();
    peakRss = Math.max(peakRss, current.rss);
    peakArrayBuffers = Math.max(peakArrayBuffers, current.arrayBuffers);
  };
  const sampler = setInterval(sample, 2);
  const durationsMs = [];
  try {
    for (let index = 0; index < runs; index += 1) {
      globalThis.gc();
      const startedAt = performance.now();
      await operation();
      durationsMs.push(performance.now() - startedAt);
      sample();
    }
  } finally {
    clearInterval(sampler);
    sample();
  }
  return {
    durationMs: summarize(durationsMs),
    baselineMiB: memoryMiB(baseline),
    peakMiB: {
      rss: round(peakRss / MIB),
      arrayBuffers: round(peakArrayBuffers / MIB),
    },
    peakDeltaMiB: {
      rss: round((peakRss - baseline.rss) / MIB),
      arrayBuffers: round((peakArrayBuffers - baseline.arrayBuffers) / MIB),
    },
  };
}

async function runKdfChild() {
  const runs = integerOption("--runs", 3);
  const warmups = integerOption("--warmups", 1, { minimum: 0 });
  const timeCost = integerOption("--kdf-time", 2);
  const memoryCostKiB = integerOption("--kdf-memory-kib", 65536);
  const parallelism = integerOption("--kdf-parallelism", 2);
  const password = new TextEncoder().encode(PASSWORD);
  const salt = Uint8Array.from({ length: 16 }, (_, index) => 0x80 + index);
  const derive = async () => {
    const key = await deriveKekArgon2id({
      password,
      salt,
      timeCost,
      memoryCost: memoryCostKiB,
      parallelism,
    });
    key.fill(0);
  };
  globalThis.gc();
  const baseline = process.memoryUsage();
  let peakRss = baseline.rss;
  let peakArrayBuffers = baseline.arrayBuffers;
  const sample = () => {
    const current = process.memoryUsage();
    peakRss = Math.max(peakRss, current.rss);
    peakArrayBuffers = Math.max(peakArrayBuffers, current.arrayBuffers);
  };
  const sampler = setInterval(sample, 2);
  let coldDurationMs;
  const durationsMs = [];
  try {
    let startedAt = performance.now();
    await derive();
    coldDurationMs = performance.now() - startedAt;
    for (let index = 0; index < warmups; index += 1) await derive();
    for (let index = 0; index < runs; index += 1) {
      startedAt = performance.now();
      await derive();
      durationsMs.push(performance.now() - startedAt);
      sample();
    }
  } finally {
    clearInterval(sampler);
    sample();
  }
  return {
    kind: "argon2id",
    parameters: { timeCost, memoryCostKiB, parallelism },
    coldDurationMs: round(coldDurationMs),
    durationMs: summarize(durationsMs),
    baselineMiB: memoryMiB(baseline),
    peakMiB: {
      rss: round(peakRss / MIB),
      arrayBuffers: round(peakArrayBuffers / MIB),
    },
    peakDeltaMiB: {
      rss: round((peakRss - baseline.rss) / MIB),
      arrayBuffers: round((peakArrayBuffers - baseline.arrayBuffers) / MIB),
    },
  };
}

async function runDataChild() {
  const runs = integerOption("--runs", 3);
  const warmups = integerOption("--warmups", 1, { minimum: 0 });
  const sizeMiB = integerOption("--size-mib", 128);
  const chunkSizeMiB = integerOption("--chunk-size-mib", 4);
  const operation = option("--operation", "encrypt");
  const scenario = option("--scenario", "instrumented");
  if (!['encrypt', 'decrypt', 'copy'].includes(operation)) throw new Error("Invalid operation");
  if (!['instrumented', 'files'].includes(scenario)) throw new Error("Invalid scenario");
  const sizeBytes = sizeMiB * MIB;
  const chunkSize = chunkSizeMiB * MIB;
  if (!Number.isSafeInteger(sizeBytes)) {
    throw new Error("--size-mib produces a byte length outside the safe integer range");
  }
  const directory = await mkdtemp(join(tmpdir(), "clearcrypt-v2-benchmark-"));
  try {
    const files = await prepareFiles(directory, sizeBytes, chunkSize);
    const params = {
      directory,
      sizeBytes,
      chunkSize,
      operation,
      scenario,
      ...files,
    };
    const measured = await measure(() => runDataOnce(params), runs, warmups);
    let verified = true;
    if (scenario === "files") {
      const outputPath = join(directory, "output.bin");
      if (operation === "encrypt") {
        const verification = countingDestination();
        await decrypt(webFileSource(outputPath), verification.stream);
        verified = verification.bytes() === sizeBytes;
      } else {
        verified = (await hashFile(files.plaintextPath)) === (await hashFile(outputPath));
      }
    }
    const medianSeconds = measured.durationMs.median / 1000;
    return {
      kind: operation === "copy" ? "io-baseline" : "data",
      operation,
      scenario,
      sizeMiB,
      chunkSizeMiB,
      throughputMiBPerSecond: round(sizeMiB / medianSeconds),
      verified,
      ...measured,
    };
  } finally {
    const target = resolve(directory);
    const base = resolve(tmpdir());
    const relativeTarget = relative(base, target);
    if (relativeTarget.startsWith("..") || isAbsolute(relativeTarget)) {
      throw new Error("Refusing to remove a benchmark directory outside the temporary directory");
    }
    await rm(target, { recursive: true, force: true });
  }
}

function runChild(arguments_) {
  const child = spawnSync(
    process.execPath,
    ["--expose-gc", fileURLToPath(import.meta.url), "--child", ...arguments_],
    { cwd: process.cwd(), encoding: "utf8", shell: false, maxBuffer: 16 * MIB }
  );
  if (child.error) throw child.error;
  if (child.status !== 0) {
    process.stderr.write(child.stderr);
    process.exit(child.status ?? 1);
  }
  return JSON.parse(child.stdout);
}

async function runParent() {
  const runs = integerOption("--runs", 3);
  const warmups = integerOption("--warmups", 1, { minimum: 0 });
  const sizeMiB = integerOption("--size-mib", 128);
  const chunkSizesMiB = chunkSizesOption();
  const requestedScenario = option("--scenario", "all");
  const scenarios = requestedScenario === "all"
    ? ["instrumented", "files"]
    : [requestedScenario];
  if (scenarios.some((value) => !["instrumented", "files"].includes(value))) {
    throw new Error("--scenario must be all, instrumented, or files");
  }
  const common = [
    "--runs", String(runs),
    "--warmups", String(warmups),
  ];
  const kdf = runChild([
    "--kind", "kdf",
    ...common,
    "--kdf-time", String(integerOption("--kdf-time", 2)),
    "--kdf-memory-kib", String(integerOption("--kdf-memory-kib", 65536)),
    "--kdf-parallelism", String(integerOption("--kdf-parallelism", 2)),
  ]);
  const data = [];
  const io = [];
  for (const scenario of scenarios) {
    io.push(runChild([
      "--kind", "data",
      ...common,
      "--size-mib", String(sizeMiB),
      "--chunk-size-mib", "4",
      "--scenario", scenario,
      "--operation", "copy",
    ]));
  }
  for (const chunkSizeMiB of chunkSizesMiB) {
    for (const scenario of scenarios) {
      for (const operation of ["encrypt", "decrypt"]) {
        data.push(runChild([
          "--kind", "data",
          ...common,
          "--size-mib", String(sizeMiB),
          "--chunk-size-mib", String(chunkSizeMiB),
          "--scenario", scenario,
          "--operation", operation,
        ]));
      }
    }
  }
  const cpu = cpus()[0];
  return {
    schema: "clearcrypt-cfenc002-node-benchmark-v1",
    createdAt: new Date().toISOString(),
    runtime: {
      node: process.version,
      platform: `${platform()} ${release()}`,
      cpu: cpu?.model ?? "unknown",
      logicalCpus: cpus().length,
      totalMemoryMiB: round(totalmem() / MIB),
      freeMemoryMiBAtReport: round(freemem() / MIB),
    },
    protocol: {
      runs,
      warmups,
      sizeMiB,
      chunkSizesMiB,
      sourcePieceKiB: SOURCE_PIECE_BYTES / 1024,
      kdfSeparatedFromDataMeasurements: true,
      note: "Measured observations only; the runner does not extrapolate larger files.",
    },
    kdf,
    io,
    data,
  };
}

if (typeof globalThis.gc !== "function") {
  throw new Error("Run this benchmark with node --expose-gc");
}

if (process.argv.includes("--child")) {
  const result = option("--kind", "data") === "kdf"
    ? await runKdfChild()
    : await runDataChild();
  process.stdout.write(`${JSON.stringify(result)}\n`);
} else {
  console.log(JSON.stringify(await runParent(), null, 2));
}
