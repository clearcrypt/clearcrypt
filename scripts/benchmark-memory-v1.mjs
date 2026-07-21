#!/usr/bin/env node
import { decryptBytesV1, encryptBytesV1 } from "../dist/index.js";

const sizeMiB = Number(process.argv[2] ?? 32);
if (!Number.isSafeInteger(sizeMiB) || sizeMiB <= 0) {
  throw new Error("Size must be a positive integer in MiB");
}
if (typeof globalThis.gc !== "function") {
  throw new Error("Run this benchmark with node --expose-gc");
}

const sizeBytes = sizeMiB * 1024 * 1024;
let plaintext = new Uint8Array(sizeBytes);
for (let offset = 0; offset < plaintext.length; offset += 4096) {
  plaintext[offset] = (offset / 4096) & 0xff;
}

const archive = await encryptBytesV1(plaintext, "memory-benchmark", {
  kdf: { timeCost: 1, memoryCost: 8 * 1024, parallelism: 1 },
});
plaintext = null;
globalThis.gc();

const baseline = process.memoryUsage();
let peak = baseline;
const sample = () => {
  const current = process.memoryUsage();
  if (current.rss > peak.rss || current.arrayBuffers > peak.arrayBuffers) {
    peak = {
      ...peak,
      rss: Math.max(peak.rss, current.rss),
      arrayBuffers: Math.max(peak.arrayBuffers, current.arrayBuffers),
    };
  }
};
const sampler = setInterval(sample, 1);
const startedAt = performance.now();
const decrypted = await decryptBytesV1(archive, "memory-benchmark");
const durationMs = performance.now() - startedAt;
sample();
clearInterval(sampler);

if (decrypted.length !== sizeBytes) {
  throw new Error("Decryption verification failed");
}
for (let offset = 0; offset < decrypted.length; offset += 4096) {
  if (decrypted[offset] !== ((offset / 4096) & 0xff)) {
    throw new Error("Decryption verification failed");
  }
}

const toMiB = (bytes) => Math.round((bytes / 1024 / 1024) * 10) / 10;
console.log(JSON.stringify({
  sizeMiB,
  durationMs: Math.round(durationMs),
  baselineMiB: {
    rss: toMiB(baseline.rss),
    arrayBuffers: toMiB(baseline.arrayBuffers),
  },
  peakMiB: {
    rss: toMiB(peak.rss),
    arrayBuffers: toMiB(peak.arrayBuffers),
  },
  peakDeltaMiB: {
    rss: toMiB(peak.rss - baseline.rss),
    arrayBuffers: toMiB(peak.arrayBuffers - baseline.arrayBuffers),
  },
}, null, 2));
