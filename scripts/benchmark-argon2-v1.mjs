#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { cpus, freemem, platform, release, totalmem } from "node:os";
import { fileURLToPath } from "node:url";
import { KDF_PROFILES_V1, encryptBytesV1 } from "../dist/index.js";

const MIB = 1024 * 1024;

function readOption(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

function readPositiveInteger(name, fallback) {
  const value = Number(readOption(name, fallback));
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function percentile(values, fraction) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

const round = (value, digits = 1) => {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
};

const profileIds = Object.keys(KDF_PROFILES_V1);
const childProfile = readOption("--child", undefined);
const runs = readPositiveInteger("--runs", 5);
const warmups = readPositiveInteger("--warmups", 1);

async function encryptOnce(profileId) {
  const { version: _version, ...kdf } = KDF_PROFILES_V1[profileId];
  const startedAt = performance.now();
  await encryptBytesV1(
    new Uint8Array(),
    "clearcrypt-argon2-benchmark",
    { kdf }
  );
  return performance.now() - startedAt;
}

async function runChild(profileId) {
  if (!profileIds.includes(profileId)) {
    throw new Error(`Unknown profile: ${profileId}`);
  }
  if (typeof globalThis.gc !== "function") {
    throw new Error("The benchmark child requires --expose-gc");
  }

  globalThis.gc();
  const baselineMemory = process.memoryUsage();
  const baselineMaxRssKiB = process.resourceUsage().maxRSS;
  const coldDurationMs = await encryptOnce(profileId);

  for (let index = 0; index < warmups; index++) {
    await encryptOnce(profileId);
  }

  const durationsMs = [];
  for (let index = 0; index < runs; index++) {
    durationsMs.push(await encryptOnce(profileId));
  }

  const concurrentStartedAt = performance.now();
  await Promise.all([encryptOnce(profileId), encryptOnce(profileId)]);
  const concurrentPairDurationMs = performance.now() - concurrentStartedAt;

  globalThis.gc();
  const finalMemory = process.memoryUsage();
  const finalMaxRssKiB = process.resourceUsage().maxRSS;
  const profile = KDF_PROFILES_V1[profileId];

  return {
    profileId,
    profile,
    coldDurationMs: round(coldDurationMs),
    warmDurationMs: {
      samples: durationsMs.map((value) => round(value)),
      median: round(percentile(durationsMs, 0.5)),
      p95: round(percentile(durationsMs, 0.95)),
      min: round(Math.min(...durationsMs)),
      max: round(Math.max(...durationsMs)),
    },
    concurrentPairDurationMs: round(concurrentPairDurationMs),
    memoryMiB: {
      baselineRss: round(baselineMemory.rss / MIB),
      finalRss: round(finalMemory.rss / MIB),
      finalRssDelta: round((finalMemory.rss - baselineMemory.rss) / MIB),
      maxRssDelta: round(
        Math.max(0, finalMaxRssKiB - baselineMaxRssKiB) / 1024
      ),
      finalArrayBuffersDelta: round(
        (finalMemory.arrayBuffers - baselineMemory.arrayBuffers) / MIB
      ),
    },
  };
}

if (childProfile) {
  const result = await runChild(childProfile);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} else {
  const requestedProfile = readOption("--profile", "all");
  const selectedProfiles =
    requestedProfile === "all" ? profileIds : [requestedProfile];
  for (const profileId of selectedProfiles) {
    if (!profileIds.includes(profileId)) {
      throw new Error(`Unknown profile: ${profileId}`);
    }
  }

  const results = selectedProfiles.map((profileId) => {
    const child = spawnSync(
      process.execPath,
      [
        "--expose-gc",
        fileURLToPath(import.meta.url),
        "--child",
        profileId,
        "--runs",
        String(runs),
        "--warmups",
        String(warmups),
      ],
      { cwd: process.cwd(), encoding: "utf8", shell: false }
    );
    if (child.error) throw child.error;
    if (child.status !== 0) {
      process.stderr.write(child.stderr);
      process.exit(child.status ?? 1);
    }
    return JSON.parse(child.stdout);
  });

  const cpu = cpus()[0];
  const report = {
    schema: "clearcrypt-argon2id-benchmark-v1",
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
      payloadBytes: 0,
      runs,
      warmups,
      passwordEncoding: "UTF-8",
      operation: "encryptBytesV1",
      note: "Measurements are observations, not automatic profile recommendations.",
    },
    results,
  };

  console.log(JSON.stringify(report, null, 2));
}
