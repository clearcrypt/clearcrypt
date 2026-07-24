import { KDF_PROFILES_V1, encryptBytesV1 } from "../../../dist/browser.js";

const profileSelect = document.querySelector("#profile");
const modeSelect = document.querySelector("#mode");
const runsInput = document.querySelector("#runs");
const runButton = document.querySelector("#run");
const downloadButton = document.querySelector("#download");
const status = document.querySelector("#status");
const output = document.querySelector("#output");
let latestReport;

const round = (value, digits = 1) => {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
};

function percentile(values, fraction) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

function summarize(durationsMs) {
  return {
    samples: durationsMs.map((value) => round(value)),
    median: round(percentile(durationsMs, 0.5)),
    p95: round(percentile(durationsMs, 0.95)),
    min: round(Math.min(...durationsMs)),
    max: round(Math.max(...durationsMs)),
  };
}

async function sampleMemory() {
  if (typeof performance.measureUserAgentSpecificMemory === "function") {
    try {
      const result = await performance.measureUserAgentSpecificMemory();
      return { source: "measureUserAgentSpecificMemory", bytes: result.bytes };
    } catch {
      // Fall back when the browser exposes the API but disallows this call.
    }
  }
  if (performance.memory?.usedJSHeapSize !== undefined) {
    return { source: "performance.memory", bytes: performance.memory.usedJSHeapSize };
  }
  return { source: "unavailable", bytes: null };
}

function nextFrame() {
  return new Promise((resolve) => requestAnimationFrame(resolve));
}

function startFrameMonitor() {
  let active = true;
  let previous = performance.now();
  let maxGapMs = 0;
  const tick = (now) => {
    maxGapMs = Math.max(maxGapMs, now - previous);
    previous = now;
    if (active) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  return {
    async stop() {
      await nextFrame();
      active = false;
      return round(maxGapMs);
    },
  };
}

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

async function runOnMainThread(profileId, runs) {
  await encryptOnce(profileId);
  const durationsMs = [];
  for (let index = 0; index < runs; index++) {
    durationsMs.push(await encryptOnce(profileId));
  }
  return durationsMs;
}

function runInWorker(profileId, runs) {
  return new Promise((resolve, reject) => {
    const worker = new Worker("/worker.js", { type: "module" });
    worker.addEventListener("message", ({ data }) => {
      worker.terminate();
      data.ok ? resolve(data.durationsMs) : reject(new Error(data.error));
    }, { once: true });
    worker.addEventListener("error", (event) => {
      worker.terminate();
      reject(event.error ?? new Error(event.message));
    }, { once: true });
    worker.postMessage({ profileId, runs });
  });
}

async function runScenario(profileId, mode, runs) {
  await nextFrame();
  const memoryBefore = await sampleMemory();
  const frameMonitor = startFrameMonitor();
  const wallStartedAt = performance.now();
  const durationsMs = mode === "main"
    ? await runOnMainThread(profileId, runs)
    : await runInWorker(profileId, runs);
  const wallDurationMs = performance.now() - wallStartedAt;
  const maxFrameGapMs = await frameMonitor.stop();
  const memoryAfter = await sampleMemory();

  return {
    profileId,
    profile: KDF_PROFILES_V1[profileId],
    mode,
    durationsMs: summarize(durationsMs),
    wallDurationMs: round(wallDurationMs),
    maxFrameGapMs,
    memory: {
      source:
        memoryBefore.source === memoryAfter.source
          ? memoryAfter.source
          : "incomparable",
      beforeBytes: memoryBefore.bytes,
      afterBytes: memoryAfter.bytes,
      deltaBytes:
        memoryBefore.source !== memoryAfter.source ||
        memoryBefore.bytes === null ||
        memoryAfter.bytes === null
          ? null
          : memoryAfter.bytes - memoryBefore.bytes,
    },
  };
}

runButton.addEventListener("click", async () => {
  const runs = Number(runsInput.value);
  if (!Number.isSafeInteger(runs) || runs < 1 || runs > 20) {
    status.textContent = "Runs must be an integer between 1 and 20.";
    return;
  }

  runButton.disabled = true;
  downloadButton.disabled = true;
  const profileIds = profileSelect.value === "all"
    ? Object.keys(KDF_PROFILES_V1)
    : [profileSelect.value];
  const modes = modeSelect.value === "both"
    ? ["main", "worker"]
    : [modeSelect.value];

  try {
    const results = [];
    for (const profileId of profileIds) {
      for (const mode of modes) {
        status.textContent = `Running ${profileId} on ${mode}…`;
        results.push(await runScenario(profileId, mode, runs));
      }
    }

    latestReport = {
      schema: "clearcrypt-argon2id-browser-benchmark-v1",
      createdAt: new Date().toISOString(),
      environment: {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        logicalCpus: navigator.hardwareConcurrency ?? null,
        deviceMemoryGiB: navigator.deviceMemory ?? null,
        crossOriginIsolated: globalThis.crossOriginIsolated ?? false,
      },
      protocol: {
        payloadBytes: 0,
        measuredRuns: runs,
        warmups: 1,
        passwordEncoding: "UTF-8",
        note: "Measurements are observations, not automatic profile recommendations.",
      },
      results,
    };
    output.textContent = JSON.stringify(latestReport, null, 2);
    status.textContent = "Benchmark complete.";
    downloadButton.disabled = false;
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : String(error);
  } finally {
    runButton.disabled = false;
  }
});

downloadButton.addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(latestReport, null, 2)], {
    type: "application/json",
  });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `clearcrypt-argon2-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});
