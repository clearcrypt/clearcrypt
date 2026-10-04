import {
  KDF_PROFILES_V1,
  decryptBytesV1,
  decryptStreamV2,
  encryptBytesV1,
} from "../../dist/browser.js";

const toBytes = (values) => new Uint8Array(values);
const toValues = (bytes) => Array.from(bytes);

function checksumUpdate(checksum, bytes) {
  let value = checksum;
  for (const byte of bytes) {
    value ^= byte;
    value = Math.imul(value, 0x01000193) >>> 0;
  }
  return value;
}

function decodeBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function vectorPlaintextChecksum(plaintext) {
  let checksum = 0x811c9dc5;
  if (plaintext.encoding === "hex") {
    const bytes = new Uint8Array(plaintext.valueHex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number.parseInt(plaintext.valueHex.slice(index * 2, index * 2 + 2), 16);
    }
    return checksumUpdate(checksum, bytes);
  }
  for (let offset = 0; offset < plaintext.length; offset += 64 * 1024) {
    const length = Math.min(64 * 1024, plaintext.length - offset);
    const bytes = Uint8Array.from(
      { length },
      (_, index) => (plaintext.start + offset + index) & 0xff
    );
    checksum = checksumUpdate(checksum, bytes);
  }
  return checksum;
}

async function decryptV2Vector(vector) {
  const archive = decodeBase64(vector.archiveBase64);
  let offset = 0;
  const source = new ReadableStream({
    pull(controller) {
      if (offset === archive.length) {
        controller.close();
        return;
      }
      const end = Math.min(offset + 32 * 1024, archive.length);
      controller.enqueue(archive.subarray(offset, end));
      offset = end;
    },
  });
  let plaintextLength = 0;
  let checksum = 0x811c9dc5;
  const destination = new WritableStream({
    write(chunk) {
      plaintextLength += chunk.length;
      checksum = checksumUpdate(checksum, chunk);
    },
  });
  await decryptStreamV2(source, destination, vector.password.value, {
    resourcePolicy: {
      maxMemoryCostKiB: vector.kdf.memoryCostKiB,
      maxTimeCost: vector.kdf.timeCost,
      maxParallelism: vector.kdf.parallelism,
    },
  });
  return {
    name: vector.name,
    plaintextLength,
    checksum,
    expectedLength: vector.plaintext.length,
    expectedChecksum: vectorPlaintextChecksum(vector.plaintext),
  };
}

function createWorker() {
  return new Worker("/crypto.worker.js", { type: "module" });
}

function requestWorker(message) {
  return new Promise((resolve, reject) => {
    const worker = createWorker();
    worker.addEventListener(
      "message",
      ({ data }) => {
        worker.terminate();
        data.ok ? resolve(data.value) : reject(Object.assign(
          new Error(data.error.message),
          {
            name: data.error.name,
            code: data.error.code,
          }
        ));
      },
      { once: true }
    );
    worker.addEventListener(
      "error",
      (event) => {
        worker.terminate();
        reject(event.error ?? new Error(event.message));
      },
      { once: true }
    );
    worker.postMessage(message);
  });
}

function requestResponsiveWorker(message) {
  let ticks = 0;
  const timer = setInterval(() => {
    ticks += 1;
  }, 0);
  return requestWorker(message)
    .then((value) => ({ value, mainThreadTicks: ticks }))
    .finally(() => clearInterval(timer));
}

let cancelableOperation;
let cancelableV2Operation;

window.clearcryptTest = {
  profiles: KDF_PROFILES_V1,

  async encrypt(plaintext, password, options) {
    return toValues(
      await encryptBytesV1(toBytes(plaintext), password, options)
    );
  },

  async decrypt(archive, password, options) {
    return toValues(
      await decryptBytesV1(toBytes(archive), password, options)
    );
  },

  async captureDecryptError(archive, password, options) {
    try {
      await decryptBytesV1(toBytes(archive), password, options);
      return null;
    } catch (error) {
      return {
        name: error instanceof Error ? error.name : typeof error,
        code: error?.code ?? null,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  },

  workerRoundTrip(plaintext, password) {
    return requestWorker({
      action: "roundTrip",
      plaintext,
      password,
    });
  },

  workerV2RoundTrip(totalBytes, password) {
    return requestResponsiveWorker({
      action: "v2RoundTrip",
      totalBytes,
      password,
    });
  },

  workerV2BoundedProbe(totalBytes, password) {
    return requestResponsiveWorker({
      action: "v2BoundedProbe",
      totalBytes,
      password,
    });
  },

  workerV2PipedRoundTrip(totalBytes, password) {
    return requestResponsiveWorker({
      action: "v2PipedRoundTrip",
      totalBytes,
      password,
    });
  },

  async verifyV2Vectors() {
    const paths = [
      "/vectors/v2/empty.json",
      "/vectors/v2/unicode-binary.json",
      "/vectors/v2/multiple-blocks.json",
    ];
    const vectors = await Promise.all(
      paths.map(async (path) => {
        const response = await fetch(path);
        if (!response.ok) throw new Error(`Unable to load ${path}`);
        return response.json();
      })
    );
    const results = [];
    for (const vector of vectors) results.push(await decryptV2Vector(vector));
    return results;
  },

  async concurrentRoundTrips(payloads, password) {
    return Promise.all(
      payloads.map(async (plaintext) => {
        const archive = await encryptBytesV1(toBytes(plaintext), password);
        return toValues(await decryptBytesV1(archive, password));
      })
    );
  },

  async startCancelableWorker() {
    if (cancelableOperation) {
      throw new Error("A cancelable operation is already active");
    }

    const worker = createWorker();
    let resolveStarted;
    let resolveResult;
    let rejectResult;
    const started = new Promise((resolve) => {
      resolveStarted = resolve;
    });
    const result = new Promise((resolve, reject) => {
      resolveResult = resolve;
      rejectResult = reject;
    });

    worker.addEventListener("message", ({ data }) => {
      if (data.started) {
        resolveStarted();
        return;
      }
      cancelableOperation = undefined;
      worker.terminate();
      data.ok
        ? resolveResult(data.value)
        : rejectResult(new Error(data.error.message));
    });
    worker.addEventListener("error", (event) => {
      cancelableOperation = undefined;
      worker.terminate();
      rejectResult(event.error ?? new Error(event.message));
    });
    cancelableOperation = { worker, result, rejectResult };
    worker.postMessage({
      action: "encrypt",
      plaintext: [],
      password: "cancel-browser-worker",
      options: { kdfProfile: "hardened-v1" },
      notifyStarted: true,
    });
    await started;
  },

  waitForCancelableWorker() {
    if (!cancelableOperation) {
      throw new Error("No cancelable operation is active");
    }
    return cancelableOperation.result;
  },

  cancelWorker() {
    if (!cancelableOperation) {
      throw new Error("No cancelable operation is active");
    }
    const { worker, rejectResult } = cancelableOperation;
    cancelableOperation = undefined;
    worker.terminate();
    const error = new Error("Worker operation aborted");
    error.name = "AbortError";
    rejectResult(error);
  },

  async startCancelableV2Worker(totalBytes, password) {
    if (cancelableV2Operation) {
      throw new Error("A cancelable V2 operation is already active");
    }
    const worker = createWorker();
    const id = crypto.randomUUID();
    let resolveStarted;
    let resolveResult;
    const started = new Promise((resolve) => {
      resolveStarted = resolve;
    });
    const result = new Promise((resolve) => {
      resolveResult = resolve;
    });

    worker.addEventListener("message", ({ data }) => {
      if (data.started && data.id === id) {
        resolveStarted();
        return;
      }
      cancelableV2Operation = undefined;
      resolveResult(data);
    });
    worker.addEventListener("error", (event) => {
      cancelableV2Operation = undefined;
      resolveResult({
        ok: false,
        error: { name: "Error", code: null, message: event.message },
        closing: false,
      });
    });
    cancelableV2Operation = { worker, id, result };
    worker.postMessage({ action: "startCancelableV2", id, totalBytes, password });
    await started;
  },

  waitForCancelableV2Worker() {
    if (!cancelableV2Operation) {
      throw new Error("No cancelable V2 operation is active");
    }
    return cancelableV2Operation.result;
  },

  cancelV2Worker() {
    if (!cancelableV2Operation) {
      throw new Error("No cancelable V2 operation is active");
    }
    cancelableV2Operation.worker.postMessage({
      action: "cancelV2",
      id: cancelableV2Operation.id,
    });
  },
};

document.querySelector("#ready").textContent = "ready";
