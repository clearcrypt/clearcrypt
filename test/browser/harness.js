import {
  KDF_PROFILES_V1,
  decryptBytesV1,
  encryptBytesV1,
} from "../../dist/browser.js";

const toBytes = (values) => new Uint8Array(values);
const toValues = (bytes) => Array.from(bytes);

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

let cancelableOperation;

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
};

document.querySelector("#ready").textContent = "ready";
