import {
  normalizeArgon2Module,
  toArgon2BrowserParams,
} from "./types";
import type {
  Argon2BrowserModule,
  Argon2HashResult,
  Argon2idHashParams,
} from "./types";

const AUDITED_WASM_SHA256 =
  "0c2149886c13e4eae4a6ca25ee71d47423c5c8740a874cf04ff816d1b2c901d7";

type NodeRuntime = {
  module: Argon2BrowserModule;
  wasmByteLength: number;
  wasmSha256: string;
  loadWasmModule: () => Promise<unknown>;
};

let runtimePromise: Promise<NodeRuntime> | undefined;
let operationQueue: Promise<void> = Promise.resolve();

function withTemporaryGlobal<T>(
  name: string,
  value: unknown,
  callback: () => T
): T {
  const previous = Object.getOwnPropertyDescriptor(globalThis, name);
  Object.defineProperty(globalThis, name, {
    configurable: true,
    enumerable: previous?.enumerable ?? false,
    writable: true,
    value,
  });

  try {
    return callback();
  } finally {
    if (previous) {
      Object.defineProperty(globalThis, name, previous);
    } else {
      Reflect.deleteProperty(globalThis, name);
    }
  }
}

async function loadNodeRuntime(): Promise<NodeRuntime> {
  const [{ readFileSync }, { createHash }, { createRequire }] =
    await Promise.all([
      import("node:fs"),
      import("node:crypto"),
      import("node:module"),
    ]);
  const require = createRequire(import.meta.url);
  const wasmPath = require.resolve("argon2-browser/dist/argon2.wasm");
  const wasmBinary = new Uint8Array(readFileSync(wasmPath));
  const wasmSha256 = createHash("sha256").update(wasmBinary).digest("hex");

  if (!WebAssembly.validate(wasmBinary)) {
    throw new Error("argon2-browser contains an invalid WebAssembly module");
  }
  if (wasmSha256 !== AUDITED_WASM_SHA256) {
    throw new Error(
      "argon2-browser WebAssembly digest does not match the audited binary"
    );
  }

  const module = withTemporaryGlobal("self", globalThis, () =>
    normalizeArgon2Module(require("argon2-browser/lib/argon2.js"))
  );
  const loadWasmModule = (): Promise<unknown> =>
    withTemporaryGlobal(
      "self",
      { Module: { wasmBinary } },
      () => Promise.resolve(require("argon2-browser/dist/argon2.js"))
    );

  return {
    module,
    wasmByteLength: wasmBinary.byteLength,
    wasmSha256,
    loadWasmModule,
  };
}

function getNodeRuntime(): Promise<NodeRuntime> {
  runtimePromise ??= loadNodeRuntime();
  return runtimePromise;
}

export function hashArgon2idInNode(
  params: Argon2idHashParams
): Promise<Argon2HashResult> {
  const operation = operationQueue.then(async () => {
    const runtime = await getNodeRuntime();
    let pendingHash: Promise<Argon2HashResult> | undefined;

    withTemporaryGlobal(
      "loadArgon2WasmModule",
      runtime.loadWasmModule,
      () => {
        pendingHash = runtime.module.hash(toArgon2BrowserParams(params));
      }
    );

    if (!pendingHash) {
      throw new Error("argon2-browser did not start hashing");
    }
    return pendingHash;
  });
  operationQueue = operation.then(
    () => undefined,
    () => undefined
  );
  return operation;
}

export async function getNodeArgon2WasmMetadata(): Promise<{
  byteLength: number;
  sha256: string;
}> {
  const runtime = await getNodeRuntime();
  return {
    byteLength: runtime.wasmByteLength,
    sha256: runtime.wasmSha256,
  };
}
