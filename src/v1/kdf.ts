const ARGON2ID_FALLBACK = 2;
const KEK_LENGTH_BYTES = 32;
export const MIN_TIME_COST = 1;
export const MAX_TIME_COST = 10;
export const MIN_MEMORY_COST_KIB = 8 * 1024;
export const MAX_MEMORY_COST_KIB = 256 * 1024;
export const MIN_PARALLELISM = 1;
export const MAX_PARALLELISM = 16;
let argon2Module: any = null;
let nodeLoaderReady = false;

function toBytes(input: Uint8Array | string): Uint8Array {
  if (typeof input === "string") {
    return new TextEncoder().encode(input);
  }
  return input;
}

export async function deriveKekArgon2id(params: {
  password: Uint8Array | string;
  salt: Uint8Array;
  timeCost: number;
  memoryCost: number;
  parallelism: number;
}): Promise<Uint8Array> {
  const { password, salt, timeCost, memoryCost, parallelism } = params;

  assertValidArgon2idParams({ salt, timeCost, memoryCost, parallelism });

  if (!nodeLoaderReady && typeof process !== "undefined" && process.versions?.node) {
    const [{ readFileSync }, { createRequire }] = await Promise.all([
      import("node:fs"),
      import("node:module"),
    ]);
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("argon2-browser/dist/argon2.wasm");
    const wasmBinary = readFileSync(wasmPath);
    const globalAny = globalThis as {
      self?: unknown;
      loadArgon2WasmBinary?: () => Promise<Uint8Array>;
      Module?: { wasmBinary?: Uint8Array | ArrayBuffer };
    };
    globalAny.self = globalThis;
    globalAny.Module = globalAny.Module ?? {};
    globalAny.Module.wasmBinary = wasmBinary;
    globalAny.loadArgon2WasmBinary = () => Promise.resolve(new Uint8Array(wasmBinary));
    nodeLoaderReady = true;
  }

  if (!argon2Module) {
    if (typeof process !== "undefined" && process.versions?.node) {
      const { createRequire } = await import("node:module");
      const require = createRequire(import.meta.url);
      argon2Module = require("argon2-browser/lib/argon2.js");
    } else {
      argon2Module = await import("argon2-browser/lib/argon2.js");
    }
  }

  const pass = toBytes(password);
  const type = (argon2Module as any)?.ArgonType?.Argon2id ?? ARGON2ID_FALLBACK;

  const result = await argon2Module.hash({
    pass,
    salt,
    time: timeCost,
    mem: memoryCost,
    parallelism,
    hashLen: KEK_LENGTH_BYTES,
    type,
  });

  const hash = (result as { hash: Uint8Array | ArrayBuffer }).hash;
  return hash instanceof Uint8Array ? hash : new Uint8Array(hash);
}

export function assertValidArgon2idParams(params: {
  salt: Uint8Array;
  timeCost: number;
  memoryCost: number;
  parallelism: number;
}): void {
  const { salt, timeCost, memoryCost, parallelism } = params;
  if (salt.length !== 16) {
    throw new Error("Salt must be 16 bytes");
  }
  assertRange("timeCost", timeCost, MIN_TIME_COST, MAX_TIME_COST);
  assertRange("memoryCost", memoryCost, MIN_MEMORY_COST_KIB, MAX_MEMORY_COST_KIB);
  assertRange("parallelism", parallelism, MIN_PARALLELISM, MAX_PARALLELISM);
}

function assertRange(name: string, value: number, min: number, max: number): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
}
