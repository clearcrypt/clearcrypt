import { passwordToBytes } from "./password";
import {
  CryptoOperationError,
  EnvironmentError,
  InvalidParamsError,
} from "./errors";
import {
  ARGON2_VERSION_DECIMAL,
  hashArgon2id,
} from "./argon2/runtime";
import { wipeBytesBestEffort } from "./memory";

const KEK_LENGTH_BYTES = 32;
export const MIN_TIME_COST = 1;
export const MAX_TIME_COST = 10;
export const MIN_MEMORY_COST_KIB = 8 * 1024;
export const MAX_MEMORY_COST_KIB = 256 * 1024;
export const MIN_PARALLELISM = 1;
export const MAX_PARALLELISM = 16;
export async function deriveKekArgon2id(params: {
  password: Uint8Array | string;
  salt: Uint8Array;
  timeCost: number;
  memoryCost: number;
  parallelism: number;
}): Promise<Uint8Array> {
  const { password, salt, timeCost, memoryCost, parallelism } = params;

  assertValidArgon2idParams({ salt, timeCost, memoryCost, parallelism });

  const ownsPasswordBytes = typeof password === "string";
  const pass = passwordToBytes(password);
  let result: { hash: Uint8Array | ArrayBuffer; encoded: string };
  try {
    result = await hashArgon2id({
      password: pass,
      salt,
      timeCost,
      memoryCostKiB: memoryCost,
      parallelism,
      hashLengthBytes: KEK_LENGTH_BYTES,
    });
  } catch (cause) {
    throw new EnvironmentError("Argon2id execution failed", cause);
  } finally {
    if (ownsPasswordBytes) {
      wipeBytesBestEffort(pass);
    }
  }

  const hash = result.hash instanceof Uint8Array
    ? result.hash
    : new Uint8Array(result.hash);
  try {
    if (!result.encoded.startsWith(`$argon2id$v=${ARGON2_VERSION_DECIMAL}$`)) {
      throw new CryptoOperationError(
        "Argon2id returned an unexpected algorithm or version"
      );
    }
    if (hash.length !== KEK_LENGTH_BYTES) {
      throw new CryptoOperationError("Argon2id returned an invalid key length");
    }
    return hash;
  } catch (error) {
    wipeBytesBestEffort(hash);
    throw error;
  }
}

export function assertValidArgon2idParams(params: {
  salt: Uint8Array;
  timeCost: number;
  memoryCost: number;
  parallelism: number;
}): void {
  const { salt, timeCost, memoryCost, parallelism } = params;
  if (salt.length !== 16) {
    throw new InvalidParamsError("Salt must be 16 bytes");
  }
  assertRange("timeCost", timeCost, MIN_TIME_COST, MAX_TIME_COST);
  assertRange("memoryCost", memoryCost, MIN_MEMORY_COST_KIB, MAX_MEMORY_COST_KIB);
  assertRange("parallelism", parallelism, MIN_PARALLELISM, MAX_PARALLELISM);
}

function assertRange(name: string, value: number, min: number, max: number): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new InvalidParamsError(`${name} must be an integer between ${min} and ${max}`);
  }
}
