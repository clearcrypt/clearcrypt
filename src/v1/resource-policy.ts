import type { V1KdfParams } from "./spec/types";
import { assertValidArgon2idParams } from "./kdf";

export type DecryptResourcePolicy = {
  maxMemoryCostKiB: number;
  maxTimeCost: number;
  maxParallelism: number;
};

export type V1DecryptOptions = {
  resourcePolicy?: Partial<DecryptResourcePolicy>;
};

export const DEFAULT_DECRYPT_RESOURCE_POLICY: DecryptResourcePolicy = {
  maxMemoryCostKiB: 128 * 1024,
  maxTimeCost: 4,
  maxParallelism: 4,
};

export class ResourcePolicyError extends Error {
  constructor() {
    super("Archive exceeds the local decryption resource policy");
    this.name = "ResourcePolicyError";
  }
}

export class InvalidResourcePolicyError extends Error {
  constructor(name: keyof DecryptResourcePolicy) {
    super(`${name} must be a positive integer`);
    this.name = "InvalidResourcePolicyError";
  }
}

export class InvalidArchiveKdfParamsError extends Error {
  readonly cause: unknown;

  constructor(cause: unknown) {
    super("Invalid Argon2id parameters in archive");
    this.name = "InvalidArchiveKdfParamsError";
    this.cause = cause;
  }
}

export function enforceDecryptResourcePolicy(
  kdf: V1KdfParams,
  overrides: Partial<DecryptResourcePolicy> = {}
): void {
  try {
    assertValidArgon2idParams(kdf);
  } catch (cause) {
    throw new InvalidArchiveKdfParamsError(cause);
  }

  const policy: DecryptResourcePolicy = {
    ...DEFAULT_DECRYPT_RESOURCE_POLICY,
    ...overrides,
  };

  for (const name of Object.keys(policy) as (keyof DecryptResourcePolicy)[]) {
    const value = policy[name];
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new InvalidResourcePolicyError(name);
    }
  }

  if (
    kdf.memoryCost > policy.maxMemoryCostKiB ||
    kdf.timeCost > policy.maxTimeCost ||
    kdf.parallelism > policy.maxParallelism
  ) {
    throw new ResourcePolicyError();
  }
}
