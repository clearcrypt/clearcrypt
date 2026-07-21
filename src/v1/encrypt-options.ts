import { KDF_ARGON2ID } from "./spec/constants";
import type { V1KdfParams } from "./spec/types";

export type KdfProfile = "interactive" | "hardened";

export type V1KdfOptions = {
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
};

export type V1EncryptOptions = {
  kdfProfile?: KdfProfile;
  kdf?: V1KdfOptions;
};

const KDF_PROFILES: Record<KdfProfile, Omit<V1KdfParams, "kdfId" | "salt">> = {
  interactive: {
    timeCost: 2,
    memoryCost: 64 * 1024,
    parallelism: 2,
  },
  // Provisional until the cross-platform benchmarks planned for P1.2.
  hardened: {
    timeCost: 3,
    memoryCost: 128 * 1024,
    parallelism: 2,
  },
};

export function resolveV1KdfParams(
  salt: Uint8Array,
  options: V1EncryptOptions = {}
): V1KdfParams {
  const profileName = options.kdfProfile ?? "interactive";
  const profile = (KDF_PROFILES as Record<string, (typeof KDF_PROFILES)[KdfProfile]>)[profileName];
  if (!profile) {
    throw new Error(`Unsupported KDF profile: ${String(profileName)}`);
  }

  return {
    kdfId: KDF_ARGON2ID,
    salt,
    timeCost: options.kdf?.timeCost ?? profile.timeCost,
    memoryCost: options.kdf?.memoryCost ?? profile.memoryCost,
    parallelism: options.kdf?.parallelism ?? profile.parallelism,
  };
}
