import { KDF_ARGON2ID } from "./spec/constants";
import type { V1KdfParams } from "./spec/types";
import { InvalidParamsError } from "./errors";

export const KDF_PROFILES_V1 = {
  "interactive-v1": {
    version: 1,
    timeCost: 2,
    memoryCost: 64 * 1024,
    parallelism: 2,
  },
  "hardened-v1": {
    version: 1,
    timeCost: 3,
    memoryCost: 128 * 1024,
    parallelism: 2,
  },
} as const;

export type VersionedKdfProfile = keyof typeof KDF_PROFILES_V1;
export type LegacyKdfProfile = "interactive" | "hardened";
export type KdfProfile = VersionedKdfProfile | LegacyKdfProfile;

export type V1KdfOptions = {
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
};

export type V1EncryptOptions = {
  kdfProfile?: KdfProfile;
  kdf?: V1KdfOptions;
};

const PROFILE_ALIASES: Record<LegacyKdfProfile, VersionedKdfProfile> = {
  interactive: "interactive-v1",
  hardened: "hardened-v1",
};

export function resolveV1KdfParams(
  salt: Uint8Array,
  options: V1EncryptOptions = {}
): V1KdfParams {
  const requestedProfile = options.kdfProfile ?? "interactive-v1";
  const profileName =
    (PROFILE_ALIASES as Record<string, VersionedKdfProfile | undefined>)[
      requestedProfile
    ] ?? requestedProfile;
  const profile = (
    KDF_PROFILES_V1 as Record<
      string,
      (typeof KDF_PROFILES_V1)[VersionedKdfProfile] | undefined
    >
  )[profileName];
  if (!profile) {
    throw new InvalidParamsError(
      `Unsupported KDF profile: ${String(requestedProfile)}`
    );
  }

  return {
    kdfId: KDF_ARGON2ID,
    salt,
    timeCost: options.kdf?.timeCost ?? profile.timeCost,
    memoryCost: options.kdf?.memoryCost ?? profile.memoryCost,
    parallelism: options.kdf?.parallelism ?? profile.parallelism,
  };
}
