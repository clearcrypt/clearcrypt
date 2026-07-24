import { describe, expect, it } from "vitest";

import { KDF_PROFILES_V1 } from "../src/index";
import { resolveV1KdfParams } from "../src/v1/encrypt-options";

const salt = new Uint8Array(16);

describe("V1 KDF profiles", () => {
  it("uses interactive-v1 by default", () => {
    const profile = KDF_PROFILES_V1["interactive-v1"];
    expect(resolveV1KdfParams(salt)).toEqual({
      kdfId: 1,
      salt,
      timeCost: profile.timeCost,
      memoryCost: profile.memoryCost,
      parallelism: profile.parallelism,
    });
  });

  it.each([
    ["interactive", "interactive-v1"],
    ["hardened", "hardened-v1"],
  ] as const)("keeps the %s compatibility alias", (alias, canonical) => {
    expect(resolveV1KdfParams(salt, { kdfProfile: alias })).toEqual(
      resolveV1KdfParams(salt, { kdfProfile: canonical })
    );
  });

  it("applies explicit values over a versioned profile", () => {
    expect(
      resolveV1KdfParams(
        salt,
        {
          kdfProfile: "hardened-v1",
          kdf: { timeCost: 4, parallelism: 1 },
        }
      )
    ).toEqual({
      kdfId: 1,
      memoryCost: KDF_PROFILES_V1["hardened-v1"].memoryCost,
      timeCost: 4,
      parallelism: 1,
      salt,
    });
  });
});
