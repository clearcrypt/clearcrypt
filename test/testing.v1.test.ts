import { describe, expect, it } from "vitest";
import { encryptBytesV1DeterministicForTests } from "../src/v1/testing";
import { bytes } from "./helpers";

describe("V1 internal deterministic encryption helper", () => {
  it("produces identical archives from identical fixed test inputs", async () => {
    const plaintext = bytes(32, (i) => i * 3);
    const options = {
      nonce: bytes(12, (i) => 0x10 + i),
      salt: bytes(16, (i) => 0x20 + i),
      wrapNonce: bytes(12, (i) => 0x30 + i),
      dek: bytes(32, (i) => 0x40 + i),
      kdf: { timeCost: 1, memoryCost: 8 * 1024, parallelism: 1 },
    };

    const first = await encryptBytesV1DeterministicForTests(
      plaintext,
      "vector-password",
      options
    );
    const second = await encryptBytesV1DeterministicForTests(
      plaintext,
      "vector-password",
      options
    );

    expect(first).toEqual(second);
  });
});
