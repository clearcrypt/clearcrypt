import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { decryptBytesV1 } from "../src/index";
import { decodeEnvelopeV1 } from "../src/v1/format";
import { deriveKekArgon2id } from "../src/v1/kdf";
import { encryptBytesV1DeterministicForTests } from "../src/v1/testing";
import { wrapDekWithKek } from "../src/v1/wrap";

type V1Vector = {
  name: string;
  format: "CFENC001";
  password: { value: string; utf8Hex: string };
  plaintextHex: string;
  expectedPlaintextHex: string;
  kdf: {
    algorithmId: number;
    version: number;
    saltHex: string;
    timeCost: number;
    memoryCostKiB: number;
    parallelism: number;
    outputLengthBytes: number;
  };
  kekHex: string;
  dekHex: string;
  wrappedDek: {
    algorithmId: number;
    nonceHex: string;
    ciphertextHex: string;
    tagHex: string;
  };
  contentEncryption: {
    algorithmId: number;
    nonceHex: string;
    ciphertextHex: string;
    tagHex: string;
  };
  aadHex: string;
  archiveHex: string;
  archiveBase64: string;
};

const fromHex = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, "hex"));
const toHex = (value: Uint8Array): string => Buffer.from(value).toString("hex");
const vectorPath = resolve(
  "test/vectors/v1/unicode-password-binary-plaintext.json"
);
const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as V1Vector;

describe("CFENC001 deterministic vectors", () => {
  it("matches every documented intermediate and final value", async () => {
    const passwordBytes = new TextEncoder().encode(vector.password.value);
    expect(toHex(passwordBytes)).toBe(vector.password.utf8Hex);

    const salt = fromHex(vector.kdf.saltHex);
    const kek = await deriveKekArgon2id({
      password: passwordBytes,
      salt,
      timeCost: vector.kdf.timeCost,
      memoryCost: vector.kdf.memoryCostKiB,
      parallelism: vector.kdf.parallelism,
    });
    expect(toHex(kek)).toBe(vector.kekHex);

    const dek = fromHex(vector.dekHex);
    const wrapNonce = fromHex(vector.wrappedDek.nonceHex);
    const wrap = await wrapDekWithKek({ dek, kekRaw32: kek, wrapNonce });
    expect(toHex(wrap.wrappedDekCiphertext)).toBe(
      vector.wrappedDek.ciphertextHex
    );
    expect(toHex(wrap.wrapTag)).toBe(vector.wrappedDek.tagHex);

    const archive = await encryptBytesV1DeterministicForTests(
      fromHex(vector.plaintextHex),
      passwordBytes,
      {
        salt,
        nonce: fromHex(vector.contentEncryption.nonceHex),
        wrapNonce,
        dek,
        kdf: {
          timeCost: vector.kdf.timeCost,
          memoryCost: vector.kdf.memoryCostKiB,
          parallelism: vector.kdf.parallelism,
        },
      }
    );
    expect(toHex(archive)).toBe(vector.archiveHex);
    expect(Buffer.from(archive).toString("base64")).toBe(vector.archiveBase64);

    const envelope = decodeEnvelopeV1(archive);
    expect(toHex(envelope.aad)).toBe(vector.aadHex);
    expect(toHex(envelope.ciphertext)).toBe(
      vector.contentEncryption.ciphertextHex
    );
    expect(toHex(envelope.tag)).toBe(vector.contentEncryption.tagHex);

    const plaintext = await decryptBytesV1(archive, passwordBytes);
    expect(toHex(plaintext)).toBe(vector.expectedPlaintextHex);
  });

  it("is verified by the independent primitive-only implementation", () => {
    const output = execFileSync(
      process.execPath,
      [resolve("scripts/verify-v1-vector.mjs"), vectorPath],
      { cwd: process.cwd(), encoding: "utf8" }
    );

    expect(output.trim()).toBe(`verified ${vector.name}`);
  });
});
