import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import {
  ClearcryptFileInputError,
  ClearcryptFileOutputError,
  decryptFileV2,
  encryptFileV2,
} from "../src/node";
import { ClearcryptError } from "../src/index";
import { MIN_CHUNK_SIZE_V2 } from "../src/v2/spec/constants";

const FAST_KDF = { timeCost: 1, memoryCostKiB: 8 * 1024, parallelism: 1 };
const RESOURCE_POLICY = {
  maxMemoryCostKiB: 8 * 1024,
  maxTimeCost: 1,
  maxParallelism: 1,
};

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

describe("Node V2 file adapter", () => {
  let directory: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(process.cwd(), ".clearcrypt-file-v2-"));
  });

  afterAll(async () => {
    const workspace = resolve(process.cwd());
    const target = resolve(directory);
    const relativeTarget = relative(workspace, target);
    if (relativeTarget.startsWith("..") || isAbsolute(relativeTarget)) {
      throw new Error("Refusing to clean a test directory outside the workspace");
    }
    await rm(target, { recursive: true, force: true });
  });

  it("round-trips a file through bounded streaming and removes temporary files", async () => {
    const plaintext = bytes(MIN_CHUNK_SIZE_V2 * 3 + 17, 0x40);
    const input = join(directory, "input.bin");
    const encrypted = join(directory, "archive.cc2");
    const decrypted = join(directory, "output.bin");
    await writeFile(input, plaintext);

    const encryption = await encryptFileV2(input, encrypted, "password", {
      chunkSize: MIN_CHUNK_SIZE_V2,
      kdf: FAST_KDF,
    });
    const decryption = await decryptFileV2(encrypted, decrypted, "password", {
      resourcePolicy: RESOURCE_POLICY,
    });

    expect(new Uint8Array(await readFile(decrypted))).toEqual(plaintext);
    expect(encryption.records).toBe(4n);
    expect(decryption.records).toBe(4n);
    expect((await readdir(directory)).some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("keeps an existing destination unchanged after a wrong password", async () => {
    const input = join(directory, "archive.cc2");
    const destination = join(directory, "existing.bin");
    const sentinel = bytes(23, 0xa0);
    await writeFile(destination, sentinel);

    let received: unknown;
    try {
      await decryptFileV2(input, destination, "wrong-password", {
        resourcePolicy: RESOURCE_POLICY,
      });
    } catch (error) {
      received = error;
    }

    expect(received).toBeInstanceOf(ClearcryptError);
    expect((received as ClearcryptError).code).toBe("AUTH_FAILED");
    expect(new Uint8Array(await readFile(destination))).toEqual(sentinel);
    expect((await readdir(directory)).some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("keeps an existing destination unchanged when already cancelled", async () => {
    const input = join(directory, "input.bin");
    const destination = join(directory, "cancelled.bin");
    const sentinel = bytes(19, 0xb0);
    await writeFile(destination, sentinel);
    const controller = new AbortController();
    controller.abort("test cancellation");

    await expect(
      encryptFileV2(input, destination, "password", {
        signal: controller.signal,
        chunkSize: MIN_CHUNK_SIZE_V2,
        kdf: FAST_KDF,
      })
    ).rejects.toMatchObject({ code: "ABORTED" });
    expect(new Uint8Array(await readFile(destination))).toEqual(sentinel);
    expect((await readdir(directory)).some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("distinguishes input and output filesystem failures", async () => {
    await expect(
      encryptFileV2(
        join(directory, "missing.bin"),
        join(directory, "unused.cc2"),
        "password",
        { chunkSize: MIN_CHUNK_SIZE_V2, kdf: FAST_KDF }
      )
    ).rejects.toBeInstanceOf(ClearcryptFileInputError);

    await expect(
      encryptFileV2(
        join(directory, "input.bin"),
        join(directory, "missing-directory", "unused.cc2"),
        "password",
        { chunkSize: MIN_CHUNK_SIZE_V2, kdf: FAST_KDF }
      )
    ).rejects.toBeInstanceOf(ClearcryptFileOutputError);
  });
});
