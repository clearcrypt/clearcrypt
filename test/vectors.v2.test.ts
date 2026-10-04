import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { decryptStreamV2 } from "../src/index";
import { deriveKekArgon2id } from "../src/v1/kdf";
import { encryptStreamV2Internal } from "../src/v2/encrypt-stream";

type PlaintextDescriptor = {
  encoding: "hex" | "counter-mod-256";
  valueHex?: string;
  length: number;
  start?: number;
  sha256Hex: string;
};

type V2Vector = {
  name: string;
  format: "CFENC002";
  password: { value: string; utf8Hex: string };
  plaintext: PlaintextDescriptor;
  kdf: { timeCost: number; memoryCostKiB: number; parallelism: number };
  inputs: {
    archiveIdHex: string;
    contentNoncePrefixHex: string;
    passwordSaltHex: string;
    wrapNonceHex: string;
    archiveMasterKeyHex: string;
  };
  intermediates: {
    keySchedule: {
      segment0KeyHex: string;
      segment1KeyHex: string;
      finalKeyHex: string;
    };
    segmentTransition: {
      recordsPerSegment: string;
      before: { segmentNumber: string; localRecordNumber: string; nonceHex: string };
      after: { segmentNumber: string; localRecordNumber: string; nonceHex: string };
    };
  };
  records: Array<{ plaintextLength: number }>;
  archiveLength: number;
  archiveBase64: string;
};

const vectorPaths = [
  resolve("test/vectors/v2/empty.json"),
  resolve("test/vectors/v2/unicode-binary.json"),
  resolve("test/vectors/v2/multiple-blocks.json"),
];

const fromHex = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, "hex"));

function plaintextFromDescriptor(descriptor: PlaintextDescriptor): Uint8Array {
  if (descriptor.encoding === "hex") return fromHex(descriptor.valueHex ?? "");
  return Uint8Array.from(
    { length: descriptor.length },
    (_, index) => ((descriptor.start ?? 0) + index) & 0xff
  );
}

function readable(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

function destination(): {
  stream: WritableStream<Uint8Array>;
  bytes: () => Uint8Array;
} {
  const chunks: Uint8Array[] = [];
  let length = 0;
  return {
    stream: new WritableStream({
      write(chunk) {
        chunks.push(chunk.slice());
        length += chunk.length;
      },
    }),
    bytes() {
      const result = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
      }
      return result;
    },
  };
}

function deterministicRandom(vector: V2Vector): (length: number) => Uint8Array {
  const values = [
    fromHex(vector.inputs.archiveIdHex),
    fromHex(vector.inputs.contentNoncePrefixHex),
    fromHex(vector.inputs.passwordSaltHex),
    fromHex(vector.inputs.wrapNonceHex),
    fromHex(vector.inputs.archiveMasterKeyHex),
  ];
  return (length) => {
    const value = values.shift();
    if (!value || value.length !== length) throw new Error("Unexpected random request");
    return value;
  };
}

describe("CFENC002 normative vectors", () => {
  let vectors: V2Vector[];
  let temporaryDirectory: string;

  beforeAll(async () => {
    vectors = await Promise.all(
      vectorPaths.map(async (path) => JSON.parse(await readFile(path, "utf8")) as V2Vector)
    );
    temporaryDirectory = await mkdtemp(join(process.cwd(), ".clearcrypt-v2-vectors-"));
  });

  afterAll(async () => {
    const workspace = resolve(process.cwd());
    const target = resolve(temporaryDirectory);
    const relativeTarget = relative(workspace, target);
    if (relativeTarget.startsWith("..") || isAbsolute(relativeTarget)) {
      throw new Error("Refusing to clean a vector test directory outside the workspace");
    }
    await rm(target, { recursive: true, force: true });
  });

  it("is reproduced and decrypted by the independent primitive-only verifier", () => {
    const output = execFileSync(
      process.execPath,
      [resolve("scripts/verify-v2-vectors.mjs")],
      { cwd: process.cwd(), encoding: "utf8" }
    );
    expect(output.trim().split(/\r?\n/)).toEqual(
      vectors.map((vector) => `verified ${vector.name}`)
    );
  });

  it.each([0, 1, 2])("matches ClearCrypt encryption and decryption for vector %i", async (index) => {
    const vector = vectors[index]!;
    const plaintext = plaintextFromDescriptor(vector.plaintext);
    const encrypted = destination();
    await encryptStreamV2Internal(
      readable(plaintext),
      encrypted.stream,
      vector.password.value,
      {
        chunkSize: 65_536,
        kdf: vector.kdf,
      },
      {
        randomBytes: deterministicRandom(vector),
        deriveKek: deriveKekArgon2id,
      }
    );
    expect(Buffer.from(encrypted.bytes()).toString("base64")).toBe(vector.archiveBase64);

    const decrypted = destination();
    await decryptStreamV2(
      readable(new Uint8Array(Buffer.from(vector.archiveBase64, "base64"))),
      decrypted.stream,
      vector.password.value,
      {
        resourcePolicy: {
          maxMemoryCostKiB: vector.kdf.memoryCostKiB,
          maxTimeCost: vector.kdf.timeCost,
          maxParallelism: vector.kdf.parallelism,
        },
      }
    );
    expect(decrypted.bytes()).toEqual(plaintext);
    expect(createHash("sha256").update(plaintext).digest("hex")).toBe(
      vector.plaintext.sha256Hex
    );
  });

  it("documents distinct segment-zero, segment-one, and FINAL derivations", () => {
    for (const vector of vectors) {
      const schedule = vector.intermediates.keySchedule;
      expect(new Set([
        schedule.segment0KeyHex,
        schedule.segment1KeyHex,
        schedule.finalKeyHex,
      ]).size).toBe(3);
      expect(vector.intermediates.segmentTransition).toMatchObject({
        recordsPerSegment: "16384",
        before: { segmentNumber: "0", localRecordNumber: "16383" },
        after: { segmentNumber: "1", localRecordNumber: "0" },
      });
    }
  });

  it("rejects a vector whose expected archive has one altered significant byte", async () => {
    const vector = structuredClone(vectors[1]!);
    const archive = Buffer.from(vector.archiveBase64, "base64");
    archive[140] = archive[140]! ^ 0x01;
    vector.archiveBase64 = archive.toString("base64");
    const path = join(temporaryDirectory, "altered.json");
    await writeFile(path, JSON.stringify(vector));

    expect(() =>
      execFileSync(
        process.execPath,
        [resolve("scripts/verify-v2-vectors.mjs"), path],
        { cwd: process.cwd(), encoding: "utf8", stdio: "pipe" }
      )
    ).toThrow();
  });
});
