import {
  decryptStreamV2,
  encryptStreamV2,
  type V2DecryptOptions,
  type V2EncryptOptions,
  type V2OperationResult,
  type V2Progress,
} from "../src/index";

const source = new ReadableStream<Uint8Array>();
const destination = new WritableStream<Uint8Array>();
const abortController = new AbortController();

const encryptOptions: V2EncryptOptions = {
  chunkSize: 4 * 1024 * 1024,
  kdf: { timeCost: 2, memoryCostKiB: 64 * 1024, parallelism: 2 },
  signal: abortController.signal,
  onProgress(progress: V2Progress) {
    const bytes: bigint = progress.outputBytes;
    void bytes;
  },
};
const decryptOptions: V2DecryptOptions = {
  signal: abortController.signal,
  resourcePolicy: {
    maxMemoryCostKiB: 128 * 1024,
    maxTimeCost: 4,
    maxParallelism: 4,
  },
};

const encryption: Promise<V2OperationResult> = encryptStreamV2(
  source,
  destination,
  "password",
  encryptOptions
);
const decryption: Promise<V2OperationResult> = decryptStreamV2(
  source,
  destination,
  new Uint8Array([1]),
  decryptOptions
);

const invalidKdf: V2EncryptOptions = {
  // @ts-expect-error V2 names the encoded memory setting memoryCostKiB.
  kdf: { memoryCost: 64 * 1024 },
};
const invalidDecrypt: V2DecryptOptions = {
  // @ts-expect-error Unknown resource policy fields are rejected.
  resourcePolicy: { maxCpuTime: 10 },
};

// @ts-expect-error Internal dependency injection is not part of the public API.
encryptStreamV2(source, destination, "password", {}, { randomBytes: () => new Uint8Array() });

void [encryption, decryption, invalidKdf, invalidDecrypt];
