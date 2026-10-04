import type { DecryptResourcePolicy } from "../v1/resource-policy";

export type V2Progress = {
  phase: "kdf" | "processing" | "finalizing";
  inputBytes: bigint;
  outputBytes: bigint;
  records: bigint;
};

export type V2OperationResult = {
  format: "CFENC002";
  inputBytes: bigint;
  outputBytes: bigint;
  records: bigint;
};

export type V2StreamOptions = {
  signal?: AbortSignal;
  onProgress?: (progress: V2Progress) => void;
};

export type V2EncryptKdfOptions = {
  timeCost?: number;
  memoryCostKiB?: number;
  parallelism?: number;
};

export type V2EncryptOptions = V2StreamOptions & {
  chunkSize?: number;
  kdf?: V2EncryptKdfOptions;
};

export type V2DecryptOptions = V2StreamOptions & {
  resourcePolicy?: Partial<DecryptResourcePolicy>;
};
