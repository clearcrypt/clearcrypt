export type V2Header = {
  version: number;
  contentCipherId: number;
  contentKeyScheduleId: number;
  chunkSize: number;
  archiveId: Uint8Array;
  contentNoncePrefix: Uint8Array;
  passwordKdfId: number;
  passwordSalt: Uint8Array;
  timeCost: number;
  memoryCostKiB: number;
  parallelism: number;
  archiveKeyWrapCipherId: number;
  wrapNonce: Uint8Array;
  wrappedArchiveKeyCiphertext: Uint8Array;
  wrappedArchiveKeyTag: Uint8Array;
};

export type V2DataRecordHeader = {
  recordType: number;
  recordNumber: bigint;
  plaintextLength: number;
};

export type V2FinalRecordHeader = {
  recordType: number;
  dataRecordCount: bigint;
  totalPlaintextLength: bigint;
};
