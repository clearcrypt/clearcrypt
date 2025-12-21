export interface V1Header {
  version: number;
  cipherId: number;
  nonce: Uint8Array; // 12 bytes
}

export interface V1KdfParams {
  kdfId: number;
  salt: Uint8Array; // 16 bytes
  timeCost: number;
  memoryCost: number;
  parallelism: number;
}

export interface V1Decoded {
  header: V1Header;
  kdf: V1KdfParams;
  wrappedDek: Uint8Array; // 32 bytes
  ciphertext: Uint8Array;
  authTag: Uint8Array; // 16 bytes
}