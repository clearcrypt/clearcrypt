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
  wrappedDek: V1Wrap;
  ciphertext: Uint8Array;
  authTag: Uint8Array; // 16 bytes
}

export type V1Metadata = {
  header: V1Header;
  kdf: V1KdfParams;
  wrappedDek: V1Wrap;
};

export type V1Wrap = {
  wrapCipherId: number;         // u8
  wrapNonce: Uint8Array;        // 12
  wrappedDekCiphertext: Uint8Array; // 32
  wrapTag: Uint8Array;          // 16
};
