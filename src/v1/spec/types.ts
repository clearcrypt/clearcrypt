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

export type DecodedEnvelopeV1 = {
  header: V1Header;
  kdf: V1KdfParams;
  wrap: V1Wrap;
  aad: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
};

export type V1Wrap = {
  wrapCipherId: number;         // u8
  wrapNonce: Uint8Array;        // 12
  wrappedDekCiphertext: Uint8Array; // 32
  wrapTag: Uint8Array;          // 16
};
