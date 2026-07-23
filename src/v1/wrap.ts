import { aeadDecryptAes256Gcm, aeadEncryptAes256Gcm, importAesGcmKey } from "./aead";
import { CIPHER_AES_256_GCM } from "./spec/constants";
import type { V1Wrap } from "./spec/types";
import {
  CryptoOperationError,
  InvalidParamsError,
  UnsupportedAlgorithmError,
} from "./errors";

export async function wrapDekWithKek(params: {
  dek: Uint8Array;        // 32 bytes
  kekRaw32: Uint8Array;   // 32 bytes
  wrapNonce: Uint8Array;  // 12 bytes
}): Promise<V1Wrap> {
  const { dek, kekRaw32, wrapNonce } = params;

  if (dek.length !== 32) throw new InvalidParamsError("DEK must be 32 bytes");
  if (wrapNonce.length !== 12) throw new InvalidParamsError("Wrap nonce must be 12 bytes");

  const key = await importAesGcmKey(kekRaw32);
  const { ciphertext, tag } = await aeadEncryptAes256Gcm({
    key,
    nonce: wrapNonce,
    plaintext: dek,
    associatedAuthenticatedData: new Uint8Array(),
  });

  if (ciphertext.length !== 32) {
    throw new CryptoOperationError("Wrapped DEK ciphertext must be 32 bytes");
  }

  return {
    wrapCipherId: CIPHER_AES_256_GCM,
    wrapNonce,
    wrappedDekCiphertext: ciphertext,
    wrapTag: tag,
  };
}

export async function unwrapDekWithKek(params: {
  wrap: V1Wrap;
  kekRaw32: Uint8Array;
}): Promise<Uint8Array> {
  const { wrap, kekRaw32 } = params;

  if (wrap.wrapCipherId !== CIPHER_AES_256_GCM) {
    throw new UnsupportedAlgorithmError("Unsupported wrap cipher");
  }

  const key = await importAesGcmKey(kekRaw32);
  const dek = await aeadDecryptAes256Gcm({
    key,
    nonce: wrap.wrapNonce,
    ciphertext: wrap.wrappedDekCiphertext,
    tag: wrap.wrapTag,
    associatedAuthenticatedData: new Uint8Array(),
  });

  if (dek.length !== 32) {
    throw new CryptoOperationError("Unwrapped DEK must be 32 bytes");
  }

  return dek;
}
