import { AES_GCM_TAG_LENGTH_BITS } from "./spec/constants";
import { getWebCrypto } from "./crypto-runtime";
import {
    AuthenticationError,
    CryptoOperationError,
    InvalidParamsError,
} from "./errors";

function toWebCryptoBytes(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  if (u8.buffer instanceof ArrayBuffer) {
    return u8 as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(u8);
}

function combineCiphertextAndTag(
    ciphertext: Uint8Array,
    tag: Uint8Array
): Uint8Array {
    if (
        ciphertext.buffer === tag.buffer &&
        ciphertext.byteOffset + ciphertext.byteLength === tag.byteOffset
    ) {
        return new Uint8Array(
            ciphertext.buffer,
            ciphertext.byteOffset,
            ciphertext.byteLength + tag.byteLength
        );
    }

    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.length);
    return combined;
}

export async function importAesGcmKey(raw32: Uint8Array): Promise<CryptoKey> {
    if (raw32.length !== 32) {
        throw new InvalidParamsError("AES-256-GCM key must be 32 bytes");
    }
    try {
        return await getWebCrypto().subtle.importKey(
            "raw",
            toWebCryptoBytes(raw32),
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );
    } catch (cause) {
        throw new CryptoOperationError("Unable to import AES-GCM key", cause);
    }
}

export async function aeadEncryptAes256Gcm(params: {
    key: CryptoKey;
    nonce: Uint8Array;
    plaintext: Uint8Array;
    associatedAuthenticatedData?: Uint8Array;
}): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
    const { key, nonce, plaintext, associatedAuthenticatedData } = params;

    if (nonce.length !== 12) {
        throw new InvalidParamsError("Nonce must be 12 bytes for AES-GCM (recommended/expected)");
    }

    const algorithmorithm: AesGcmParams = {
        name: "AES-GCM",
        iv: toWebCryptoBytes(nonce),
        tagLength: AES_GCM_TAG_LENGTH_BITS,
    };
    if (associatedAuthenticatedData && associatedAuthenticatedData.length > 0) {
        algorithmorithm.additionalData = toWebCryptoBytes(associatedAuthenticatedData);
    }

    let encrypted: ArrayBuffer;
    try {
        encrypted = await getWebCrypto().subtle.encrypt(
            algorithmorithm,
            key,
            toWebCryptoBytes(plaintext)
        );
    } catch (cause) {
        throw new CryptoOperationError("AES-GCM encryption failed", cause);
    }
    const out = new Uint8Array(encrypted);

    if (out.length < 16) {
        throw new CryptoOperationError("Invalid Authenticated Encryption with Associated Data (AEAD) output");
    }

    const tag = out.subarray(out.length - 16);
    const ciphertext = out.subarray(0, out.length - 16);

    return { ciphertext, tag };
}

export async function aeadDecryptAes256Gcm(params: {
    key: CryptoKey;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    tag: Uint8Array;
    associatedAuthenticatedData?: Uint8Array;
}): Promise<Uint8Array> {
    const { key, nonce, ciphertext, tag, associatedAuthenticatedData } = params;

    if (nonce.length !== 12) {
        throw new InvalidParamsError("Nonce must be 12 bytes for AES-GCM (recommended/expected)");
    }
    if (tag.length !== 16) {
        throw new InvalidParamsError("Auth tag must be 16 bytes");
    }

    const ciphertextTagCombined = combineCiphertextAndTag(ciphertext, tag);

    const algorithm: AesGcmParams = {
        name: "AES-GCM",
        iv: toWebCryptoBytes(nonce),
        tagLength: AES_GCM_TAG_LENGTH_BITS,
    };
    if (associatedAuthenticatedData && associatedAuthenticatedData.length > 0) {
        algorithm.additionalData = toWebCryptoBytes(associatedAuthenticatedData);
    }

    let plainTextBuf: ArrayBuffer;
    try {
        plainTextBuf = await getWebCrypto().subtle.decrypt(
            algorithm,
            key,
            toWebCryptoBytes(ciphertextTagCombined)
        );
    } catch (cause) {
        throw new AuthenticationError(cause);
    }
    return new Uint8Array(plainTextBuf);
}
