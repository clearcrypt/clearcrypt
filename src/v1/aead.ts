import { AES_GCM_TAG_LENGTH_BITS } from "./spec/constants";

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.slice().buffer;
}

export async function importAesGcmKey(raw32: Uint8Array): Promise<CryptoKey> {
    if (raw32.length !== 32) {
        throw new Error("AES-256-GCM key must be 32 bytes");
    }
    return crypto.subtle.importKey(
        "raw",
        toArrayBuffer(raw32),
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function aeadEncryptAes256Gcm(params: {
    key: CryptoKey;
    nonce: Uint8Array;
    plaintext: Uint8Array;
    associatedAuthenticatedData?: Uint8Array;
}): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
    const { key, nonce, plaintext, associatedAuthenticatedData } = params;

    if (nonce.length !== 12) {
        throw new Error("Nonce must be 12 bytes for AES-GCM (recommended/expected)");
    }

    const algorithmorithm: AesGcmParams = {
        name: "AES-GCM",
        iv: toArrayBuffer(nonce),
        tagLength: AES_GCM_TAG_LENGTH_BITS,
    };
    if (associatedAuthenticatedData && associatedAuthenticatedData.length > 0) {
        algorithmorithm.additionalData = toArrayBuffer(associatedAuthenticatedData);
    }

    const out = new Uint8Array(
        await crypto.subtle.encrypt(algorithmorithm, key, toArrayBuffer(plaintext))
    );

    if (out.length < 16) {
        throw new Error("Invalid Authenticated Encryption with Associated Data (AEAD) output");
    }

    const tag = out.slice(out.length - 16);
    const ciphertext = out.slice(0, out.length - 16);

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
        throw new Error("Nonce must be 12 bytes for AES-GCM (recommended/expected)");
    }
    if (tag.length !== 16) {
        throw new Error("Auth tag must be 16 bytes");
    }

    const ciphertextTagCombined = new Uint8Array(ciphertext.length + tag.length);
    ciphertextTagCombined.set(ciphertext, 0);
    ciphertextTagCombined.set(tag, ciphertext.length);

    const algorithm: AesGcmParams = {
        name: "AES-GCM",
        iv: toArrayBuffer(nonce),
        tagLength: AES_GCM_TAG_LENGTH_BITS,
    };
    if (associatedAuthenticatedData && associatedAuthenticatedData.length > 0) {
        algorithm.additionalData = toArrayBuffer(associatedAuthenticatedData);
    }

    const plainTextBuf = await crypto.subtle.decrypt(algorithm, key, ciphertextTagCombined);
    return new Uint8Array(plainTextBuf);
}
