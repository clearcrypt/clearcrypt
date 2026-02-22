import { describe, expect, it } from "vitest";
import {
    aeadDecryptAes256Gcm,
    aeadEncryptAes256Gcm,
    importAesGcmKey,
} from "../src/v1/aead";
import { bytes } from "./helpers";

describe("AEAD AES-256-GCM", () => {
    it("roundtrip with associated Authenticated Data", async () => {
        const keyRaw = bytes(32, (i) => 0x11 + i);
        const key = await importAesGcmKey(keyRaw);

        const nonce = bytes(12, (i) => i + 1);
        const plaintext = new TextEncoder().encode("texte de mon test");
        const associatedAuthenticatedData = new TextEncoder().encode("header-bytes-go-here");

        const { ciphertext, tag } = await aeadEncryptAes256Gcm({
            key,
            nonce,
            plaintext,
            associatedAuthenticatedData,
        });

        const decrypted = await aeadDecryptAes256Gcm({
            key,
            nonce,
            ciphertext,
            tag,
            associatedAuthenticatedData,
        });

        expect([...decrypted]).toEqual([...plaintext]);
        expect(tag.length).toBe(16);
    });

    it("fails with wrong key", async () => {
        const key1 = await importAesGcmKey(bytes(32, (i) => 0x10 + i));
        const key2 = await importAesGcmKey(bytes(32, (i) => 0x20 + i));

        const nonce = bytes(12, (i) => 0xaa - i);
        const plaintext = bytes(50, (i) => i);
        const associatedAuthenticatedData = bytes(13, (i) => 0x55 + i);

        const { ciphertext, tag } = await aeadEncryptAes256Gcm({
            key: key1,
            nonce,
            plaintext,
            associatedAuthenticatedData,
        });

        await expect(
            aeadDecryptAes256Gcm({ key: key2, nonce, ciphertext, tag, associatedAuthenticatedData })
        ).rejects.toThrow();
    });

    it("fails if associatedAuthenticatedData is modified", async () => {
        const key = await importAesGcmKey(bytes(32, (i) => 0x33 + i));
        const nonce = bytes(12, (i) => i);
        const plaintext = bytes(32, (i) => 0xff - i);

        const associatedAuthenticatedData = bytes(20, (i) => i + 7);
        const { ciphertext, tag } = await aeadEncryptAes256Gcm({
            key,
            nonce,
            plaintext,
            associatedAuthenticatedData,
        });

        const badassociatedAuthenticatedData = associatedAuthenticatedData.slice();
        badassociatedAuthenticatedData[0] = (badassociatedAuthenticatedData[0]! ^ 0xff) & 0xff;

        await expect(
            aeadDecryptAes256Gcm({ key, nonce, ciphertext, tag, associatedAuthenticatedData: badassociatedAuthenticatedData })
        ).rejects.toThrow();
    });

    it("fails if ciphertext is tampered", async () => {
        const key = await importAesGcmKey(bytes(32, (i) => 0x44 + i));
        const nonce = bytes(12, (i) => 0x99 - i);
        const plaintext = bytes(128, (i) => i ^ 0x5a);

        const { ciphertext, tag } = await aeadEncryptAes256Gcm({
            key,
            nonce,
            plaintext,
            associatedAuthenticatedData: new Uint8Array(),
        });

        const tampered = ciphertext.slice();
        tampered[10] = (tampered[10]! ^ 0x01) & 0x01;

        await expect(
            aeadDecryptAes256Gcm({ key, nonce, ciphertext: tampered, tag })
        ).rejects.toThrow();
    });
});
