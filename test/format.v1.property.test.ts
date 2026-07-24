import { describe, expect, it } from "vitest";
import fc from "fast-check";

import {
  decodeEnvelopeV1,
  decodeV1,
  decryptV1WithDek,
  encodeV1,
  encryptV1WithDek,
} from "../src/v1/format";
import type {
  V1Header,
  V1KdfParams,
  V1Wrap,
} from "../src/v1/spec/types";

const AAD_LENGTH = 109;
const MIN_ARCHIVE_LENGTH = 125;
const PROPERTY_SEED = 0x0cf001;

const fixedBytes = (length: number) =>
  fc.uint8Array({ minLength: length, maxLength: length });

const envelopeArbitrary = fc.record({
  header: fc.record({
    version: fc.constant(1),
    cipherId: fc.constant(1),
    nonce: fixedBytes(12),
  }),
  kdf: fc.record({
    kdfId: fc.constant(1),
    salt: fixedBytes(16),
    timeCost: fc.integer({ min: 1, max: 10 }),
    memoryCost: fc.integer({ min: 8 * 1024, max: 256 * 1024 }),
    parallelism: fc.integer({ min: 1, max: 16 }),
  }),
  wrap: fc.record({
    wrapCipherId: fc.constant(1),
    wrapNonce: fixedBytes(12),
    wrappedDekCiphertext: fixedBytes(32),
    wrapTag: fixedBytes(16),
  }),
  ciphertext: fc.uint8Array({ maxLength: 4096 }),
  tag: fixedBytes(16),
});

const encryptedEnvelopeArbitrary = fc.record({
  header: envelopeArbitrary.map(({ header }) => header),
  kdf: envelopeArbitrary.map(({ kdf }) => kdf),
  wrap: envelopeArbitrary.map(({ wrap }) => wrap),
  dek: fixedBytes(32),
  plaintext: fc.uint8Array({ maxLength: 1024 }),
});

describe("CFENC001 format properties", () => {
  it("round-trips every representable V1 field without copying parsed bytes", () => {
    fc.assert(
      fc.property(
        envelopeArbitrary,
        ({ header, kdf, wrap, ciphertext, tag }) => {
          const { bytes, aadLength } = encodeV1(
            header,
            kdf,
            wrap,
            ciphertext,
            tag
          );
          const decoded = decodeV1(bytes);
          const envelope = decodeEnvelopeV1(bytes);

          expect(aadLength).toBe(AAD_LENGTH);
          expect(decoded).toEqual({
            header,
            kdf,
            wrappedDek: wrap,
            ciphertext,
            authTag: tag,
          });
          for (const view of [
            envelope.aad,
            envelope.header.nonce,
            envelope.kdf.salt,
            envelope.wrap.wrapNonce,
            envelope.wrap.wrappedDekCiphertext,
            envelope.wrap.wrapTag,
            envelope.ciphertext,
            envelope.tag,
          ]) {
            expect(view.buffer).toBe(bytes.buffer);
          }
        }
      ),
      { numRuns: 500, seed: PROPERTY_SEED }
    );
  });

  it("encrypts and decrypts arbitrary binary payloads and metadata", async () => {
    await fc.assert(
      fc.asyncProperty(
        encryptedEnvelopeArbitrary,
        async ({ header, kdf, wrap, dek, plaintext }) => {
          const { bytes } = await encryptV1WithDek({
            header,
            kdf,
            wrappedDek: wrap,
            dek,
            plaintext,
          });
          const result = await decryptV1WithDek({ data: bytes, dek });

          expect(result.plaintext).toEqual(plaintext);
          expect(result.header).toEqual(header);
          expect(result.kdf).toEqual(kdf);
          expect(result.wrappedDek).toEqual(wrap);
        }
      ),
      { numRuns: 50, seed: PROPERTY_SEED }
    );
  });

  it("rejects a mutation in every fixed header field", async () => {
    const header: V1Header = {
      version: 1,
      cipherId: 1,
      nonce: Uint8Array.from({ length: 12 }, (_, index) => 0x10 + index),
    };
    const kdf: V1KdfParams = {
      kdfId: 1,
      salt: Uint8Array.from({ length: 16 }, (_, index) => 0x20 + index),
      timeCost: 2,
      memoryCost: 64 * 1024,
      parallelism: 2,
    };
    const wrap: V1Wrap = {
      wrapCipherId: 1,
      wrapNonce: Uint8Array.from({ length: 12 }, (_, index) => 0x30 + index),
      wrappedDekCiphertext: Uint8Array.from(
        { length: 32 },
        (_, index) => 0x40 + index
      ),
      wrapTag: Uint8Array.from({ length: 16 }, (_, index) => 0x60 + index),
    };
    const dek = Uint8Array.from({ length: 32 }, (_, index) => 0x80 + index);
    const { bytes } = await encryptV1WithDek({
      header,
      kdf,
      wrappedDek: wrap,
      dek,
      plaintext: Uint8Array.of(1, 2, 3, 4),
    });
    const fields = [
      ["magic", 0, 8],
      ["version", 8, 9],
      ["content cipher", 9, 10],
      ["content nonce", 10, 22],
      ["KDF", 22, 23],
      ["salt", 23, 39],
      ["time cost", 39, 43],
      ["memory cost", 43, 47],
      ["parallelism", 47, 48],
      ["wrap cipher", 48, 49],
      ["wrap nonce", 49, 61],
      ["wrapped DEK", 61, 93],
      ["wrapped DEK tag", 93, 109],
    ] as const;

    for (const [field, start, end] of fields) {
      for (let offset = start; offset < end; offset++) {
        const mutated = bytes.slice();
        mutated[offset] = mutated[offset]! ^ 1;
        await expect(
          decryptV1WithDek({ data: mutated, dek }),
          `${field} byte at offset ${offset}`
        ).rejects.toThrow();
      }
    }
  });

  it("rejects truncation at every offset before the complete archive", async () => {
    const dek = new Uint8Array(32);
    const { bytes } = await encryptV1WithDek({
      header: {
        version: 1,
        cipherId: 1,
        nonce: new Uint8Array(12),
      },
      kdf: {
        kdfId: 1,
        salt: new Uint8Array(16),
        timeCost: 1,
        memoryCost: 8 * 1024,
        parallelism: 1,
      },
      wrappedDek: {
        wrapCipherId: 1,
        wrapNonce: new Uint8Array(12),
        wrappedDekCiphertext: new Uint8Array(32),
        wrapTag: new Uint8Array(16),
      },
      dek,
      plaintext: new Uint8Array(32),
    });

    for (let offset = 0; offset < bytes.length; offset++) {
      await expect(
        decryptV1WithDek({ data: bytes.subarray(0, offset), dek }),
        `truncation at offset ${offset}`
      ).rejects.toThrow();
    }
    expect(bytes.length).toBe(MIN_ARCHIVE_LENGTH + 32);
  });

  it("parses extreme payload lengths as bounded zero-copy views", () => {
    for (const payloadLength of [0, 1, 1024, 1024 * 1024, 8 * 1024 * 1024]) {
      const archive = new Uint8Array(MIN_ARCHIVE_LENGTH + payloadLength);
      archive.set(new TextEncoder().encode("CFENC001"), 0);
      archive[8] = 1;

      const envelope = decodeEnvelopeV1(archive);
      expect(envelope.aad.byteLength).toBe(AAD_LENGTH);
      expect(envelope.ciphertext.byteLength).toBe(payloadLength);
      expect(envelope.tag.byteLength).toBe(16);
      expect(envelope.ciphertext.buffer).toBe(archive.buffer);
      expect(envelope.tag.buffer).toBe(archive.buffer);
    }
  });
});
