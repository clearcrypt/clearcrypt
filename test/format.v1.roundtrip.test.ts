import { describe, expect, it } from "vitest";
import {
  decodeV1,
  decryptV1WithDek,
  decryptV1WithKek,
  decryptV1WithPassword,
  encodeAadV1,
  encodeV1,
  encryptV1WithDek,
  encryptV1WithKek,
  encryptV1WithPassword,
} from "../src/v1/format";
import { Writer } from "../src/v1/writer";
import { bytes, makeHeader, makeKdf, makeWrap } from "./helpers";

describe("V1 format", () => {

  it("rejects invalid AAD field lengths", () => {
    const baseHeader = makeHeader();
    const baseKdf = makeKdf();
    const baseWrap = makeWrap();

    const cases = [
      {
        label: "nonce",
        header: makeHeader({ nonce: new Uint8Array(11) }),
        kdf: baseKdf,
        wrap: baseWrap,
        pattern: /nonce/i,
      },
      {
        label: "salt",
        header: baseHeader,
        kdf: makeKdf({ salt: new Uint8Array(15) }),
        wrap: baseWrap,
        pattern: /salt/i,
      },
      {
        label: "wrap nonce",
        header: baseHeader,
        kdf: baseKdf,
        wrap: makeWrap({ wrapNonce: new Uint8Array(11) }),
        pattern: /wrapped dek nonce/i,
      },
      {
        label: "wrapped DEK ciphertext",
        header: baseHeader,
        kdf: baseKdf,
        wrap: makeWrap({ wrappedDekCiphertext: new Uint8Array(31) }),
        pattern: /wrapped dek must be 32 bytes/i,
      },
      {
        label: "wrap tag",
        header: baseHeader,
        kdf: baseKdf,
        wrap: makeWrap({ wrapTag: new Uint8Array(15) }),
        pattern: /wrapped dek tag/i,
      },
    ];

    for (const c of cases) {
      expect(() => encodeAadV1(c.header, c.kdf, c.wrap, new Writer())).toThrow(c.pattern);
    }
  });

  it("rejects invalid auth tag length", () => {
    const header = makeHeader();
    const kdf = makeKdf();
    const wrappedDek = makeWrap();
    const ciphertext = bytes(8, (i) => i);
    const authTag = new Uint8Array(15);

    expect(() => encodeV1(header, kdf, wrappedDek, ciphertext, authTag)).toThrow(/auth tag/i);
  });

  it("encodes then decodes the same fields", () => {
    const header = makeHeader();
    const kdf = makeKdf();

    const wrappedDek = makeWrap();
    const ciphertext = bytes(50, (i) => 0x55 ^ i);
    const authTag = bytes(16, (i) => 0xee - i);

    const { bytes: encoded, aadLength } = encodeV1(header, kdf, wrappedDek, ciphertext, authTag);
    const decoded = decodeV1(encoded);

    expect(aadLength).toBeGreaterThan(0);

    expect(decoded.header.version).toBe(header.version);
    expect(decoded.header.cipherId).toBe(header.cipherId);
    expect([...decoded.header.nonce]).toEqual([...header.nonce]);

    expect(decoded.kdf.kdfId).toBe(kdf.kdfId);
    expect([...decoded.kdf.salt]).toEqual([...kdf.salt]);
    expect(decoded.kdf.timeCost).toBe(kdf.timeCost);
    expect(decoded.kdf.memoryCost).toBe(kdf.memoryCost);
    expect(decoded.kdf.parallelism).toBe(kdf.parallelism);

    expect(decoded.wrappedDek.wrapCipherId).toBe(wrappedDek.wrapCipherId);
    expect([...decoded.wrappedDek.wrapNonce]).toEqual([...wrappedDek.wrapNonce]);
    expect([...decoded.wrappedDek.wrappedDekCiphertext]).toEqual([...wrappedDek.wrappedDekCiphertext]);
    expect([...decoded.wrappedDek.wrapTag]).toEqual([...wrappedDek.wrapTag]);
    expect([...decoded.ciphertext]).toEqual([...ciphertext]);
    expect([...decoded.authTag]).toEqual([...authTag]);
  });

  it("rejects invalid magic/version", () => {
    const header = makeHeader({ nonce: new Uint8Array(12) });
    const kdf = makeKdf({ salt: new Uint8Array(16) });

    const wrappedDek = makeWrap({
      wrapNonce: new Uint8Array(12),
      wrappedDekCiphertext: new Uint8Array(32),
      wrapTag: new Uint8Array(16),
    });
    const ciphertext = new Uint8Array([1, 2, 3]);
    const authTag = new Uint8Array(16);

    const { bytes: encoded } = encodeV1(header, kdf, wrappedDek, ciphertext, authTag);


    const corruptedMagic = encoded.slice();
    corruptedMagic[0] = corruptedMagic[0]! ^ 0xff;
    expect(() => decodeV1(corruptedMagic)).toThrow(/magic/i);


    const corruptedVersion = encoded.slice();
    corruptedVersion[8] = 0xff;
    expect(() => decodeV1(corruptedVersion)).toThrow(/version/i);
  });

  it("rejects payload shorter than auth tag", () => {

    const header = makeHeader({ nonce: new Uint8Array(12) });
    const kdf = makeKdf({ salt: new Uint8Array(16) });
    const wrappedDek = makeWrap({
      wrapNonce: new Uint8Array(12),
      wrappedDekCiphertext: new Uint8Array(32),
      wrapTag: new Uint8Array(16),
    });

    const { bytes: encoded } = encodeV1(header, kdf, wrappedDek, new Uint8Array(0), new Uint8Array(16));

    const truncated = encoded.slice(0, encoded.length - 10);
    expect(() => decodeV1(truncated)).toThrow(/payload/i);
  });

  it("rejects truncated header", () => {
    const header = makeHeader();
    const kdf = makeKdf();
    const wrappedDek = makeWrap();
    const ciphertext = bytes(10, (i) => i);
    const authTag = bytes(16, (i) => 0xaa - i);

    const { bytes: encoded } = encodeV1(header, kdf, wrappedDek, ciphertext, authTag);
    const truncated = encoded.slice(0, 10);

    expect(() => decodeV1(truncated)).toThrow(/unexpected end of file/i);
  });

  it("rejects header truncation at multiple offsets", () => {
    const header = makeHeader();
    const kdf = makeKdf();
    const wrappedDek = makeWrap();
    const ciphertext = bytes(4, (i) => i);
    const authTag = bytes(16, (i) => 0xf0 - i);

    const { bytes: encoded } = encodeV1(header, kdf, wrappedDek, ciphertext, authTag);

    const offsets = [
      7,   // during magic
      9,   // version + cipherId
      15,  // nonce
      25,  // kdf id + salt
      35,  // kdf params
      45,  // wrapCipherId + wrapNonce
      60,  // wrapped DEK ciphertext
      70,  // wrap tag
    ];

    for (const offset of offsets) {
      const truncated = encoded.slice(0, offset);
      expect(() => decodeV1(truncated)).toThrow(/unexpected end of file/i);
    }
  });
});

describe("V1 encryption", () => {

  it("encrypts then decrypts with DEK", async () => {
    const header = makeHeader();
    const kdf = makeKdf();

    const wrappedDek = makeWrap();
    const dek = bytes(32, (i) => 0x55 ^ i);
    const plaintext = bytes(64, (i) => 0xff - i);

    const { bytes: encoded, aadLength } = await encryptV1WithDek({
      header,
      kdf,
      wrappedDek,
      dek,
      plaintext,
    });

    expect(aadLength).toBeGreaterThan(0);

    const { plaintext: decrypted, header: decodedHeader, kdf: decodedKdf, wrappedDek: decodedWrappedDek } =
      await decryptV1WithDek({ data: encoded, dek });

    expect([...decrypted]).toEqual([...plaintext]);
    expect(decodedHeader.version).toBe(header.version);
    expect(decodedHeader.cipherId).toBe(header.cipherId);
    expect([...decodedHeader.nonce]).toEqual([...header.nonce]);
    expect(decodedKdf.kdfId).toBe(kdf.kdfId);
    expect([...decodedKdf.salt]).toEqual([...kdf.salt]);
    expect(decodedKdf.timeCost).toBe(kdf.timeCost);
    expect(decodedKdf.memoryCost).toBe(kdf.memoryCost);
    expect(decodedKdf.parallelism).toBe(kdf.parallelism);
    expect(decodedWrappedDek.wrapCipherId).toBe(wrappedDek.wrapCipherId);
    expect([...decodedWrappedDek.wrapNonce]).toEqual([...wrappedDek.wrapNonce]);
    expect([...decodedWrappedDek.wrappedDekCiphertext]).toEqual([...wrappedDek.wrappedDekCiphertext]);
    expect([...decodedWrappedDek.wrapTag]).toEqual([...wrappedDek.wrapTag]);
  });

  it("fails if nonce is tampered", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x10 + i) });
    const kdf = makeKdf({ salt: bytes(16, (i) => 0x20 + i) });

    const wrappedDek = makeWrap({ wrappedDekCiphertext: bytes(32, (i) => 0x30 + i) });
    const dek = bytes(32, (i) => 0x40 + i);
    const plaintext = bytes(32, (i) => 0xaa - i);

    const { bytes: encoded } = await encryptV1WithDek({
      header,
      kdf,
      wrappedDek,
      dek,
      plaintext,
    });

    const tampered = encoded.slice();
    tampered[10] = (tampered[10]! ^ 0xff) & 0xff;

    await expect(decryptV1WithDek({ data: tampered, dek })).rejects.toThrow();
  });

  it("fails if ciphertext is tampered", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x60 + i) });
    const kdf = makeKdf({ salt: bytes(16, (i) => 0x70 + i) });

    const wrappedDek = makeWrap({ wrappedDekCiphertext: bytes(32, (i) => 0x80 + i) });
    const dek = bytes(32, (i) => 0x90 + i);
    const plaintext = bytes(48, (i) => i ^ 0x5a);

    const { bytes: encoded, aadLength } = await encryptV1WithDek({
      header,
      kdf,
      wrappedDek,
      dek,
      plaintext,
    });

    const tampered = encoded.slice();
    tampered[aadLength] = (tampered[aadLength]! ^ 0x01) & 0xff;

    await expect(decryptV1WithDek({ data: tampered, dek })).rejects.toThrow();
  });

  it("fails if DEK is wrong", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x11 + i) });
    const kdf = makeKdf({ salt: bytes(16, (i) => 0x22 + i) });

    const wrappedDek = makeWrap({ wrappedDekCiphertext: bytes(32, (i) => 0x33 + i) });
    const dek = bytes(32, (i) => 0x44 + i);
    const wrongDek = bytes(32, (i) => 0x55 + i);
    const plaintext = bytes(40, (i) => i ^ 0xa5);

    const { bytes: encoded } = await encryptV1WithDek({
      header,
      kdf,
      wrappedDek,
      dek,
      plaintext,
    });

    await expect(decryptV1WithDek({ data: encoded, dek: wrongDek })).rejects.toThrow();
  });

  it("fails if AAD is altered (wrapped DEK)", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x66 + i) });
    const kdf = makeKdf({ salt: bytes(16, (i) => 0x77 + i) });

    const wrappedDek = makeWrap({ wrappedDekCiphertext: bytes(32, (i) => 0x88 + i) });
    const dek = bytes(32, (i) => 0x99 + i);
    const plaintext = bytes(52, (i) => 0x5a ^ i);

    const { bytes: encoded, aadLength } = await encryptV1WithDek({
      header,
      kdf,
      wrappedDek,
      dek,
      plaintext,
    });

    const tampered = encoded.slice();
    const wrappedDekOffset = aadLength - (16 + 32);
    tampered[wrappedDekOffset] = (tampered[wrappedDekOffset]! ^ 0xff) & 0xff;

    await expect(decryptV1WithDek({ data: tampered, dek })).rejects.toThrow();
  });

  it("fails if cipher is unsupported", async () => {
    const header = makeHeader({ cipherId: 0x99 });
    const kdf = makeKdf();
    const wrappedDek = makeWrap();
    const ciphertext = bytes(12, (i) => i ^ 0x2a);
    const authTag = bytes(16, (i) => 0xee - i);

    const { bytes: encoded } = encodeV1(header, kdf, wrappedDek, ciphertext, authTag);

    await expect(decryptV1WithDek({ data: encoded, dek: bytes(32, (i) => i) })).rejects.toThrow(
      /unsupported cipher/i
    );
  });
});

describe("V1 encryption with KEK", () => {

  it("encrypts then decrypts with KEK", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x10 + i) });
    const kdf = makeKdf();
    const kekRaw32 = bytes(32, (i) => 0x55 + i);
    const wrapNonce = bytes(12, (i) => 0x20 + i);
    const plaintext = bytes(64, (i) => 0xaa - i);

    const { bytes: encoded } = await encryptV1WithKek({
      header,
      kdf,
      kekRaw32,
      wrapNonce,
      plaintext,
    });

    const { plaintext: decrypted } = await decryptV1WithKek({
      data: encoded,
      kekRaw32,
    });

    expect([...decrypted]).toEqual([...plaintext]);
  });

  it("fails if KEK is wrong (decryptV1WithKek)", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x10 + i) });
    const kdf = makeKdf();
    const kekRaw32 = bytes(32, (i) => 0x55 + i);
    const wrongKek = bytes(32, (i) => 0x77 + i);
    const wrapNonce = bytes(12, (i) => 0x20 + i);
    const plaintext = bytes(32, (i) => 0x5a ^ i);

    const { bytes: encoded } = await encryptV1WithKek({
      header,
      kdf,
      kekRaw32,
      wrapNonce,
      plaintext,
    });

    await expect(decryptV1WithKek({ data: encoded, kekRaw32: wrongKek })).rejects.toThrow();
  });

  it("fails if AAD is altered (wrap nonce)", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x10 + i) });
    const kdf = makeKdf();
    const kekRaw32 = bytes(32, (i) => 0x55 + i);
    const wrapNonce = bytes(12, (i) => 0x20 + i);
    const plaintext = bytes(32, (i) => 0x33 + i);

    const { bytes: encoded } = await encryptV1WithKek({
      header,
      kdf,
      kekRaw32,
      wrapNonce,
      plaintext,
    });

    const tampered = encoded.slice();
    // wrapNonce est juste après kdf + wrapCipherId, donc on peut le cibler via la longueur AAD
    const decoded = decodeV1(encoded);
    const aadLength = encodeAadV1(decoded.header, decoded.kdf, decoded.wrappedDek, new Writer());
    const wrapNonceOffset = aadLength - (16 + 32 + 12); // tag + wrappedDekCiphertext + wrapNonce
    tampered[wrapNonceOffset] = (tampered[wrapNonceOffset]! ^ 0xff) & 0xff;

    await expect(decryptV1WithKek({ data: tampered, kekRaw32 })).rejects.toThrow();
  });

  it("fails if ciphertext is tampered", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x10 + i) });
    const kdf = makeKdf();
    const kekRaw32 = bytes(32, (i) => 0x55 + i);
    const wrapNonce = bytes(12, (i) => 0x20 + i);
    const plaintext = bytes(40, (i) => 0x9a - i);

    const { bytes: encoded, aadLength } = await encryptV1WithKek({
      header,
      kdf,
      kekRaw32,
      wrapNonce,
      plaintext,
    });

    const tampered = encoded.slice();
    tampered[aadLength] = (tampered[aadLength]! ^ 0x01) & 0xff;

    await expect(decryptV1WithKek({ data: tampered, kekRaw32 })).rejects.toThrow();
  });
});

describe("V1 encryption with password", () => {
  it("encrypts then decrypts with password", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x12 + i) });
    const kdf = makeKdf({ salt: bytes(16, (i) => 0x2a + i) });
    const wrapNonce = bytes(12, (i) => 0x20 + i);
    const plaintext = bytes(48, (i) => i ^ 0x3c);

    const { bytes: encoded } = await encryptV1WithPassword({
      header,
      kdf,
      password: "password-123",
      wrapNonce,
      plaintext,
    });

    const { plaintext: decrypted } = await decryptV1WithPassword({
      data: encoded,
      password: "password-123",
    });

    expect([...decrypted]).toEqual([...plaintext]);
  });

  it("fails with wrong password", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x22 + i) });
    const kdf = makeKdf({ salt: bytes(16, (i) => 0x3b + i) });
    const wrapNonce = bytes(12, (i) => 0x21 + i);
    const plaintext = bytes(32, (i) => 0x7f - i);

    const { bytes: encoded } = await encryptV1WithPassword({
      header,
      kdf,
      password: "correct-password",
      wrapNonce,
      plaintext,
    });

    await expect(
      decryptV1WithPassword({ data: encoded, password: "wrong-password" })
    ).rejects.toThrow();
  });

  it("fails if ciphertext is tampered", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x32 + i) });
    const kdf = makeKdf({ salt: bytes(16, (i) => 0x42 + i) });
    const wrapNonce = bytes(12, (i) => 0x52 + i);
    const plaintext = bytes(36, (i) => 0x6b ^ i);

    const { bytes: encoded, aadLength } = await encryptV1WithPassword({
      header,
      kdf,
      password: "password-xyz",
      wrapNonce,
      plaintext,
    });

    const tampered = encoded.slice();
    tampered[aadLength] = (tampered[aadLength]! ^ 0xff) & 0xff;

    await expect(
      decryptV1WithPassword({ data: tampered, password: "password-xyz" })
    ).rejects.toThrow();
  });

  it("fails if KDF id is unsupported", async () => {
    const header = makeHeader({ nonce: bytes(12, (i) => 0x32 + i) });
    const kdf = makeKdf({ kdfId: 0xff, salt: bytes(16, (i) => 0x42 + i) });
    const wrappedDek = makeWrap();
    const ciphertext = bytes(8, (i) => i ^ 0x55);
    const authTag = bytes(16, (i) => 0xaa - i);
    const { bytes: encoded } = encodeV1(header, kdf, wrappedDek, ciphertext, authTag);

    await expect(
      decryptV1WithPassword({ data: encoded, password: "password-xyz" })
    ).rejects.toThrow(/unsupported kdf/i);
  });
});
