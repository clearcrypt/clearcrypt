#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";

const require = createRequire(import.meta.url);
const MAGIC = new TextEncoder().encode("CFENC002");
const VERSION = 2;
const ALGORITHM_ID = 1;
const HEADER_LENGTH = 122;
const WRAP_AAD_LENGTH = 74;
const DATA_HEADER_LENGTH = 13;
const FINAL_HEADER_LENGTH = 17;
const TAG_LENGTH = 16;
const CHUNK_SIZE = 65_536;
const SEGMENT_SIZE = 1n << 30n;
const SEGMENT_LABEL = new TextEncoder().encode("ClearCrypt/CFENC002/segment-key");
const FINAL_LABEL = new TextEncoder().encode("ClearCrypt/CFENC002/final-key");
const DEFAULT_VECTOR_DIRECTORY = resolve("test/vectors/v2");
const VECTOR_FILES = ["empty.json", "unicode-binary.json", "multiple-blocks.json"];

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (value) => new Uint8Array(Buffer.from(value, "hex"));
const base64 = (bytes) => Buffer.from(bytes).toString("base64");
const fromBase64 = (value) => new Uint8Array(Buffer.from(value, "base64"));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function concat(...parts) {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function u8(value) {
  return Uint8Array.of(value);
}

function u32be(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function u64be(value) {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
  return bytes;
}

function assertEqual(label, actual, expected) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch: ${actual} != ${expected}`);
  }
}

function setTemporaryGlobal(name, value, previous) {
  previous.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  Object.defineProperty(globalThis, name, {
    configurable: true,
    writable: true,
    value,
  });
}

function restoreGlobals(previous) {
  for (const [name, descriptor] of previous) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else Reflect.deleteProperty(globalThis, name);
  }
}

function loadArgon2(previous) {
  const wasmBinary = readFileSync(require.resolve("argon2-browser/dist/argon2.wasm"));
  setTemporaryGlobal("self", globalThis, previous);
  setTemporaryGlobal("Module", { wasmBinary }, previous);
  setTemporaryGlobal(
    "loadArgon2WasmBinary",
    () => Promise.resolve(new Uint8Array(wasmBinary)),
    previous
  );
  return require("argon2-browser/lib/argon2.js");
}

async function deriveKek(passwordBytes, salt, kdf) {
  const previous = new Map();
  try {
    const argon2 = loadArgon2(previous);
    const result = await argon2.hash({
      pass: passwordBytes,
      salt,
      time: kdf.timeCost,
      mem: kdf.memoryCostKiB,
      parallelism: kdf.parallelism,
      hashLen: 32,
      type: argon2.ArgonType.Argon2id,
    });
    if (!result.encoded.startsWith("$argon2id$v=19$")) {
      throw new Error("Argon2id returned an unexpected algorithm or version");
    }
    return result.hash instanceof Uint8Array
      ? result.hash
      : new Uint8Array(result.hash);
  } finally {
    restoreGlobals(previous);
  }
}

async function aesGcmEncrypt(keyBytes, nonce, plaintext, aad) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const combined = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      plaintext
    )
  );
  return {
    ciphertext: combined.subarray(0, combined.length - TAG_LENGTH),
    tag: combined.subarray(combined.length - TAG_LENGTH),
  };
}

async function aesGcmDecrypt(keyBytes, nonce, ciphertext, tag, aad) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      concat(ciphertext, tag)
    )
  );
}

async function hkdf(ikm, salt, info) {
  const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      baseKey,
      256
    )
  );
}

function plaintextFromDescriptor(descriptor) {
  if (descriptor.encoding === "hex") return fromHex(descriptor.valueHex);
  if (descriptor.encoding === "counter-mod-256") {
    return Uint8Array.from(
      { length: descriptor.length },
      (_, index) => (descriptor.start + index) & 0xff
    );
  }
  throw new Error(`Unsupported plaintext encoding: ${descriptor.encoding}`);
}

function encodeHeaderPrefix(inputs, kdf) {
  return concat(
    MAGIC,
    u8(VERSION),
    u8(ALGORITHM_ID),
    u8(ALGORITHM_ID),
    u32be(CHUNK_SIZE),
    fromHex(inputs.archiveIdHex),
    fromHex(inputs.contentNoncePrefixHex),
    u8(ALGORITHM_ID),
    fromHex(inputs.passwordSaltHex),
    u32be(kdf.timeCost),
    u32be(kdf.memoryCostKiB),
    u8(kdf.parallelism),
    u8(ALGORITHM_ID),
    fromHex(inputs.wrapNonceHex)
  );
}

function encodeDataHeader(recordNumber, plaintextLength) {
  return concat(u8(1), u64be(recordNumber), u32be(plaintextLength));
}

function encodeFinalHeader(recordCount, plaintextLength) {
  return concat(u8(2), u64be(recordCount), u64be(plaintextLength));
}

function dataPosition(recordNumber) {
  const recordsPerSegment = SEGMENT_SIZE / BigInt(CHUNK_SIZE);
  const number = BigInt(recordNumber);
  return {
    recordsPerSegment,
    segmentNumber: number / recordsPerSegment,
    localRecordNumber: number % recordsPerSegment,
  };
}

function dataNonce(prefix, localRecordNumber) {
  return concat(prefix, u64be(localRecordNumber));
}

async function calculateVector(definition) {
  const passwordBytes = new TextEncoder().encode(definition.password);
  const plaintext = plaintextFromDescriptor(definition.plaintext);
  const archiveId = fromHex(definition.inputs.archiveIdHex);
  const noncePrefix = fromHex(definition.inputs.contentNoncePrefixHex);
  const salt = fromHex(definition.inputs.passwordSaltHex);
  const wrapNonce = fromHex(definition.inputs.wrapNonceHex);
  const amk = fromHex(definition.inputs.archiveMasterKeyHex);
  const kek = await deriveKek(passwordBytes, salt, definition.kdf);
  const wrapAad = encodeHeaderPrefix(definition.inputs, definition.kdf);
  const wrapped = await aesGcmEncrypt(kek, wrapNonce, amk, wrapAad);
  const archiveAad = concat(wrapAad, wrapped.ciphertext, wrapped.tag);

  const segmentKeys = new Map();
  async function getSegmentKey(segmentNumber) {
    const id = segmentNumber.toString();
    if (!segmentKeys.has(id)) {
      segmentKeys.set(
        id,
        await hkdf(amk, archiveId, concat(SEGMENT_LABEL, u64be(segmentNumber)))
      );
    }
    return segmentKeys.get(id);
  }

  const encodedRecords = [];
  const recordVectors = [];
  let offset = 0;
  let recordNumber = 0n;
  while (offset < plaintext.length) {
    const chunk = plaintext.subarray(offset, Math.min(offset + CHUNK_SIZE, plaintext.length));
    const position = dataPosition(recordNumber);
    const key = await getSegmentKey(position.segmentNumber);
    const header = encodeDataHeader(recordNumber, chunk.length);
    const nonce = dataNonce(noncePrefix, position.localRecordNumber);
    const encrypted = await aesGcmEncrypt(key, nonce, chunk, concat(archiveAad, header));
    const encoded = concat(header, encrypted.ciphertext, encrypted.tag);
    const archiveOffset = HEADER_LENGTH + encodedRecords.reduce(
      (length, record) => length + record.length,
      0
    );
    encodedRecords.push(encoded);
    recordVectors.push({
      recordNumber: recordNumber.toString(),
      archiveOffset,
      plaintextLength: chunk.length,
      plaintextSha256Hex: sha256(chunk),
      headerHex: hex(header),
      segmentNumber: position.segmentNumber.toString(),
      localRecordNumber: position.localRecordNumber.toString(),
      nonceHex: hex(nonce),
      ciphertextSha256Hex: sha256(encrypted.ciphertext),
      tagHex: hex(encrypted.tag),
    });
    offset += chunk.length;
    recordNumber += 1n;
  }

  const finalKey = await hkdf(amk, archiveId, FINAL_LABEL);
  const finalHeader = encodeFinalHeader(recordNumber, BigInt(plaintext.length));
  const finalNonce = dataNonce(noncePrefix, 0n);
  const finalEncrypted = await aesGcmEncrypt(
    finalKey,
    finalNonce,
    new Uint8Array(),
    concat(archiveAad, finalHeader)
  );
  const finalRecord = concat(finalHeader, finalEncrypted.tag);
  const archive = concat(archiveAad, ...encodedRecords, finalRecord);

  const segment0Info = concat(SEGMENT_LABEL, u64be(0n));
  const segment1Info = concat(SEGMENT_LABEL, u64be(1n));
  const segment0Key = await getSegmentKey(0n);
  const segment1Key = await getSegmentKey(1n);
  const beforeTransition = dataPosition(16_383n);
  const afterTransition = dataPosition(16_384n);

  return {
    schema: "clearcrypt-cfenc002-test-vector-v1",
    name: definition.name,
    format: "CFENC002",
    password: { value: definition.password, utf8Hex: hex(passwordBytes) },
    plaintext: {
      ...definition.plaintext,
      length: plaintext.length,
      sha256Hex: sha256(plaintext),
    },
    kdf: {
      algorithm: "argon2id",
      version: 19,
      outputLengthBytes: 32,
      ...definition.kdf,
    },
    inputs: definition.inputs,
    intermediates: {
      kekHex: hex(kek),
      wrapAadHex: hex(wrapAad),
      wrappedArchiveKeyCiphertextHex: hex(wrapped.ciphertext),
      wrappedArchiveKeyTagHex: hex(wrapped.tag),
      archiveAadHex: hex(archiveAad),
      keySchedule: {
        segment0InfoHex: hex(segment0Info),
        segment0KeyHex: hex(segment0Key),
        segment1InfoHex: hex(segment1Info),
        segment1KeyHex: hex(segment1Key),
        finalInfoHex: hex(FINAL_LABEL),
        finalKeyHex: hex(finalKey),
      },
      segmentTransition: {
        recordsPerSegment: beforeTransition.recordsPerSegment.toString(),
        before: {
          recordNumber: "16383",
          segmentNumber: beforeTransition.segmentNumber.toString(),
          localRecordNumber: beforeTransition.localRecordNumber.toString(),
          nonceHex: hex(dataNonce(noncePrefix, beforeTransition.localRecordNumber)),
        },
        after: {
          recordNumber: "16384",
          segmentNumber: afterTransition.segmentNumber.toString(),
          localRecordNumber: afterTransition.localRecordNumber.toString(),
          nonceHex: hex(dataNonce(noncePrefix, afterTransition.localRecordNumber)),
        },
      },
    },
    records: recordVectors,
    final: {
      archiveOffset: archive.length - FINAL_HEADER_LENGTH - TAG_LENGTH,
      headerHex: hex(finalHeader),
      dataRecordCount: recordNumber.toString(),
      totalPlaintextLength: plaintext.length.toString(),
      nonceHex: hex(finalNonce),
      tagHex: hex(finalEncrypted.tag),
    },
    archiveLength: archive.length,
    archiveSha256Hex: sha256(archive),
    archiveBase64: base64(archive),
  };
}

const DEFINITIONS = [
  {
    file: "empty.json",
    name: "empty-plaintext",
    password: "empty-vector-password",
    plaintext: { encoding: "hex", valueHex: "" },
    kdf: { timeCost: 1, memoryCostKiB: 8192, parallelism: 1 },
    inputs: {
      archiveIdHex: "000102030405060708090a0b0c0d0e0f",
      contentNoncePrefixHex: "10111213",
      passwordSaltHex: "202122232425262728292a2b2c2d2e2f",
      wrapNonceHex: "303132333435363738393a3b",
      archiveMasterKeyHex: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    },
  },
  {
    file: "unicode-binary.json",
    name: "unicode-password-binary-plaintext",
    password: "  Café🔐 e\u0301  ",
    plaintext: {
      encoding: "hex",
      valueHex: "00010203feff436c6561724372797074204346454e4330303200807fff",
    },
    kdf: { timeCost: 1, memoryCostKiB: 8192, parallelism: 1 },
    inputs: {
      archiveIdHex: "606162636465666768696a6b6c6d6e6f",
      contentNoncePrefixHex: "70717273",
      passwordSaltHex: "808182838485868788898a8b8c8d8e8f",
      wrapNonceHex: "909192939495969798999a9b",
      archiveMasterKeyHex: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
    },
  },
  {
    file: "multiple-blocks.json",
    name: "multiple-blocks-final-short",
    password: "multiple-blocks-vector-password",
    plaintext: { encoding: "counter-mod-256", length: CHUNK_SIZE * 2 + 17, start: 112 },
    kdf: { timeCost: 1, memoryCostKiB: 8192, parallelism: 1 },
    inputs: {
      archiveIdHex: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
      contentNoncePrefixHex: "d0d1d2d3",
      passwordSaltHex: "e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
      wrapNonceHex: "f0f1f2f3f4f5f6f7f8f9fafb",
      archiveMasterKeyHex: "102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f",
    },
  },
];

async function decryptArchiveIndependently(vector) {
  const archive = fromBase64(vector.archiveBase64);
  assertEqual("archive length", archive.length, vector.archiveLength);
  assertEqual("archive digest", sha256(archive), vector.archiveSha256Hex);
  if (archive.length < HEADER_LENGTH + FINAL_HEADER_LENGTH + TAG_LENGTH) {
    throw new Error("archive is too short");
  }
  assertEqual("magic", new TextDecoder().decode(archive.subarray(0, 8)), "CFENC002");
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  assertEqual("version", archive[8], VERSION);
  assertEqual("content cipher", archive[9], ALGORITHM_ID);
  assertEqual("key schedule", archive[10], ALGORITHM_ID);
  assertEqual("chunk size", view.getUint32(11, false), CHUNK_SIZE);
  assertEqual("password KDF", archive[35], ALGORITHM_ID);
  assertEqual("wrap cipher", archive[61], ALGORITHM_ID);

  const passwordBytes = new TextEncoder().encode(vector.password.value);
  const kek = await deriveKek(
    passwordBytes,
    archive.subarray(36, 52),
    vector.kdf
  );
  const amk = await aesGcmDecrypt(
    kek,
    archive.subarray(62, 74),
    archive.subarray(74, 106),
    archive.subarray(106, 122),
    archive.subarray(0, WRAP_AAD_LENGTH)
  );
  const archiveAad = archive.subarray(0, HEADER_LENGTH);
  const archiveId = archive.subarray(15, 31);
  const noncePrefix = archive.subarray(31, 35);
  const chunks = [];
  let offset = HEADER_LENGTH;
  let expectedRecord = 0n;
  let totalPlaintext = 0n;
  let sawShortRecord = false;
  let sawFinal = false;

  while (offset < archive.length) {
    const recordType = archive[offset];
    if (recordType === 1) {
      if (sawShortRecord || offset + DATA_HEADER_LENGTH + TAG_LENGTH > archive.length) {
        throw new Error("invalid DATA framing");
      }
      const header = archive.subarray(offset, offset + DATA_HEADER_LENGTH);
      const headerView = new DataView(header.buffer, header.byteOffset, header.byteLength);
      const recordNumber = headerView.getBigUint64(1, false);
      const plaintextLength = headerView.getUint32(9, false);
      assertEqual("record number", recordNumber.toString(), expectedRecord.toString());
      if (plaintextLength < 1 || plaintextLength > CHUNK_SIZE) {
        throw new Error("invalid DATA plaintext length");
      }
      const ciphertextStart = offset + DATA_HEADER_LENGTH;
      const tagStart = ciphertextStart + plaintextLength;
      const nextOffset = tagStart + TAG_LENGTH;
      if (nextOffset > archive.length) throw new Error("truncated DATA record");
      const position = dataPosition(recordNumber);
      const key = await hkdf(
        amk,
        archiveId,
        concat(SEGMENT_LABEL, u64be(position.segmentNumber))
      );
      chunks.push(
        await aesGcmDecrypt(
          key,
          dataNonce(noncePrefix, position.localRecordNumber),
          archive.subarray(ciphertextStart, tagStart),
          archive.subarray(tagStart, nextOffset),
          concat(archiveAad, header)
        )
      );
      expectedRecord += 1n;
      totalPlaintext += BigInt(plaintextLength);
      sawShortRecord = plaintextLength < CHUNK_SIZE;
      offset = nextOffset;
      continue;
    }
    if (recordType !== 2 || offset + FINAL_HEADER_LENGTH + TAG_LENGTH !== archive.length) {
      throw new Error("invalid FINAL framing");
    }
    const header = archive.subarray(offset, offset + FINAL_HEADER_LENGTH);
    const headerView = new DataView(header.buffer, header.byteOffset, header.byteLength);
    assertEqual("FINAL record count", headerView.getBigUint64(1, false).toString(), expectedRecord.toString());
    assertEqual("FINAL plaintext length", headerView.getBigUint64(9, false).toString(), totalPlaintext.toString());
    const finalKey = await hkdf(amk, archiveId, FINAL_LABEL);
    const finalPlaintext = await aesGcmDecrypt(
      finalKey,
      dataNonce(noncePrefix, 0n),
      new Uint8Array(),
      archive.subarray(offset + FINAL_HEADER_LENGTH),
      concat(archiveAad, header)
    );
    assertEqual("FINAL plaintext size", finalPlaintext.length, 0);
    sawFinal = true;
    offset = archive.length;
  }

  if (!sawFinal) throw new Error("archive ended before FINAL");

  const plaintext = concat(...chunks);
  assertEqual("decrypted plaintext length", plaintext.length, vector.plaintext.length);
  assertEqual("decrypted plaintext digest", sha256(plaintext), vector.plaintext.sha256Hex);
  return plaintext;
}

async function verifyVector(path) {
  const vector = JSON.parse(await readFile(path, "utf8"));
  if (vector.schema !== "clearcrypt-cfenc002-test-vector-v1" || vector.format !== "CFENC002") {
    throw new Error("unsupported V2 vector metadata");
  }
  const definition = {
    name: vector.name,
    password: vector.password.value,
    plaintext: vector.plaintext,
    kdf: {
      timeCost: vector.kdf.timeCost,
      memoryCostKiB: vector.kdf.memoryCostKiB,
      parallelism: vector.kdf.parallelism,
    },
    inputs: vector.inputs,
  };
  const calculated = await calculateVector(definition);
  assertEqual("password UTF-8", calculated.password.utf8Hex, vector.password.utf8Hex);
  assertEqual("KEK", calculated.intermediates.kekHex, vector.intermediates.kekHex);
  assertEqual("wrap AAD", calculated.intermediates.wrapAadHex, vector.intermediates.wrapAadHex);
  assertEqual("archive AAD", calculated.intermediates.archiveAadHex, vector.intermediates.archiveAadHex);
  assertEqual(
    "key schedule",
    JSON.stringify(calculated.intermediates.keySchedule),
    JSON.stringify(vector.intermediates.keySchedule)
  );
  assertEqual(
    "segment transition",
    JSON.stringify(calculated.intermediates.segmentTransition),
    JSON.stringify(vector.intermediates.segmentTransition)
  );
  assertEqual("record metadata", JSON.stringify(calculated.records), JSON.stringify(vector.records));
  assertEqual("FINAL metadata", JSON.stringify(calculated.final), JSON.stringify(vector.final));
  assertEqual("archive bytes", calculated.archiveBase64, vector.archiveBase64);
  await decryptArchiveIndependently(vector);
  process.stdout.write(`verified ${vector.name}\n`);
}

async function generate(directory) {
  await mkdir(directory, { recursive: true });
  for (const definition of DEFINITIONS) {
    const vector = await calculateVector(definition);
    await writeFile(join(directory, definition.file), `${JSON.stringify(vector, null, 2)}\n`);
  }
}

if (process.argv[2] === "--generate") {
  await generate(resolve(process.argv[3] ?? DEFAULT_VECTOR_DIRECTORY));
} else {
  const paths = process.argv.length > 2
    ? process.argv.slice(2).map(resolve)
    : VECTOR_FILES.map((file) => join(DEFAULT_VECTOR_DIRECTORY, file));
  for (const path of paths) await verifyVector(path);
}
