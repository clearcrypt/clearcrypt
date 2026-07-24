#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const MAGIC = new TextEncoder().encode("CFENC001");
const VERSION = 1;
const AES_256_GCM_ID = 1;
const ARGON2ID_ID = 1;
const TAG_LENGTH = 16;

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (value) => new Uint8Array(Buffer.from(value, "hex"));
const concat = (...chunks) => {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
};
const u8 = (value) => Uint8Array.of(value);
const u32be = (value) => {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
};
const assertHex = (label, actual, expected) => {
  if (hex(actual) !== expected) {
    throw new Error(`${label} mismatch: ${hex(actual)} != ${expected}`);
  }
};

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
    if (descriptor) {
      Object.defineProperty(globalThis, name, descriptor);
    } else {
      Reflect.deleteProperty(globalThis, name);
    }
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

async function deriveKek(passwordBytes, kdf) {
  const previousGlobals = new Map();
  try {
    const argon2 = loadArgon2(previousGlobals);
    const result = await argon2.hash({
      pass: passwordBytes,
      salt: fromHex(kdf.saltHex),
      time: kdf.timeCost,
      mem: kdf.memoryCostKiB,
      parallelism: kdf.parallelism,
      hashLen: kdf.outputLengthBytes,
      type: argon2.ArgonType.Argon2id,
    });
    if (!result.encoded.startsWith(`$argon2id$v=${kdf.version}$`)) {
      throw new Error("argon2-browser returned an unexpected algorithm or version");
    }
    return result.hash instanceof Uint8Array
      ? result.hash
      : new Uint8Array(result.hash);
  } finally {
    restoreGlobals(previousGlobals);
  }
}

async function aesGcmEncrypt(keyBytes, nonce, plaintext, aad) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const algorithm = { name: "AES-GCM", iv: nonce, tagLength: 128 };
  if (aad.length > 0) algorithm.additionalData = aad;
  const combined = new Uint8Array(await crypto.subtle.encrypt(algorithm, key, plaintext));
  return {
    ciphertext: combined.subarray(0, combined.length - TAG_LENGTH),
    tag: combined.subarray(combined.length - TAG_LENGTH),
  };
}

async function aesGcmDecrypt(keyBytes, nonce, combined, aad) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const algorithm = { name: "AES-GCM", iv: nonce, tagLength: 128 };
  if (aad.length > 0) algorithm.additionalData = aad;
  return new Uint8Array(await crypto.subtle.decrypt(algorithm, key, combined));
}

function buildAad(vector, wrappedDek) {
  return concat(
    MAGIC,
    u8(VERSION),
    u8(AES_256_GCM_ID),
    fromHex(vector.contentEncryption.nonceHex),
    u8(ARGON2ID_ID),
    fromHex(vector.kdf.saltHex),
    u32be(vector.kdf.timeCost),
    u32be(vector.kdf.memoryCostKiB),
    u8(vector.kdf.parallelism),
    u8(AES_256_GCM_ID),
    fromHex(vector.wrappedDek.nonceHex),
    wrappedDek.ciphertext,
    wrappedDek.tag
  );
}

async function calculateVector(input) {
  const passwordBytes = new TextEncoder().encode(input.password.value);
  const plaintext = fromHex(input.plaintextHex);
  const dek = fromHex(input.dekHex);
  const kek = await deriveKek(passwordBytes, input.kdf);
  const wrappedDek = await aesGcmEncrypt(
    kek,
    fromHex(input.wrappedDek.nonceHex),
    dek,
    new Uint8Array()
  );
  const aad = buildAad(input, wrappedDek);
  const content = await aesGcmEncrypt(
    dek,
    fromHex(input.contentEncryption.nonceHex),
    plaintext,
    aad
  );
  const archive = concat(aad, content.ciphertext, content.tag);

  return { passwordBytes, plaintext, kek, wrappedDek, aad, content, archive };
}

async function generate() {
  const input = {
    schema: "clearcrypt-cfenc001-test-vector",
    name: "unicode-password-binary-plaintext",
    format: "CFENC001",
    password: {
      value: "  Caf\u00e9\ud83d\udd10 e\u0301  ",
      utf8Hex: "",
    },
    plaintextHex: "00010203feff436c6561724372797074204346454e43303031",
    expectedPlaintextHex: "00010203feff436c6561724372797074204346454e43303031",
    kdf: {
      algorithm: "argon2id",
      algorithmId: ARGON2ID_ID,
      version: 19,
      saltHex: "000102030405060708090a0b0c0d0e0f",
      timeCost: 1,
      memoryCostKiB: 8192,
      parallelism: 1,
      outputLengthBytes: 32,
    },
    kekHex: "",
    dekHex: "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    wrappedDek: {
      algorithm: "aes-256-gcm",
      algorithmId: AES_256_GCM_ID,
      nonceHex: "202122232425262728292a2b",
      ciphertextHex: "",
      tagHex: "",
    },
    contentEncryption: {
      algorithm: "aes-256-gcm",
      algorithmId: AES_256_GCM_ID,
      nonceHex: "101112131415161718191a1b",
      ciphertextHex: "",
      tagHex: "",
    },
    aadHex: "",
    archiveHex: "",
    archiveBase64: "",
  };
  const calculated = await calculateVector(input);
  input.password.utf8Hex = hex(calculated.passwordBytes);
  input.kekHex = hex(calculated.kek);
  input.wrappedDek.ciphertextHex = hex(calculated.wrappedDek.ciphertext);
  input.wrappedDek.tagHex = hex(calculated.wrappedDek.tag);
  input.contentEncryption.ciphertextHex = hex(calculated.content.ciphertext);
  input.contentEncryption.tagHex = hex(calculated.content.tag);
  input.aadHex = hex(calculated.aad);
  input.archiveHex = hex(calculated.archive);
  input.archiveBase64 = Buffer.from(calculated.archive).toString("base64");
  process.stdout.write(`${JSON.stringify(input, null, 2)}\n`);
}

async function verify(path) {
  const vector = JSON.parse(readFileSync(path, "utf8"));
  if (vector.format !== "CFENC001" || vector.kdf.version !== 19) {
    throw new Error("Unsupported vector metadata");
  }
  const calculated = await calculateVector(vector);
  assertHex("password UTF-8", calculated.passwordBytes, vector.password.utf8Hex);
  assertHex("KEK", calculated.kek, vector.kekHex);
  assertHex("wrapped DEK", calculated.wrappedDek.ciphertext, vector.wrappedDek.ciphertextHex);
  assertHex("wrapped DEK tag", calculated.wrappedDek.tag, vector.wrappedDek.tagHex);
  assertHex("AAD", calculated.aad, vector.aadHex);
  assertHex("ciphertext", calculated.content.ciphertext, vector.contentEncryption.ciphertextHex);
  assertHex("content tag", calculated.content.tag, vector.contentEncryption.tagHex);
  assertHex("archive", calculated.archive, vector.archiveHex);
  if (Buffer.from(calculated.archive).toString("base64") !== vector.archiveBase64) {
    throw new Error("archive base64 mismatch");
  }

  const archive = fromHex(vector.archiveHex);
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  if (new TextDecoder().decode(archive.subarray(0, 8)) !== "CFENC001") {
    throw new Error("magic mismatch");
  }
  if (view.getUint8(8) !== 1 || view.getUint8(9) !== 1 || view.getUint8(22) !== 1 || view.getUint8(48) !== 1) {
    throw new Error("identifier mismatch");
  }
  if (view.getUint32(39, false) !== vector.kdf.timeCost || view.getUint32(43, false) !== vector.kdf.memoryCostKiB) {
    throw new Error("KDF integer mismatch");
  }

  const unwrappedDek = await aesGcmDecrypt(
    calculated.kek,
    archive.subarray(49, 61),
    archive.subarray(61, 109),
    new Uint8Array()
  );
  assertHex("unwrapped DEK", unwrappedDek, vector.dekHex);
  const plaintext = await aesGcmDecrypt(
    unwrappedDek,
    archive.subarray(10, 22),
    archive.subarray(109),
    archive.subarray(0, 109)
  );
  assertHex("decrypted plaintext", plaintext, vector.expectedPlaintextHex);
  process.stdout.write(`verified ${vector.name}\n`);
}

if (process.argv[2] === "--generate") {
  await generate();
} else {
  await verify(process.argv[2] ?? "test/vectors/v1/unicode-password-binary-plaintext.json");
}
