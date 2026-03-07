#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { decryptBytesV1, encryptBytesV1, ClearcryptError } from "../dist/index.js";

function usage() {
  console.error("Usage:");
  console.error("  node scripts/cc-file.mjs encrypt <input> <output>");
  console.error("  node scripts/cc-file.mjs decrypt <input> <output>");
}

async function readPassword() {
  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });
  try {
    return (await rl.question("Password: ")).trim();
  } finally {
    rl.close();
  }
}

const [command, inputPath, outputPath] = process.argv.slice(2);
if (!command || !inputPath || !outputPath) {
  usage();
  process.exit(1);
}

try {
  const password = await readPassword();
  if (!password) {
    console.error("Password must not be empty");
    process.exit(1);
  }

  const input = readFileSync(inputPath);
  if (command === "encrypt") {
    const encrypted = await encryptBytesV1(new Uint8Array(input), password);
    writeFileSync(outputPath, encrypted);
    console.log("OK");
  } else if (command === "decrypt") {
    const decrypted = await decryptBytesV1(new Uint8Array(input), password);
    writeFileSync(outputPath, decrypted);
    console.log("OK");
  } else {
    usage();
    process.exit(1);
  }
} catch (err) {
  if (err instanceof ClearcryptError) {
    console.error(`${err.code}: ${err.message}`);
  } else {
    console.error(err);
  }
  process.exit(2);
}
