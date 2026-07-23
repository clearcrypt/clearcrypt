#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import {
  CLI_EXIT,
  PasswordConfirmationError,
  readConfirmedPassword,
  readPassword,
} from "./cli-password.mjs";

function usage() {
  console.error("Usage:");
  console.error("  node scripts/cc-file.mjs encrypt <input> <output>");
  console.error("  node scripts/cc-file.mjs decrypt <input> <output>");
}

async function main() {
  const [command, inputPath, outputPath, ...extra] = process.argv.slice(2);
  if (
    (command !== "encrypt" && command !== "decrypt") ||
    !inputPath ||
    !outputPath ||
    extra.length > 0
  ) {
    usage();
    return CLI_EXIT.USAGE;
  }

  let password;
  try {
    password = command === "encrypt"
      ? await readConfirmedPassword()
      : await readPassword();
  } catch (error) {
    console.error(
      error instanceof PasswordConfirmationError
        ? "PASSWORD_MISMATCH"
        : "PASSWORD_INPUT_ERROR"
    );
    return CLI_EXIT.PASSWORD;
  }

  let input;
  try {
    input = readFileSync(inputPath);
  } catch {
    console.error("INPUT_ERROR");
    return CLI_EXIT.INPUT;
  }

  let output;
  try {
    const { decryptBytesV1, encryptBytesV1 } = await import(
      "../dist/index.js"
    );
    output = command === "encrypt"
      ? await encryptBytesV1(new Uint8Array(input), password)
      : await decryptBytesV1(new Uint8Array(input), password);
  } catch (error) {
    if (error?.name === "ClearcryptError" && error.code === "INVALID_PARAMS") {
      console.error(`INVALID_PARAMS: ${error.message}`);
      return CLI_EXIT.PASSWORD;
    }
    console.error(
      error?.name === "ClearcryptError"
        ? `${error.code}: ${error.message}`
        : "CRYPTO_ERROR"
    );
    return CLI_EXIT.CRYPTO;
  }

  try {
    writeFileSync(outputPath, output);
  } catch {
    console.error("OUTPUT_ERROR");
    return CLI_EXIT.OUTPUT;
  }

  console.log("OK");
  return CLI_EXIT.OK;
}

process.exitCode = await main();
