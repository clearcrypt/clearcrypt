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
  console.error("  node scripts/cc-file.mjs encrypt <input> <output>     # V1");
  console.error("  node scripts/cc-file.mjs decrypt <input> <output>     # V1");
  console.error("  node scripts/cc-file.mjs encrypt-v2 <input> <output>  # streaming");
  console.error("  node scripts/cc-file.mjs decrypt-v2 <input> <output>  # streaming");
}

function createProgressReporter(label) {
  let lastPhase;
  let lastUpdate = 0;
  let active = false;
  return {
    update(progress) {
      const now = Date.now();
      if (progress.phase === lastPhase && now - lastUpdate < 250) return;
      const mebibytes = progress.inputBytes / (1024n * 1024n);
      process.stderr.write(
        `\r${label} ${progress.phase}: ${mebibytes.toString()} MiB, ${progress.records.toString()} blocks`
      );
      lastPhase = progress.phase;
      lastUpdate = now;
      active = true;
    },
    finish() {
      if (active) process.stderr.write("\n");
    },
  };
}

function reportOperationError(error) {
  if (error?.name === "ClearcryptFileInputError") {
    console.error("INPUT_ERROR");
    return CLI_EXIT.INPUT;
  }
  if (error?.name === "ClearcryptFileOutputError") {
    console.error("OUTPUT_ERROR");
    return CLI_EXIT.OUTPUT;
  }
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

async function main() {
  const [command, inputPath, outputPath, ...extra] = process.argv.slice(2);
  const commands = new Set(["encrypt", "decrypt", "encrypt-v2", "decrypt-v2"]);
  if (
    !commands.has(command) ||
    !inputPath ||
    !outputPath ||
    extra.length > 0
  ) {
    usage();
    return CLI_EXIT.USAGE;
  }

  const encrypting = command === "encrypt" || command === "encrypt-v2";
  const streaming = command === "encrypt-v2" || command === "decrypt-v2";

  let password;
  try {
    password = encrypting
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

  if (streaming) {
    const abortController = new AbortController();
    const abort = () => abortController.abort("CLI interrupted");
    process.once("SIGINT", abort);
    process.once("SIGTERM", abort);
    const progress = createProgressReporter(encrypting ? "Encrypting" : "Decrypting");
    try {
      const { decryptFileV2, encryptFileV2 } = await import("../dist/node.js");
      const options = {
        signal: abortController.signal,
        onProgress: progress.update,
      };
      if (encrypting) {
        await encryptFileV2(inputPath, outputPath, password, options);
      } else {
        await decryptFileV2(inputPath, outputPath, password, options);
      }
    } catch (error) {
      progress.finish();
      return reportOperationError(error);
    } finally {
      process.removeListener("SIGINT", abort);
      process.removeListener("SIGTERM", abort);
    }
    progress.finish();
  } else {
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
      output = encrypting
        ? await encryptBytesV1(new Uint8Array(input), password)
        : await decryptBytesV1(new Uint8Array(input), password);
    } catch (error) {
      return reportOperationError(error);
    }

    try {
      writeFileSync(outputPath, output);
    } catch {
      console.error("OUTPUT_ERROR");
      return CLI_EXIT.OUTPUT;
    }
  }

  console.log("OK");
  return CLI_EXIT.OK;
}

process.exitCode = await main();
