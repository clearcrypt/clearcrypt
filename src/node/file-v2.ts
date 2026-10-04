import { randomUUID } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { rename, rm } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { finished } from "node:stream/promises";
import { decryptStreamV2, encryptStreamV2 } from "../v2/api";
import type {
  V2DecryptOptions,
  V2EncryptOptions,
  V2OperationResult,
} from "../v2/stream-types";

export class ClearcryptFileInputError extends Error {
  readonly cause?: unknown;

  constructor(cause?: unknown) {
    super("Unable to read the input file");
    this.name = "ClearcryptFileInputError";
    this.cause = cause;
  }
}

export class ClearcryptFileOutputError extends Error {
  readonly cause?: unknown;

  constructor(cause?: unknown) {
    super("Unable to write the output file");
    this.name = "ClearcryptFileOutputError";
    this.cause = cause;
  }
}

async function removeTemporaryFile(path: string): Promise<void> {
  try {
    await rm(path, { force: true });
  } catch {
    // Cleanup failure must not mask the operation error.
  }
}

function isFilesystemStreamErrorForPath(
  error: unknown,
  expectedPath: string
): error is NodeJS.ErrnoException {
  if (
    !(error instanceof Error) ||
    typeof (error as NodeJS.ErrnoException).code !== "string" ||
    typeof (error as NodeJS.ErrnoException).syscall !== "string"
  ) {
    return false;
  }
  const errorPath = (error as NodeJS.ErrnoException).path;
  return typeof errorPath !== "string" || resolve(errorPath) === expectedPath;
}

async function transformFileV2(params: {
  inputPath: string;
  outputPath: string;
  transform: (
    source: ReadableStream<Uint8Array>,
    destination: WritableStream<Uint8Array>
  ) => Promise<V2OperationResult>;
}): Promise<V2OperationResult> {
  const inputPath = resolve(params.inputPath);
  const outputPath = resolve(params.outputPath);
  const temporaryPath = join(
    dirname(outputPath),
    `.${basename(outputPath)}.clearcrypt-${process.pid}-${randomUUID()}.tmp`
  );
  const input = createReadStream(inputPath);
  const output = createWriteStream(temporaryPath, { flags: "wx" });
  let inputError: unknown;
  let outputError: unknown;
  input.once("error", (error) => {
    if (isFilesystemStreamErrorForPath(error, inputPath)) inputError = error;
  });
  output.once("error", (error) => {
    if (isFilesystemStreamErrorForPath(error, temporaryPath)) outputError = error;
  });

  try {
    const result = await params.transform(
      Readable.toWeb(input) as ReadableStream<Uint8Array>,
      Writable.toWeb(output) as WritableStream<Uint8Array>
    );
    try {
      await rename(temporaryPath, outputPath);
    } catch (error) {
      throw new ClearcryptFileOutputError(error);
    }
    return result;
  } catch (error) {
    input.destroy();
    output.destroy();
    await Promise.allSettled([finished(input), finished(output)]);
    await removeTemporaryFile(temporaryPath);
    if (inputError) throw new ClearcryptFileInputError(inputError);
    if (outputError) throw new ClearcryptFileOutputError(outputError);
    throw error;
  }
}

export function encryptFileV2(
  inputPath: string,
  outputPath: string,
  password: Uint8Array | string,
  options: V2EncryptOptions = {}
): Promise<V2OperationResult> {
  return transformFileV2({
    inputPath,
    outputPath,
    transform: (source, destination) =>
      encryptStreamV2(source, destination, password, options),
  });
}

export function decryptFileV2(
  inputPath: string,
  outputPath: string,
  password: Uint8Array | string,
  options: V2DecryptOptions = {}
): Promise<V2OperationResult> {
  return transformFileV2({
    inputPath,
    outputPath,
    transform: (source, destination) =>
      decryptStreamV2(source, destination, password, options),
  });
}
