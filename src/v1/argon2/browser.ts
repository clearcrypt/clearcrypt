import {
  normalizeArgon2Module,
  toArgon2BrowserParams,
} from "./types";
import type {
  Argon2BrowserModule,
  Argon2HashResult,
  Argon2idHashParams,
} from "./types";

let modulePromise: Promise<Argon2BrowserModule> | undefined;
let operationQueue: Promise<void> = Promise.resolve();

async function loadBrowserModule(): Promise<Argon2BrowserModule> {
  modulePromise ??= import("argon2-browser/dist/argon2-bundled.min.js").then(
    normalizeArgon2Module
  );
  return modulePromise;
}

export function hashArgon2idInBrowser(
  params: Argon2idHashParams
): Promise<Argon2HashResult> {
  const operation = operationQueue.then(async () => {
    const module = await loadBrowserModule();
    return module.hash(toArgon2BrowserParams(params));
  });
  operationQueue = operation.then(
    () => undefined,
    () => undefined
  );
  return operation;
}
