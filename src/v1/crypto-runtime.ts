import { EnvironmentError } from "./errors";

export function getWebCrypto(): Crypto {
  if (
    typeof globalThis.crypto === "undefined" ||
    typeof globalThis.crypto.getRandomValues !== "function" ||
    !globalThis.crypto.subtle
  ) {
    throw new EnvironmentError("WebCrypto is not available");
  }
  return globalThis.crypto;
}

export function secureRandomBytes(length: number): Uint8Array {
  try {
    return getWebCrypto().getRandomValues(new Uint8Array(length));
  } catch (cause) {
    if (cause instanceof EnvironmentError) throw cause;
    throw new EnvironmentError("Secure randomness is not available", cause);
  }
}
