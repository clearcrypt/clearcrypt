/**
 * Overwrite a package-owned temporary buffer when possible.
 *
 * This does not guarantee zeroization: JavaScript engines, WebAssembly and
 * WebCrypto may retain copies outside this buffer.
 */
export function wipeBytesBestEffort(bytes: Uint8Array | undefined): void {
  if (!bytes) return;
  try {
    bytes.fill(0);
  } catch {
    // A detached or otherwise inaccessible buffer must not mask the operation's
    // original result or error.
  }
}
