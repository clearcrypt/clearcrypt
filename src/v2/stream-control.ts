import type { V2Progress } from "./stream-types";

export class V2OperationAbortedError extends Error {
  readonly reason: unknown;

  constructor(reason?: unknown) {
    super("ClearCrypt V2 operation aborted");
    this.name = "V2OperationAbortedError";
    this.reason = reason;
  }
}

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new V2OperationAbortedError(signal.reason);
  }
}

export function emitProgress(
  callback: ((progress: V2Progress) => void) | undefined,
  progress: V2Progress
): void {
  callback?.(progress);
}

export function listenForAbort(
  signal: AbortSignal | undefined,
  sourceReader: ReadableStreamDefaultReader<Uint8Array>,
  destinationWriter: WritableStreamDefaultWriter<Uint8Array>
): () => void {
  if (!signal) return () => undefined;

  const abort = (): void => {
    const error = new V2OperationAbortedError(signal.reason);
    void sourceReader.cancel(error).catch(() => undefined);
    void destinationWriter.abort(error).catch(() => undefined);
  };
  signal.addEventListener("abort", abort, { once: true });
  return () => signal.removeEventListener("abort", abort);
}
