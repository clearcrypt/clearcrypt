import { ClearcryptError, mapInternalError } from "../v1/api";
import { decryptStreamV2Internal } from "./decrypt-stream";
import { encryptStreamV2Internal } from "./encrypt-stream";
import { V2OperationAbortedError } from "./stream-control";
import type {
  V2DecryptOptions,
  V2EncryptOptions,
  V2OperationResult,
} from "./stream-types";

function mapV2Error(error: unknown): ClearcryptError {
  if (error instanceof V2OperationAbortedError) {
    return new ClearcryptError("ABORTED", "Operation aborted", error.reason ?? error);
  }
  return mapInternalError(error);
}

export async function encryptStreamV2(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  password: Uint8Array | string,
  options: V2EncryptOptions = {}
): Promise<V2OperationResult> {
  try {
    return await encryptStreamV2Internal(source, destination, password, options);
  } catch (error) {
    throw mapV2Error(error);
  }
}

export async function decryptStreamV2(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  password: Uint8Array | string,
  options: V2DecryptOptions = {}
): Promise<V2OperationResult> {
  try {
    return await decryptStreamV2Internal(source, destination, password, options);
  } catch (error) {
    throw mapV2Error(error);
  }
}

export type {
  V2DecryptOptions,
  V2EncryptKdfOptions,
  V2EncryptOptions,
  V2OperationResult,
  V2Progress,
  V2StreamOptions,
} from "./stream-types";
export type { DecryptResourcePolicy } from "../v1/resource-policy";
