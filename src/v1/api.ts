import { CIPHER_AES_256_GCM, VERSION_V1 } from "./spec/constants";
import type { V1Header } from "./spec/types";
import { decryptV1WithPassword, encryptV1WithPassword } from "./format";
import { resolveV1KdfParams } from "./encrypt-options";
import type { V1EncryptOptions } from "./encrypt-options";
import {
  AuthenticationError,
  CryptoOperationError,
  EnvironmentError,
  FormatError,
  InvalidParamsError,
  ResourcePolicyError,
  UnsupportedFormatError,
} from "./errors";
import type { V1DecryptOptions } from "./resource-policy";
import { validatePublicPassword } from "./password";
import { secureRandomBytes } from "./crypto-runtime";

export type { KdfProfile, V1EncryptOptions, V1KdfOptions } from "./encrypt-options";
export type { DecryptResourcePolicy, V1DecryptOptions } from "./resource-policy";

export type ClearcryptErrorCode =
  | "INVALID_PARAMS"
  | "INVALID_FORMAT"
  | "UNSUPPORTED_FORMAT"
  | "RESOURCE_LIMIT"
  | "AUTH_FAILED"
  | "CRYPTO_FAILED"
  | "ENVIRONMENT_ERROR"
  | "INTERNAL";

export class ClearcryptError extends Error {
  readonly code: ClearcryptErrorCode;
  readonly cause?: unknown;

  constructor(code: ClearcryptErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "ClearcryptError";
    this.code = code;
    this.cause = cause;
  }
}

export function mapInternalError(err: unknown): ClearcryptError {
  if (err instanceof ClearcryptError) {
    return err;
  }
  if (err instanceof InvalidParamsError) {
    return new ClearcryptError("INVALID_PARAMS", err.message, err);
  }
  if (err instanceof UnsupportedFormatError) {
    return new ClearcryptError(
      "UNSUPPORTED_FORMAT",
      "Unsupported format or algorithm",
      err
    );
  }
  if (err instanceof FormatError) {
    return new ClearcryptError("INVALID_FORMAT", "Invalid format", err);
  }
  if (err instanceof ResourcePolicyError) {
    return new ClearcryptError("RESOURCE_LIMIT", err.message, err);
  }
  if (err instanceof AuthenticationError) {
    return new ClearcryptError(
      "AUTH_FAILED",
      "Authentication failed or wrong password",
      err
    );
  }
  if (err instanceof EnvironmentError) {
    return new ClearcryptError(
      "ENVIRONMENT_ERROR",
      "Cryptographic environment unavailable",
      err
    );
  }
  if (err instanceof CryptoOperationError) {
    return new ClearcryptError(
      "CRYPTO_FAILED",
      "Cryptographic operation failed",
      err
    );
  }
  return new ClearcryptError("INTERNAL", "Internal error", err);
}

export async function encryptBytesV1(
  plaintext: Uint8Array,
  password: Uint8Array | string,
  options: V1EncryptOptions = {}
): Promise<Uint8Array> {
  try {
    const passwordBytes = validatePublicPassword(password);
    const header: V1Header = {
      version: VERSION_V1,
      cipherId: CIPHER_AES_256_GCM,
      nonce: secureRandomBytes(12),
    };

    const kdf = resolveV1KdfParams(secureRandomBytes(16), options);
    const wrapNonce = secureRandomBytes(12);

    const { bytes } = await encryptV1WithPassword({
      header,
      kdf,
      password: passwordBytes,
      wrapNonce,
      plaintext,
    });

    return bytes;
  } catch (err) {
    throw mapInternalError(err);
  }
}

export async function decryptBytesV1(
  data: Uint8Array,
  password: Uint8Array | string,
  options: V1DecryptOptions = {}
): Promise<Uint8Array> {
  try {
    const passwordBytes = validatePublicPassword(password);
    const { plaintext } = await decryptV1WithPassword({
      data,
      password: passwordBytes,
      ...(options.resourcePolicy
        ? { resourcePolicy: options.resourcePolicy }
        : {}),
    });
    return plaintext;
  } catch (err) {
    throw mapInternalError(err);
  }
}
