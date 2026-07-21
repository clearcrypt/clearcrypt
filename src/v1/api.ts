import { CIPHER_AES_256_GCM, VERSION_V1 } from "./spec/constants";
import type { V1Header } from "./spec/types";
import { decryptV1WithPassword, encryptV1WithPassword } from "./format";
import { resolveV1KdfParams } from "./encrypt-options";
import type { V1EncryptOptions } from "./encrypt-options";

export type { KdfProfile, V1EncryptOptions, V1KdfOptions } from "./encrypt-options";

export type ClearcryptErrorCode =
  | "INVALID_PARAMS"
  | "INVALID_FORMAT"
  | "AUTH_FAILED"
  | "CRYPTO_FAILED"
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

function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

function mapEncryptError(err: unknown): ClearcryptError {
  if (err instanceof ClearcryptError) {
    return err;
  }
  const message = err instanceof Error ? err.message : String(err);
  if (
    /nonce must be 12 bytes|salt must be 16 bytes|wrapped dek|unsupported kdf|timecost|memorycost|parallelism/i.test(
      message
    )
  ) {
    return new ClearcryptError("INVALID_PARAMS", message, err);
  }
  return new ClearcryptError("CRYPTO_FAILED", "Encryption failed", err);
}

function mapDecryptError(err: unknown): ClearcryptError {
  if (err instanceof ClearcryptError) {
    return err;
  }
  const message = err instanceof Error ? err.message : String(err);
  if (
    /invalid magic|unsupported version|unexpected end of file|invalid payload|unsupported cipher|unsupported kdf/i.test(
      message
    )
  ) {
    return new ClearcryptError("INVALID_FORMAT", "Invalid or unsupported format", err);
  }
  return new ClearcryptError("AUTH_FAILED", "Authentication failed or wrong password", err);
}

export async function encryptBytesV1(
  plaintext: Uint8Array,
  password: Uint8Array | string,
  options: V1EncryptOptions = {}
): Promise<Uint8Array> {
  try {
    const header: V1Header = {
      version: VERSION_V1,
      cipherId: CIPHER_AES_256_GCM,
      nonce: randomBytes(12),
    };

    const kdf = resolveV1KdfParams(randomBytes(16), options);
    const wrapNonce = randomBytes(12);

    const { bytes } = await encryptV1WithPassword({
      header,
      kdf,
      password,
      wrapNonce,
      plaintext,
    });

    return bytes;
  } catch (err) {
    throw mapEncryptError(err);
  }
}

export async function decryptBytesV1(
  data: Uint8Array,
  password: Uint8Array | string
): Promise<Uint8Array> {
  try {
    const { plaintext } = await decryptV1WithPassword({ data, password });
    return plaintext;
  } catch (err) {
    throw mapDecryptError(err);
  }
}
