import { CIPHER_AES_256_GCM, KDF_ARGON2ID, VERSION_V1 } from "./spec/constants";
import type { V1Header, V1KdfParams } from "./spec/types";
import { decryptV1WithPassword, encryptV1WithPassword } from "./format";

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

export type V1EncryptOptions = {
  nonce?: Uint8Array;
  salt?: Uint8Array;
  wrapNonce?: Uint8Array;
  kdf?: Partial<V1KdfParams>;
};

const DEFAULT_KDF: V1KdfParams = {
  kdfId: KDF_ARGON2ID,
  salt: new Uint8Array(16),
  timeCost: 2,
  memoryCost: 64 * 1024,
  parallelism: 2,
};

function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

function assertLength(name: string, value: Uint8Array, expected: number): void {
  if (value.length !== expected) {
    throw new ClearcryptError(
      "INVALID_PARAMS",
      `${name} must be ${expected} bytes`
    );
  }
}

function mapEncryptError(err: unknown): ClearcryptError {
  if (err instanceof ClearcryptError) {
    return err;
  }
  const message = err instanceof Error ? err.message : String(err);
  if (/nonce must be 12 bytes|salt must be 16 bytes|wrapped dek/i.test(message)) {
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
    /invalid magic|unsupported version|unexpected end of file|invalid payload|unsupported cipher/i.test(
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
    if (options.nonce) {
      assertLength("nonce", options.nonce, 12);
    }
    if (options.salt) {
      assertLength("salt", options.salt, 16);
    }
    if (options.wrapNonce) {
      assertLength("wrapNonce", options.wrapNonce, 12);
    }

    const header: V1Header = {
      version: VERSION_V1,
      cipherId: CIPHER_AES_256_GCM,
      nonce: options.nonce ?? randomBytes(12),
    };

    const kdf: V1KdfParams = {
      kdfId: options.kdf?.kdfId ?? DEFAULT_KDF.kdfId,
      salt: options.salt ?? randomBytes(16),
      timeCost: options.kdf?.timeCost ?? DEFAULT_KDF.timeCost,
      memoryCost: options.kdf?.memoryCost ?? DEFAULT_KDF.memoryCost,
      parallelism: options.kdf?.parallelism ?? DEFAULT_KDF.parallelism,
    };

    const wrapNonce = options.wrapNonce ?? randomBytes(12);

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
