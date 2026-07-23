import { afterEach, describe, expect, it, vi } from "vitest";
import { ClearcryptError, decryptBytesV1, encryptBytesV1 } from "../src/index";
import { mapInternalError } from "../src/v1/api";
import {
  AuthenticationError,
  CryptoOperationError,
  EnvironmentError,
  FormatError,
  InvalidParamsError,
  ResourcePolicyError,
  UnsupportedAlgorithmError,
  UnsupportedFormatError,
} from "../src/v1/errors";
import { encodeV1 } from "../src/v1/format";
import { makeHeader, makeKdf, makeWrap } from "./helpers";

const EXPECTED_MAPPINGS = [
  [new InvalidParamsError("bad parameter"), "INVALID_PARAMS"],
  [new FormatError("bad structure"), "INVALID_FORMAT"],
  [new UnsupportedFormatError("future version"), "UNSUPPORTED_FORMAT"],
  [new UnsupportedAlgorithmError("future algorithm"), "UNSUPPORTED_FORMAT"],
  [new ResourcePolicyError(), "RESOURCE_LIMIT"],
  [new AuthenticationError(), "AUTH_FAILED"],
  [new CryptoOperationError("crypto failure"), "CRYPTO_FAILED"],
  [new EnvironmentError("missing runtime"), "ENVIRONMENT_ERROR"],
  [new Error("unclassified"), "INTERNAL"],
] as const;

function encodedArchive(): Uint8Array {
  return encodeV1(
    makeHeader(),
    makeKdf(),
    makeWrap(),
    new Uint8Array(),
    new Uint8Array(16)
  ).bytes;
}

async function captureError(promise: Promise<unknown>): Promise<ClearcryptError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ClearcryptError);
    return error as ClearcryptError;
  }
  throw new Error("Expected promise to reject");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("V1 typed error mapping", () => {
  it.each(EXPECTED_MAPPINGS)("maps %s to %s", (internalError, expectedCode) => {
    expect(mapInternalError(internalError).code).toBe(expectedCode);
  });

  it("preserves an existing public error", () => {
    const error = new ClearcryptError("INTERNAL", "already mapped");
    expect(mapInternalError(error)).toBe(error);
  });

  it("reports structural truncation as INVALID_FORMAT", async () => {
    const error = await captureError(
      decryptBytesV1(encodedArchive().subarray(0, 20), "password")
    );
    expect(error.code).toBe("INVALID_FORMAT");
    expect(error.message).toBe("Invalid format");
  });

  it("reports future versions and algorithms as UNSUPPORTED_FORMAT", async () => {
    const futureVersion = encodedArchive();
    futureVersion[8] = 0xff;
    const unknownCipher = encodedArchive();
    unknownCipher[9] = 0xff;

    const versionError = await captureError(
      decryptBytesV1(futureVersion, "password")
    );
    const cipherError = await captureError(
      decryptBytesV1(unknownCipher, "password")
    );

    expect(versionError.code).toBe("UNSUPPORTED_FORMAT");
    expect(cipherError.code).toBe("UNSUPPORTED_FORMAT");
  });

  it("reports a missing WebCrypto runtime as ENVIRONMENT_ERROR", async () => {
    vi.stubGlobal("crypto", undefined);

    const error = await captureError(
      encryptBytesV1(new Uint8Array(), "password")
    );

    expect(error.code).toBe("ENVIRONMENT_ERROR");
    expect(error.message).toBe("Cryptographic environment unavailable");
  });
});
