import { CIPHER_AES_256_GCM, VERSION_V1 } from "./spec/constants";
import { deriveKekArgon2id } from "./kdf";
import { encryptV1WithDek } from "./format";
import { wrapDekWithKek } from "./wrap";
import { resolveV1KdfParams } from "./encrypt-options";
import type { V1EncryptOptions } from "./encrypt-options";

export type V1DeterministicTestOptions = V1EncryptOptions & {
  nonce: Uint8Array;
  salt: Uint8Array;
  wrapNonce: Uint8Array;
  dek: Uint8Array;
};

/** Internal test helper. Deliberately not exported from the package entry point. */
export async function encryptBytesV1DeterministicForTests(
  plaintext: Uint8Array,
  password: Uint8Array | string,
  options: V1DeterministicTestOptions
): Promise<Uint8Array> {
  const kdf = resolveV1KdfParams(options.salt, options);
  const kekRaw32 = await deriveKekArgon2id({
    password,
    salt: kdf.salt,
    timeCost: kdf.timeCost,
    memoryCost: kdf.memoryCost,
    parallelism: kdf.parallelism,
  });
  const wrappedDek = await wrapDekWithKek({
    dek: options.dek,
    kekRaw32,
    wrapNonce: options.wrapNonce,
  });
  const { bytes } = await encryptV1WithDek({
    header: {
      version: VERSION_V1,
      cipherId: CIPHER_AES_256_GCM,
      nonce: options.nonce,
    },
    kdf,
    wrappedDek,
    dek: options.dek,
    plaintext,
  });

  return bytes;
}
