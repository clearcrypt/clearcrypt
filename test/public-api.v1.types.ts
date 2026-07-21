import type { V1DecryptOptions, V1EncryptOptions } from "../src/index";

const validOptions: V1EncryptOptions = {
  kdfProfile: "interactive",
  kdf: { timeCost: 2, memoryCost: 64 * 1024, parallelism: 2 },
};

// @ts-expect-error Random nonces are intentionally not part of the public API.
const optionsWithNonce: V1EncryptOptions = { nonce: new Uint8Array(12) };
// @ts-expect-error Random salts are intentionally not part of the public API.
const optionsWithSalt: V1EncryptOptions = { salt: new Uint8Array(16) };
// @ts-expect-error DEK wrapping nonces are intentionally not part of the public API.
const optionsWithWrapNonce: V1EncryptOptions = { wrapNonce: new Uint8Array(12) };
// @ts-expect-error Algorithm identifiers are fixed by V1 and cannot be overridden.
const optionsWithKdfId: V1EncryptOptions = { kdf: { kdfId: 2 } };
const optionsWithNestedSalt: V1EncryptOptions = {
  // @ts-expect-error KDF salts cannot be supplied through the nested object either.
  kdf: { salt: new Uint8Array(16) },
};

void [
  validOptions,
  optionsWithNonce,
  optionsWithSalt,
  optionsWithWrapNonce,
  optionsWithKdfId,
  optionsWithNestedSalt,
];

const validDecryptOptions: V1DecryptOptions = {
  resourcePolicy: {
    maxMemoryCostKiB: 128 * 1024,
    maxTimeCost: 4,
    maxParallelism: 4,
  },
};
const invalidDecryptOptions: V1DecryptOptions = {
  // @ts-expect-error Unknown policy fields are intentionally rejected.
  resourcePolicy: { maxCpuTime: 10 },
};

void [validDecryptOptions, invalidDecryptOptions];
