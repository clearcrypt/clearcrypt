# clearcrypt
Client-side, zero-knowledge file encryption core. This repository provides an auditable cryptographic core for encrypting and decrypting files locally using a password-based model. No plaintext, secrets, or keys are ever stored or transmitted. Includes a versioned, self-describing file format.

## Public API (stable)
The stable API surface is:
- `encryptBytesV1(plaintext, password, options?)`
- `decryptBytesV1(data, password)`

All other modules are internal and may change.

## Install
Published package:
```bash
npm install clearcrypt
```

Local dev (from repo):
```bash
npm install
npm run build
```

## Usage
Encrypt and decrypt bytes:
```ts
import { encryptBytesV1, decryptBytesV1 } from "clearcrypt";

const plaintext = new TextEncoder().encode("hello");
const password = "secret";

const encrypted = await encryptBytesV1(plaintext, password);
const decrypted = await decryptBytesV1(encrypted, password);

console.log(new TextDecoder().decode(decrypted));
```

Encrypt and decrypt a file (Node):
```ts
import { readFileSync, writeFileSync } from "node:fs";
import { encryptBytesV1, decryptBytesV1 } from "clearcrypt";

const input = readFileSync("input.txt");
const encrypted = await encryptBytesV1(new Uint8Array(input), "secret");
writeFileSync("input.txt.cc", encrypted);

const decrypted = await decryptBytesV1(encrypted, "secret");
writeFileSync("decrypted.txt", decrypted);
```

## API reference
```ts
encryptBytesV1(
  plaintext: Uint8Array,
  password: Uint8Array | string,
  options?: V1EncryptOptions
): Promise<Uint8Array>

decryptBytesV1(
  data: Uint8Array,
  password: Uint8Array | string
): Promise<Uint8Array>
```

## Options
`encryptBytesV1` accepts optional overrides:
- `nonce`: 12 bytes (AES-GCM nonce)
- `salt`: 16 bytes (KDF salt)
- `wrapNonce`: 12 bytes (wrap nonce for DEK)
- `kdf`: `{ timeCost, memoryCost, parallelism }`

If not provided, secure random values are generated.

## Errors
API functions throw `ClearcryptError` with a short message and a `code`.
Codes:
- `INVALID_PARAMS`: input sizes are wrong (nonce/salt/wrapNonce).
- `INVALID_FORMAT`: data is not a valid or supported V1 format.
- `AUTH_FAILED`: wrong password or data was tampered with.
- `CRYPTO_FAILED`: encryption failed for an unexpected reason.

Example:
```ts
import { decryptBytesV1, ClearcryptError } from "clearcrypt";

try {
  const plaintext = await decryptBytesV1(encrypted, "password");
} catch (err) {
  if (err instanceof ClearcryptError) {
    console.error(err.code, err.message);
  } else {
    throw err;
  }
}
```

## Format note
The V1 file format is self-describing. Header/AAD fields are stored in cleartext but authenticated. The payload remains encrypted.

## Compatibility
The API uses WebCrypto-compatible primitives and runs in modern browsers and Node.js.
