# clearcrypt
Client-side, zero-knowledge file encryption core. This repository provides an auditable cryptographic core for encrypting and decrypting files locally using a password-based model. No plaintext, secrets, or keys are ever stored or transmitted. Includes a versioned, self-describing file format.

## Requirements
- Node.js 24 or newer.

## Public API (stable)
The stable API surface is:
- `encryptBytesV1(plaintext, password, options?)`
- `decryptBytesV1(data, password, options?)`

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

## Web integration constraints
- Current API is buffer-based (`Uint8Array` in / `Uint8Array` out). It is not a streaming API.
- For browser UI apps (Angular, React, etc.), run crypto operations in a Web Worker to avoid blocking the main thread.
- For very large files, enforce UI size limits until a streaming API is introduced.
- See [`docs/memory-v1.md`](docs/memory-v1.md) for the peak-memory model and benchmark.

## API reference
```ts
encryptBytesV1(
  plaintext: Uint8Array,
  password: Uint8Array | string,
  options?: V1EncryptOptions
): Promise<Uint8Array>

decryptBytesV1(
  data: Uint8Array,
  password: Uint8Array | string,
  options?: V1DecryptOptions
): Promise<Uint8Array>
```

## Options
`encryptBytesV1` accepts optional KDF settings:

- `kdfProfile`: `"interactive-v1"` (default) or `"hardened-v1"`
- `kdf`: `{ timeCost, memoryCost, parallelism }`

The versioned `interactive-v1` profile uses 64 MiB, 2 passes, and parallelism 2.
The versioned `hardened-v1` profile uses 128 MiB, 3 passes, and parallelism 2.
The former names `"interactive"` and `"hardened"` remain compatibility aliases.
Explicit `kdf` values override the selected profile. See the
[Argon2id V1 benchmark protocol](docs/argon2-profiles-v1.md) for the reproducible
Node.js and browser measurements.

The salt, content nonce, wrapping nonce, and DEK are always generated inside the
package with `crypto.getRandomValues()`. They cannot be supplied through the public API.

## Password handling

Public encryption and decryption accept a password from 1 through 1,024 bytes.
String limits are measured after UTF-8 encoding; `Uint8Array` inputs are measured
and used byte-for-byte.

ClearCrypt never trims whitespace, changes case, or applies implicit Unicode
normalization. For example, precomposed `é` and `e` followed by U+0301 are different
passwords. Applications must preserve the exact password supplied by the user.

`decryptBytesV1` accepts an optional local resource policy:

```ts
{
  resourcePolicy: {
    maxMemoryCostKiB?: number;
    maxTimeCost?: number;
    maxParallelism?: number;
  }
}
```

The provisional defaults are 128 MiB, 4 passes, and parallelism 4. Archive KDF
parameters are validated against this policy before Argon2id is started.

## Errors
API functions throw `ClearcryptError` with a short message and a `code`.
Codes:
- `INVALID_PARAMS`: a password, KDF profile, or KDF parameter is invalid.
- `INVALID_FORMAT`: data is truncated or structurally invalid.
- `UNSUPPORTED_FORMAT`: the version or an algorithm identifier is unknown.
- `RESOURCE_LIMIT`: archive KDF parameters exceed the local resource policy.
- `AUTH_FAILED`: wrong password or data was tampered with.
- `CRYPTO_FAILED`: a cryptographic operation failed.
- `ENVIRONMENT_ERROR`: the required cryptographic runtime is unavailable.
- `INTERNAL`: an unexpected, unclassified error occurred.

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
The normative binary specification and deterministic vectors are documented in
[`docs/format-v1.md`](docs/format-v1.md).

## File CLI

After building the package, files can be encrypted or decrypted with:

```bash
node scripts/cc-file.mjs encrypt <input> <output>
node scripts/cc-file.mjs decrypt <input> <output>
```

Interactive password input is not echoed. Encryption asks for the password twice;
decryption asks once. Passwords are never trimmed or printed. Use an interactive
terminal rather than piping a password for normal operation.

Stable exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 64 | invalid command-line usage |
| 65 | password input, confirmation, or policy failure |
| 66 | input file could not be read |
| 73 | output file could not be written |
| 74 | cryptographic or runtime failure |

## Compatibility
The API uses WebCrypto-compatible primitives and runs in modern browsers and Node.js 24+.

## Browser tests

The Playwright suite verifies Chromium, Firefox, and WebKit, including
Node/browser archive interoperability, Web Workers, concurrent Argon2 calls,
public errors, and Worker cancellation.

Install the browser runtimes once, build, then run the suite:

```bash
npm run test:browser:install
npm run build
npm run test:browser
```

Use `npm run test:browser -- --project=chromium` to run one engine.

## Release process

Validate a release candidate locally on Node.js 24+:

```bash
npm run release:check
```

`release:check` verifies TypeScript, unit and browser tests, the independent V1
vector, the build, and the exact contents reported by `npm pack --dry-run`.

Publishing is performed only by `.github/workflows/release.yml`. Update
`package.json` and `CHANGELOG.md`, merge through the protected `main` branch,
then push the matching `v<version>` tag. GitHub Actions publishes through npm
Trusted Publishing/OIDC with provenance and creates the GitHub Release. See
`SECURITY.md` for the required repository and npm settings.
