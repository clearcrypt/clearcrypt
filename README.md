# ClearCrypt

**Auditable client-side file encryption for browsers, Node.js and AI-agent workflows.**

ClearCrypt encrypts files locally with Argon2id and AES-256-GCM before
upload, transfer, backup or archival. The library does not transmit plaintext,
passwords or encryption keys.

It produces a public, versioned and self-describing encrypted archive format
that can be decrypted offline without the ClearCrypt service.

## Requirements
- Node.js 24 or newer.

## Public API (stable)
The stable API surface is:
- `encryptBytesV1(plaintext, password, options?)`
- `decryptBytesV1(data, password, options?)`
- `encryptStreamV2(source, destination, password, options?)`
- `decryptStreamV2(source, destination, password, options?)`

All other modules are internal and may change.

The V2 streaming API is implemented, but the `CFENC002` format remains
provisional until its independent cryptographic review is complete.

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
- The V1 API is buffer-based (`Uint8Array` in / `Uint8Array` out).
- The V2 API uses WHATWG `ReadableStream<Uint8Array>` and
  `WritableStream<Uint8Array>` with backpressure and bounded internal buffers.
- For browser UI apps (Angular, React, etc.), run crypto operations in a Web Worker to avoid blocking the main thread.
- The reference browser integration, required capabilities, progressive
  destinations, and Worker lifecycle are documented in
  [`docs/browser-v2.md`](docs/browser-v2.md).
- The KDF resource policy limits Argon2 parameters, not the archive or plaintext size.
- See [`docs/memory-v1.md`](docs/memory-v1.md) for buffer ownership, secret
  lifetime, the peak-memory model, and benchmark.

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

encryptStreamV2(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  password: Uint8Array | string,
  options?: V2EncryptOptions
): Promise<V2OperationResult>

decryptStreamV2(
  source: ReadableStream<Uint8Array>,
  destination: WritableStream<Uint8Array>,
  password: Uint8Array | string,
  options?: V2DecryptOptions
): Promise<V2OperationResult>
```

V2 uses a 4 MiB chunk by default. Encryption accepts a power-of-two `chunkSize`
from 64 KiB through 16 MiB and optional Argon2id settings under `kdf`.
Both operations accept an `AbortSignal` and a synchronous `onProgress` callback.
Progress is emitted at phase transitions and after successful records rather
than for every source chunk.

`V2OperationResult` contains `bigint` counters named `inputBytes`,
`outputBytes`, and `records`, plus `format: "CFENC002"`.

On any error or cancellation, ClearCrypt cancels the source and aborts the
destination where possible. Bytes already written may remain physically
present. Use a temporary or transactional destination and publish it only after
the returned promise resolves successfully.

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
- `ABORTED`: a V2 streaming operation was cancelled through its `AbortSignal`.
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
Both file formats are self-describing. Header/AAD fields are stored in cleartext
but authenticated, while payloads remain encrypted. V1 is specified in
[`docs/format-v1.md`](docs/format-v1.md). The provisional streaming format is
specified in [`docs/format-v2.md`](docs/format-v2.md).

## File CLI

After building the package, files can be encrypted or decrypted with:

```bash
node scripts/cc-file.mjs encrypt <input> <output>     # V1, in memory
node scripts/cc-file.mjs decrypt <input> <output>     # V1, in memory
node scripts/cc-file.mjs encrypt-v2 <input> <output>  # V2, streaming
node scripts/cc-file.mjs decrypt-v2 <input> <output>  # V2, streaming
```

Interactive password input is not echoed. Encryption asks for the password twice;
decryption asks once. Passwords are never trimmed or printed. Use an interactive
terminal rather than piping a password for normal operation.

The V2 commands report progress on standard error and keep memory bounded by the
configured block size. They write to a temporary file beside the requested output
and replace the destination only after the archive has been completely processed
and authenticated. A wrong password, disk error, or interruption therefore leaves
an existing destination unchanged. `SIGINT` and `SIGTERM` cancel the operation.

Node.js applications can use the same atomic file adapter:

```ts
import { decryptFileV2, encryptFileV2 } from "clearcrypt/node";

await encryptFileV2("archive.tar", "archive.tar.cc2", password, {
  signal: abortController.signal,
  onProgress: ({ inputBytes, records }) => {
    console.log(inputBytes, records);
  },
});

await decryptFileV2("archive.tar.cc2", "archive.tar", password);
```

Stable exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 64 | invalid command-line usage |
| 65 | password input, confirmation, or policy failure |
| 66 | input file could not be read |
| 73 | output file could not be written |
| 74 | cryptographic failure, runtime failure, or V2 interruption |

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

## Property tests and parser fuzzing

The regular Vitest suite includes deterministic `fast-check` properties for
binary round trips, every fixed header field, every truncation offset, extreme
payload lengths, invalid inputs, and KDF resource-policy enforcement.

Run a longer parser-only fuzz campaign with a reproducible seed:

```bash
npm run test:fuzz
npm run test:fuzz -- --runs 50000 --seed 847873
```

When a property fails, keep the reported seed and counterexample with the bug
report. The scheduled CI campaign uses the same checked-in invalid corpus.

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

## AI agents and automated workflows

ClearCrypt can be invoked by an authorized AI agent, browser automation,
or another automated workflow.

The user or organization decides whether the agent is allowed to access:

- the plaintext files;
- the encryption password or secret;
- the resulting encrypted archive.

Encryption runs in the caller's browser or Node.js environment. ClearCrypt does
not upload or transmit plaintext, passwords, KEKs or DEKs.

Typical agent workflows include:

- encrypting files before cloud or object-storage upload;
- preparing encrypted backups;
- encrypting completed project archives;
- creating encrypted data for cold storage;
- encrypting files before transfer to an external service.

### example

import { encryptBytesV1 } from "clearcrypt";

const plaintext = await loadFileBytes();
const secret = await getSecretFromAuthorizedAgentEnvironment();

const encryptedArchive = await encryptBytesV1(
  plaintext,
  secret,
  { kdfProfile: "hardened-v1" }
);

await uploadEncryptedArchive(encryptedArchive);

The upload function is intentionally outside ClearCrypt. The package only
produces encrypted bytes. Integrators remain responsible for storage,
authentication, authorization and secret management.

### Use ClearCrypt when

- files must be encrypted before leaving the user's device;
- the storage provider must not receive plaintext or encryption keys;
- encrypted archives must remain decryptable offline;
- a browser, Node.js application or authorized AI agent performs encryption;
- an open and versioned encrypted file format is required.

### ClearCrypt does not provide

- cloud or cold storage;
- password recovery;
- server-side encryption;
- file synchronization;
- streaming encryption in the CFENC001 format;
- HDS-certified health-data hosting.
