# V1 memory behavior and secret lifetime

`CFENC001` is a buffer-based format. Encryption and decryption require the
complete input and produce a complete output in memory; V1 is not streaming.

## Security statement

The precise project statement is:

> Le cœur ne persiste ni ne transmet volontairement le plaintext, les mots de
> passe ou les clés. Ces valeurs existent temporairement dans la mémoire du
> processus client pendant l’opération cryptographique.

In English: the core does not intentionally persist or transmit plaintext,
passwords, or keys. Those values temporarily exist in client-process memory
during the cryptographic operation.

This is not a claim that secrets never enter memory. Plaintext, password bytes,
the Argon2-derived key-encryption key (KEK), the data-encryption key (DEK), and
cryptographic runtime state all exist in memory while they are needed.

## Buffer ownership and best-effort wiping

ClearCrypt overwrites package-owned temporary byte buffers in `finally` blocks
when their operation completes:

| Buffer | Owner | ClearCrypt behavior |
| --- | --- | --- |
| UTF-8 encoding of a string password | package | overwritten after the public or low-level operation |
| Argon2 output / raw KEK | package | overwritten after DEK wrapping or unwrapping |
| generated or unwrapped raw DEK | package | overwritten after content encryption or decryption |
| plaintext supplied for encryption | caller | never modified by ClearCrypt |
| password supplied as `Uint8Array` | caller | never modified by ClearCrypt |
| returned plaintext or archive | caller | remains valid; caller controls its lifetime |
| `CryptoKey`, WebCrypto internals, Argon2 WASM state | runtime | cannot be directly overwritten by ClearCrypt |

This wiping is best-effort, not guaranteed zeroization. JavaScript engines may
move or copy values, immutable strings cannot be overwritten, and WebCrypto,
WebAssembly, browser IPC, debugging tools, crash dumps, swap, or the operating
system may retain copies outside the controlled `Uint8Array`. Garbage
collection timing is also not under application control. Wiping a raw key
buffer does not prove that an imported `CryptoKey` or a runtime copy has been
erased.

Best-effort wiping must not alter caller-owned buffers. Applications that pass a
password as `Uint8Array` may overwrite that buffer themselves after the returned
promise settles, provided it is no longer needed. A JavaScript string password
cannot be zeroized by either the package or the caller.

## Peak-memory model

Let:

- `P` be the plaintext size;
- `N = P + 125` be the V1 archive size;
- `M` be the selected Argon2 memory cost;
- `R` be implementation-dependent runtime overhead.

These are capacity-planning approximations, not hard upper bounds:

| Operation | Approximate simultaneously live buffers |
| --- | --- |
| Decryption | caller archive `N` + returned plaintext `P` + Argon2 `M` + `R` |
| Encryption | caller plaintext `P` + WebCrypto output about `P + 16` + final archive `N` + Argon2 `M` + `R` |

During decryption, the V1 parser creates only `Uint8Array.subarray()` views over
the caller-owned archive. The 109-byte AAD, fixed fields, ciphertext, and
16-byte tag share that archive buffer. The package does not allocate a
payload-sized parser copy or a second ciphertext-plus-tag buffer when the two
fields are contiguous.

During encryption, WebCrypto produces a ciphertext-and-tag result and
serialization produces the final archive. The 109-byte V1 AAD is materialized
once. Engine and WebCrypto implementations may make additional unobservable
copies, so measured RSS can exceed the visible JavaScript buffers.

Argon2's `memoryCost` is expressed in KiB and applies to the KDF itself. The
decryption resource policy checks it before Argon2 starts, but
`maxMemoryCostKiB` is not a limit on total process memory, archive size,
plaintext size, WebCrypto allocation, or Worker memory.

Within one JavaScript realm, ClearCrypt serializes calls into the shared
`argon2-browser` runtime. Separate Web Workers have separate runtimes and can
therefore multiply Argon2 memory consumption. A Worker avoids blocking the UI;
it does not reduce the memory required by the operation. Sending buffers to a
Worker without using transfer semantics may also create structured-clone copies.

## Application file-size limits

The npm package cannot choose one safe V1 file-size limit for every device.
Browser and desktop applications must reject files that exceed a locally tested
limit before calling the V1 API. Budget at least for the buffers in the table
above, the chosen Argon2 profile, and a device-specific safety margin.

The application should consider:

- supported device memory and 32-bit versus 64-bit constraints;
- other live application data and concurrent Workers;
- browser tab/process memory limits;
- whether input and output buffers are copied across API or Worker boundaries;
- the measured results from representative low-end devices.

Do not describe V1 as streaming and do not split one AES-GCM ciphertext into
ad-hoc chunks. True large-file and resumable operation requires a separately
specified and audited chunk-authenticated format such as a future `CFENC002`.

## Node benchmark

Run the reproducible proxy benchmark after building the package:

```bash
npm run build
npm run benchmark:memory:v1 -- 32
```

The script requires `--expose-gc`, which is included in the npm command. It
measures decryption of a 32 MiB plaintext and samples Node's RSS and reported
`arrayBuffers`. These figures are an engineering comparison, not browser memory
guarantees or a zeroization test.

Reference runs on Node.js 24.18.0, Windows:

| Implementation | Duration | Peak RSS delta | Peak `arrayBuffers` delta |
| --- | ---: | ---: | ---: |
| Before P0.3, 21 July 2026 | 55 ms | 38.6 MiB | 64.0 MiB |
| Current P1.5, 24 July 2026 (3 runs) | 32–33 ms | 0.9–2.4 MiB | 0 MiB |

The reduction comes from retaining views over the archive, reusing its AAD, and
passing its already-contiguous ciphertext and tag directly to WebCrypto.
