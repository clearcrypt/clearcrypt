# V1 memory behavior

`CFENC001` remains a buffer-based format. Encryption and decryption require the
complete input and produce a complete output in memory; this is not streaming.

## Peak-memory model

During decryption, the V1 parser creates only `Uint8Array.subarray()` views over
the caller-owned archive. The AAD, fixed fields, ciphertext, and tag share that
archive buffer. The package does not allocate a payload-sized parser copy or a
second ciphertext-plus-tag buffer when those fields are contiguous.

The caller must still budget for:

- the complete encrypted archive;
- the complete plaintext returned by WebCrypto;
- the Argon2id WASM memory selected by the archive and allowed by the local
  resource policy;
- implementation-dependent temporary memory inside WebCrypto and the JavaScript
  engine.

During encryption, peak memory also includes the caller-owned plaintext, the
WebCrypto ciphertext result, and the final serialized archive. The small V1 AAD
is materialized once for encryption. JavaScript and WebCrypto do not provide a
portable guarantee that their internal copies can be measured or zeroized.

Browser applications must enforce a temporary file-size limit before calling
the V1 API. The appropriate limit depends on the supported devices and must be
benchmarked by the application; the npm package does not pretend to provide
streaming or impose a universal file-size limit.

## Node benchmark

Run the reproducible proxy benchmark after building the package:

```bash
npm run build
npm run benchmark:memory:v1 -- 32
```

The script requires `--expose-gc`, which is included in the npm command. It
measures decryption of a 32 MiB plaintext and samples Node's RSS and reported
`arrayBuffers`. These figures are an engineering comparison, not browser memory
guarantees.

Reference run on Node.js 24.18.0, Windows, 21 July 2026:

| Implementation | Duration | Peak RSS delta | Peak `arrayBuffers` delta |
| --- | ---: | ---: | ---: |
| Before P0.3 | 55 ms | 38.6 MiB | 64.0 MiB |
| After P0.3 (3 runs) | 28–31 ms | 0.4–3.0 MiB | 0 MiB |

The large reduction comes from retaining views over the archive, reusing its AAD,
and passing its already-contiguous ciphertext and tag directly to WebCrypto.
