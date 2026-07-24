# Security review of `argon2-browser`

Review date: 2026-07-24  
Reviewed package: `argon2-browser@1.18.0`

## Decision

Keep `argon2-browser` temporarily for CFENC001 compatibility, pin it to exactly
`1.18.0`, and isolate it behind environment-specific adapters.

The package has no runtime dependencies and its output matches the independent
CFENC001 vector. Replacing it now would add compatibility risk before the
browser interoperability matrix exists. This is not an endorsement of its
maintenance status: npm reports that version `1.18.0` was published roughly
five years before this review, and the last upstream commit on `master` is
dated 2021-11-13.

Sources reviewed:

- https://www.npmjs.com/package/argon2-browser
- https://github.com/antelle/argon2-browser
- https://github.com/antelle/argon2-browser/commits/master/

## Audited behavior

- ClearCrypt requests Argon2id (`type = 2`) explicitly.
- The wrapper calls the reference implementation with version `0x13`, encoded
  as `v=19`, which is Argon2 version 1.3.
- The non-SIMD WASM shipped by `argon2-browser@1.18.0` is 25,725 bytes.
- Its SHA-256 digest is
  `0c2149886c13e4eae4a6ca25ee71d47423c5c8740a874cf04ff816d1b2c901d7`.
- The npm lockfile also records the registry tarball integrity.

The Node adapter validates both the WASM structure and this digest before first
use. Every result must identify `$argon2id$v=19$` and contain a 32-byte hash.

## Integration controls

- Node and browser loading live in separate adapters and package artifacts.
- Conditional package exports select `dist/index.js` for Node and
  `dist/browser.js` for browser-aware bundlers.
- CI rebundles the browser artifact with esbuild and rejects Node built-ins.
- Node's required UMD/Emscripten globals are installed only in small synchronous
  scopes and their previous property descriptors are restored.
- The module initialization promise is cached.
- Operations are serialized because the dependency shares one mutable
  Emscripten heap.
- Concurrent first use, global restoration, WASM metadata, deterministic
  vectors, and archive decryption are covered by tests.

## Residual risks and replacement criteria

The dependency uses an old Emscripten wrapper and remains a maintenance risk.
The dedicated browser artifact bundles without Node built-ins, but P1.1 does
not claim runtime interoperability across browsers. Do not upgrade or replace
it without all of the following:

1. identical Argon2id v1.3 output for every committed vector;
2. successful decryption of existing CFENC001 archives;
3. Node, Chromium, Firefox, WebKit, and Web Worker tests;
4. concurrent-call and memory-limit tests;
5. an audited WASM artifact and reproducible provenance;
6. no new public format or KDF identifier unless outputs differ.

The browser interoperability requirements are handled in P1.3. Reconsider the
dependency after that matrix is available.
