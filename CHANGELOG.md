# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add the provisional `CFENC002` streaming format and public
  `encryptStreamV2` / `decryptStreamV2` APIs with bounded buffers,
  backpressure, cancellation, progress reporting, segmented content keys, and
  authenticated termination.
- Add the Node.js `clearcrypt/node` file adapter and streaming V2 CLI commands
  with atomic destination replacement, progress, signal cancellation, and
  stable filesystem error codes.
- Validate V2 streaming inside Web Workers on Chromium, Firefox, and WebKit,
  including UI responsiveness, bounded backpressure, cooperative cancellation,
  and Worker closure.
- Publish normative `CFENC002` vectors for empty, Unicode/binary, multi-block,
  segment-transition, and FINAL cases with an independent primitive-only
  verifier shared by Node.js and browser tests.

## [1.1.0] - 2026-07-25

### Security

- Document the temporary in-memory lifetime of secrets and best-effort wiping,
  and clear package-owned password, KEK, and DEK buffers in `finally` blocks.
- Add deterministic property tests, full-header and truncation mutation checks,
  an invalid corpus, and scheduled parser fuzzing with resource-allocation guards.
- Add Playwright interoperability tests on Chromium, Firefox, and WebKit,
  including Web Workers, concurrent calls, failures, and cancellation.
- Version the Argon2id profiles and add reproducible Node.js and browser
  benchmarks for latency, memory, concurrency, UI blocking, and Web Workers.
- Pin and isolate `argon2-browser@1.18.0`, validate its audited WASM, enforce
  Argon2id v1.3 output, and serialize access to its shared runtime.
- Add typed internal errors and stable public error codes.
- Add decryption resource limits and password input limits.
- Add a Node.js compatibility CI matrix, dependency review, and Dependabot.
- Require explicit, version-pinned approval for dependency install scripts.
- Add npm Trusted Publishing through GitHub OIDC with provenance.
- Verify release tags, the lockfile-based install, the independent format
  vector, and the exact npm tarball contents before publication.
