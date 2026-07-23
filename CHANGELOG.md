# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Add typed internal errors and stable public error codes.
- Add decryption resource limits and password input limits.
- Add a Node.js compatibility CI matrix, dependency review, and Dependabot.
- Require explicit, version-pinned approval for dependency install scripts.
- Add npm Trusted Publishing through GitHub OIDC with provenance.
- Verify release tags, the lockfile-based install, the independent format
  vector, and the exact npm tarball contents before publication.
