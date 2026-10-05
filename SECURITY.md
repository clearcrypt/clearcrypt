# Security policy

## Supported versions

ClearCrypt currently provides security updates for the latest `1.x` release.
Pre-release builds and older release lines are not supported.

## Security boundaries

ClearCrypt protects archive contents against an attacker who obtains only the
encrypted bytes, assuming a sufficiently strong password and a trusted client
runtime. It does not protect plaintext or keys from malware, injected browser
scripts, extensions, debuggers, compromised dependencies or a compromised OS.
An attacker who reads a content key can decrypt without learning the password.

Authenticated encryption detects modification; it does not identify the sender
or detect replacement by an older complete valid archive. Applications must
bind archive identity and freshness to trusted external state when required.
Headers and lengths remain visible. Password guessing is offline and cannot
be rate-limited by this library; the input byte limit is not a strength check.

V2 authenticates each DATA record before writing its plaintext, but authenticates
the complete archive only after FINAL and end-of-file. Destinations must remain
unpublished until the operation succeeds. The Node file adapter and CLI use
private temporary files and atomic replacement; use a trusted output directory.
Unix permissions are `0600`; on Windows, directory ACLs control access. A crash
can leave plaintext temporary files, and unlinking is not secure erasure.

KDF limits bound each call, not archive size, total concurrency, elapsed time or
disk consumption. Integrators must apply suitable input limits, quotas and
concurrency limits for untrusted workloads. V1 requires the whole input in
memory. Secret wiping is best-effort; see [memory behavior](docs/memory-v1.md).

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting form:

https://github.com/clearcrypt/clearcrypt/security/advisories/new

Include the affected version, reproduction steps, expected impact, and any
suggested mitigation. Avoid attaching real passwords, keys, or sensitive
plaintext. Maintainers should acknowledge a complete report within three
business days and coordinate disclosure after a fix is available.

## Required repository controls

Repository administrators must:

- enable private vulnerability reporting, the dependency graph, Dependabot
  alerts, and Dependabot security updates;
- protect `main`, require pull requests and approvals, dismiss stale approvals,
  and require the two `Verify / Node …` checks plus `Dependency review`;
- prevent force pushes and branch deletion, and disallow bypassing protections;
- require strong authentication for GitHub maintainers;
- review every `package.json`, `package-lock.json`, and workflow dependency
  change before merging.

Workflows pin third-party actions to commit SHAs. Dependabot proposes updates;
maintainers must inspect the new commit and keep the version comment current.

Install scripts are denied by default through `.npmrc`. Every allowed package
and version must be recorded explicitly in `package.json` after reviewing its
published lifecycle script.

The npm package must configure `.github/workflows/release.yml` as its trusted
publisher, with the `npm` GitHub environment. Maintainers must enable
two-factor authentication on npm and avoid long-lived automation tokens.

## Release invariants

Releases are created only by pushing a `v<version>` tag whose value exactly
matches `package.json`. The tagged commit must belong to `main`. The release
workflow installs the committed lockfile, reruns all checks, verifies the exact
tarball contents, publishes through npm Trusted Publishing/OIDC with
provenance, and creates the matching GitHub Release.
