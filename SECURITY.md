# Security policy

## Supported versions

ClearCrypt currently provides security updates for the latest `1.x` release.
Pre-release builds and older release lines are not supported.

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
