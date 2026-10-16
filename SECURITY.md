# Security policy

horo-next is an unofficial PyPI distribution of
[Hermes Agent](https://github.com/NousResearch/hermes-agent). It repackages
upstream releases; it does not change what the software does.

## Reporting a vulnerability

- **In Hermes Agent's own code**: report it to upstream, following
  [their security policy](https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md).
  A fix reaches horo-next with the next upstream release built here.
- **In horo-next's packaging** (the overlay, the wheel's contents, the release
  workflow, a dependency version chosen here): open a private advisory at
  <https://github.com/iscodesnippet2/horo-next/security/advisories/new>.

## Supported versions

Only the latest release. A dependency fix on the same upstream release is
published as `X.Y.Z.postN`.

## What every release is checked for

A release is built and published only by the `release` workflow, from an
upstream tag, with no step done by hand. It stops before publishing if any of
these fails:

- **Known vulnerabilities — none allowed.** Every Python dependency, core and
  every optional extra, is checked against [OSV](https://osv.dev) for the
  target platform (Linux, CPython 3.12) — and, with every npm package compiled
  into the bundles, against Sonatype's data too (the Sonatype Guide /
  OSS Index API), which is what a Sonatype-filtered mirror judges by. Direct dependencies with a published
  fix are raised to it; transitive ones are raised in the lock. Anything left
  holds the release.
- **Bundled JavaScript.** The dashboard and terminal UI are compiled from
  upstream's locked npm dependencies (`npm ci --ignore-scripts`). npm packages
  with a published fix are raised; a front end that still carries an advisory
  is left out of the wheel.
- **Upstream's 14-day cooldown is kept**: a just-published release is where a
  compromised maintainer account shows up first. A Python security fix still
  inside it is let through by name, up to that fix's own upload time — as
  upstream does by hand — and the release notes list each exception. npm fixes
  wait out the cooldown.
- **The wheel is installed and exercised** in clean environments on every
  supported Python before it is published.

## What every release publishes

Attached to each [GitHub release](https://github.com/iscodesnippet2/horo-next/releases):

| File | Contents |
|---|---|
| `horo-next-X.Y.Z.cdx.json` | CycloneDX 1.5 SBOM: every Python dependency, every npm package compiled into the bundles, the wheel's SHA-256, and the upstream release it was built from |
| `audit-X.Y.Z.json` | The vulnerability audit: when, against which database, every package checked, every finding |
| `THIRD_PARTY_LICENSES.txt` | License texts of the npm packages compiled into the bundles |
| `requirements-X.Y.Z-hashes.txt` | The core dependency set with hashes, for `pip install --require-hashes` |

The same SBOM is inside the wheel at `.dist-info/sboms/` (PEP 770), and the
license notices at `.dist-info/licenses/`.

PyPI uploads use [Trusted Publishing](https://docs.pypi.org/trusted-publishers/):
no upload token exists. PyPI verifies that the file came from this repository's
`release` workflow, and records a signed attestation of it (PEP 740).

For a security reviewer: [docs/security-review.md](docs/security-review.md).
