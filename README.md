# horo-next

An unofficial PyPI distribution of [Hermes Agent](https://github.com/NousResearch/hermes-agent).
Not affiliated with, endorsed by, or sponsored by Nous Research.

Upstream stopped publishing to PyPI and its `setup.py` refuses to build wheels
outside Nix. This repository rebuilds each upstream release as a wheel that
installs with `pip` and works.

```bash
pip install horo-next
hermes
```

## How this repository is laid out

This is a fork of `NousResearch/hermes-agent`, but **upstream code is never
committed here**. The default branch, `horo`, holds only the tooling:

| Path | What it does |
|---|---|
| `overlay/horo_overlay.py` | Packaging changes applied to an upstream checkout |
| `overlay/security_bump.py` | Raises direct dependencies that have a published vulnerability fix |
| `overlay/build_frontends.py` | Prebuilds the dashboard and TUI into the package (needs Node 22) |
| `overlay/verify_wheel.py` | Installs the wheel into a clean venv and checks it works |
| `overlay/audit.py` | Checks the Linux / Python 3.12 dependency set against OSV |
| `overlay/extras_map.py` | Maps each package to the features (core or extras) that need it |
| `airgap/probe.py` | Run on an air-gapped machine: which dependencies the mirror serves |
| `pypi/README.md` | The project page shown on PyPI |
| `.github/workflows/release.yml` | Tag → overlay → bump → wheel → verify → TestPyPI → PyPI |

A release is a pure function of *(upstream tag, `overlay/`)*. There is nothing
to merge, so syncing with upstream never conflicts; the only coupling is the
set of anchors the overlay edits.

`main` mirrors upstream and is not used by the release workflow. Leave it
alone: upstream's own workflows live there and run on pushes to it.

## Principles

**Packaging only.** The overlay never changes product behaviour. Every line of
difference from upstream is a line to re-check at each release.

**Fail closed.** Code edits use exact anchors and stop the build if upstream
moved them. Removal steps are checked by their result — no URL dependency
left, every core dependency active on every supported Python — because
upstream's shape legitimately varies between releases.

**Verify by installing, not by building.** Every defect found so far built and
would have uploaded cleanly: missing skills, dependencies absent on some
Pythons, `hermes update` taking a backup then pointing at upstream's installer,
a source checkout in `~/.hermes` reported as this install, and `horo-next[all]`
pulling in the old `hermes-agent` package. Each was caught by installing the
wheel into a clean venv.

**Security bumps on direct dependencies only.** Upstream pins exactly and
bumps by hand; advisories land between releases. A pinned version with a
published fix is raised to the lowest version that fixes it. Transitive
dependencies are left to pip, which already picks the newest available —
adding floors for them would break installs behind mirrors that have not
synced the fix yet.

**Python 3.11 stays supported, and 3.12 is required.** The upper bound
follows each upstream release; horo-next does not vouch for a Python upstream
has not tested. The air-gapped target runs CPython 3.12 on Linux, so a release
that cannot install there stops at the overlay rather than at an install.

**No known advisory in core dependencies on the target.** `overlay/audit.py`
checks the Linux / Python 3.12 dependency set against OSV on both install
paths — the offline list pinned by the lock, and what `pip install horo-next`
resolves today. A core advisory holds the release: a mirror that filters by
CVE refuses the whole install if one core package is blocked. Advisories in
extras are reported in the release notes without holding it.

A clean audit is a snapshot, not a guarantee. PyJWT 2.13.0 was clean when
upstream released v0.21.5 and carried a CRITICAL advisory six days later.
Enterprise mirrors may also use advisory databases other than OSV.

## Releasing

Run the **release** workflow with the upstream tag and version, e.g.
`v2026.9.24` / `0.21.5`. With `publish` off it builds and verifies only.

One-time setup (repository settings and PyPI):

1. Set `horo` as the default branch.
2. Create environments `testpypi` and `pypi`; give `pypi` a required reviewer.
3. On PyPI and TestPyPI, add a pending Trusted Publisher: project `horo-next`,
   owner `iscodesnippet2`, repository `horo-next`, workflow `release.yml`,
   environment `pypi` / `testpypi` respectively.

## Running locally

```bash
git clone --depth 1 --branch v2026.9.24 https://github.com/NousResearch/hermes-agent.git upstream
python overlay/horo_overlay.py upstream 0.21.5
python overlay/security_bump.py upstream --notes release-notes.md
python overlay/build_frontends.py upstream --notes release-notes.md
(cd upstream && uv build --wheel --out-dir ../dist)
python overlay/verify_wheel.py dist/horo_next-0.21.5-py3-none-any.whl 3.12 0.21.5
```

Requires `packaging` and a uv new enough for upstream's lockfile; set
`HORO_UV="uvx --from uv@<version> uv"` if the local uv is older.
