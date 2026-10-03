# Checking an air-gapped mirror

`probe.py` finds out, on the air-gapped machine itself, which horo-next
dependencies the enterprise package mirror will serve — and what each refusal
costs.

It needs only Python and pip. It installs nothing and changes nothing; it asks
pip to download each package separately and records the result, so one run
gives the complete list instead of stopping at the first failure.

## What to bring

From the horo-next GitHub release for the version you want, for example 0.21.5:

| File | Purpose |
|---|---|
| `probe.py` | the script |
| `requirements-0.21.5.txt` | core dependencies — what `pip install horo-next` needs |
| `requirements-0.21.5-all-extras.txt` | every optional feature's dependencies |
| `extras-map-0.21.5.json` | which features need each package |

## Running it

Core first. If this fails, horo-next cannot be installed at all:

```bash
python3 probe.py requirements-0.21.5.txt --map extras-map-0.21.5.json
```

Then the optional features:

```bash
python3 probe.py requirements-0.21.5-all-extras.txt --map extras-map-0.21.5.json
```

Before a version has been published, add `--no-self`: the script otherwise
also checks `horo-next` itself, which no mirror can have yet, and would report
that horo-next cannot be installed.

pip uses this machine's configuration (`pip.conf`, `PIP_INDEX_URL`,
certificates, proxy). To point at a mirror explicitly, add
`--index-url https://mirror.example/simple`.

To keep everything that downloaded — a ready-made wheelhouse for machines with
no mirror access — add `--dest wheelhouse`.

## Reading the result

| Status | Meaning |
|---|---|
| `ok` | a wheel is available |
| `skipped` | does not apply to this OS or Python (environment marker) |
| `sdist-only` | only source is available; installing needs a compiler |
| `sdist-unbuildable` | only source is available, and it fails to build on this Python |
| `blocked` | the mirror refused it (HTTP 403 — usually a security policy) |
| `missing` | not on the mirror, or not in the requested version |

For a missing package the script lists the versions the mirror does have, which
shows whether a different version would be accepted.

The summary at the end states plainly whether horo-next installs, and which
features would be unavailable.

`airgap-probe-report.json` is written next to the requirements file. Bring it
back for analysis; user names and passwords in index URLs are removed from it.

Exit status: `0` all available, `1` something unavailable, `2` mirror unreachable.
