# Reviewing horo-next

For whoever evaluates horo-next for use inside an organisation — written with
Sonatype (Lifecycle / IQ Server, Nexus Firewall) in mind, but nothing here is
specific to one product.

## What it is

An unofficial PyPI repackaging of [Hermes Agent](https://github.com/NousResearch/hermes-agent)
(MIT, Nous Research). Upstream stopped publishing to PyPI after 0.19.0 and
blocks wheel builds outside Nix. horo-next rebuilds each upstream release tag
as a wheel. The changes are packaging only; they are listed, with the reason
for each, in [`overlay/horo_overlay.py`](../overlay/horo_overlay.py).

- `horo-next X.Y.Z` = upstream `vX.Y.Z` (for 0.21.5: tag `v2026.9.24`).
- Same command (`hermes`) and data directory (`~/.hermes`) as upstream.
- Do not install alongside `hermes-agent`: both provide the same modules.

## Why it may look unfamiliar to a scanner

| What the scanner sees | What it is | Where it is described |
|---|---|---|
| A new, low-popularity PyPI project | A repackaging of a widely used project under a new name | SBOM `metadata.component.pedigree` names the upstream tag it was built from |
| ~7 MB of minified JavaScript (`hermes_cli/web_dist`, `hermes_cli/tui_dist`) with no `package.json` | Upstream's dashboard and terminal UI, compiled at build time | Every npm package inside them is a component in the SBOM, with `horo:bundled-in` |
| Skills, locales and MCP definitions under `hermes_cli/_bundled/` | Upstream's asset directories, moved inside the package so a wheel can find them | `overlay/horo_overlay.py` step 5 |

## How to evaluate it

1. **Import the SBOM**, not the wheel alone. `horo-next-X.Y.Z.cdx.json` from
   the GitHub release (CycloneDX 1.5, validated against the schema at build
   time). Components are identified by purl — `pkg:pypi/…` for Python,
   `pkg:npm/…` for what is compiled into the JavaScript — which is how
   Sonatype matches components. The copy inside the wheel
   (`.dist-info/sboms/horo-next.cdx.json`) is identical except that it cannot
   carry the wheel's own hash.
2. **Check the wheel is the one the workflow built.** Its SHA-256 is in the
   release SBOM (`metadata.component.hashes`) and in the PyPI attestation
   (Trusted Publishing, PEP 740) on the PyPI file page.
3. **Compare with our audit.** `audit-X.Y.Z.json` lists every package checked
   against OSV for Linux / CPython 3.12 and every finding; a release is not
   published with any. Sonatype's database differs from OSV, so differences
   are possible — a finding of yours that is absent from ours is worth
   reporting (see [SECURITY.md](../SECURITY.md)).

## Scope of the SBOM

- **Python, core** (`scope: required`, `horo:installed-by=core`): what
  `pip install horo-next` installs.
- **Python, extras** (`scope: optional`, `horo:extras=…`): installed only with
  that extra, e.g. `horo-next[web]`. Environment markers are kept as
  `horo:environment-marker`; a Windows-only package does not install on Linux.
- **npm, bundled** (`horo:bundled-in=dashboard|tui`): read from the bundles'
  own build output (sourcemaps for the dashboard, module markers for the TUI),
  so it lists what is inside them — not the whole dependency tree.
- **Not included**: upstream's Electron desktop app, its installer and its
  test tooling. They are part of upstream's repository but not built into
  horo-next; advisories against them do not apply to it.

## Licenses

horo-next and Hermes Agent: MIT. Each component's declared license is in the
SBOM; npm packages compiled into the bundles have their license texts in
`THIRD_PARTY_LICENSES` (inside the wheel under `.dist-info/licenses/`, and on
the release page). A few Python extras' upstream metadata declares no license;
those components carry none in the SBOM rather than a guess.
