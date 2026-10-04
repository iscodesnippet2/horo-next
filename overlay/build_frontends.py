"""Build the dashboard and TUI front ends into the package before the wheel.

    python overlay/build_frontends.py <upstream-checkout> [--notes FILE]

Both are TypeScript projects. A source install builds them on the user's
machine with npm the first time they are used; a wheel has no source to build
from, so `hermes dashboard` would exit and the dashboard's Chat tab and
`hermes --tui` would have nothing to run. Upstream already looks for prebuilt
copies in the two places used here — hermes_cli/web_dist/ and
hermes_cli/tui_dist/entry.js — which is where its own Nix and Docker builds put
them. Nothing in upstream code changes.

The result is that the air-gapped machine never runs npm for these: the
dashboard needs nothing but the [web] extra, and the TUI needs only a `node`
binary (the bundle is self-contained).

npm runs with --ignore-scripts: install scripts are where npm supply-chain
attacks execute, and neither build needs one. Dependencies come from upstream's
package-lock.json (npm ci), so the bundled JavaScript is exactly what upstream
locked.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

WORKSPACES = ["web", "ui-tui"]


def run(cmd: list[str], cwd: Path) -> None:
    print(f"[frontends] $ {' '.join(cmd)}  (in {cwd.name}/)", flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


def audit(root: Path) -> list[str]:
    """npm's advisory counts for what ends up in the bundles. Reported, not held:
    these are compiled into static files, and npm audit cannot tell which
    advisories reach code the bundle actually contains."""
    cmd = ["npm", "audit", "--json", "--omit=dev", *[f"--workspace={w}" for w in WORKSPACES]]
    r = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    try:
        report = json.loads(r.stdout)
        counts = report["metadata"]["vulnerabilities"]
    except (ValueError, KeyError):
        return ["- npm audit did not produce a report "
                f"(exit {r.returncode}): {(r.stderr or r.stdout).strip()[:200]}"]
    found = {k: v for k, v in counts.items() if k != "total" and v}
    if not found:
        return ["- npm audit (runtime dependencies of web, ui-tui): no advisories"]
    lines = [f"- npm audit (runtime dependencies of web, ui-tui): "
             + ", ".join(f"{v} {k}" for k, v in found.items())]
    for name, v in sorted(report.get("vulnerabilities", {}).items()):
        via = [x.get("title", "") for x in v.get("via", []) if isinstance(x, dict)]
        lines.append(f"  - {name} ({v.get('severity')}): {'; '.join(via)[:200] or 'via ' + ', '.join(map(str, v.get('via', [])))}")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("checkout", type=Path)
    ap.add_argument("--notes", type=Path)
    args = ap.parse_args()
    root = args.checkout.resolve()
    pkg = root / "hermes_cli"

    if not shutil.which("npm") or not shutil.which("node"):
        sys.exit("[frontends] node and npm are required")

    run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund",
         "--include-workspace-root=false", *[f"--workspace={w}" for w in WORKSPACES]], root)

    # Dashboard: vite writes to hermes_cli/web_dist (web/vite.config.ts outDir).
    web_dist = pkg / "web_dist"
    shutil.rmtree(web_dist, ignore_errors=True)
    run(["node", "../node_modules/typescript/bin/tsc", "-b"], root / "web")
    run(["node", "../node_modules/vite/bin/vite.js", "build"], root / "web")
    if not (web_dist / "index.html").is_file():
        sys.exit(f"[frontends] dashboard build produced no {web_dist}/index.html")

    # TUI: esbuild writes one self-contained ui-tui/dist/entry.js.
    run(["node", "ui-tui/scripts/build.mjs"], root)
    entry = root / "ui-tui" / "dist" / "entry.js"
    if not entry.is_file():
        sys.exit(f"[frontends] TUI build produced no {entry}")
    tui_dist = pkg / "tui_dist"
    shutil.rmtree(tui_dist, ignore_errors=True)
    tui_dist.mkdir()
    shutil.copy2(entry, tui_dist / "entry.js")
    # The bundle is an ES module; node decides that from the nearest
    # package.json. Upstream's Nix build ships ui-tui/package.json beside it
    # for the same reason. Only the field node reads is kept.
    (tui_dist / "package.json").write_text('{"type": "module"}\n', encoding="utf-8")

    size = lambda p: sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) / 1e6  # noqa: E731
    print(f"[frontends] ok   hermes_cli/web_dist ({size(web_dist):.1f} MB)")
    print(f"[frontends] ok   hermes_cli/tui_dist ({size(tui_dist):.1f} MB)")

    notes = ["", "## Front ends", "",
             "The dashboard and TUI are prebuilt into the wheel from upstream's "
             "package-lock.json; the target machine does not run npm for them.", "",
             *audit(root)]
    print("\n".join(notes))
    if args.notes:
        with args.notes.open("a", encoding="utf-8") as f:
            f.write("\n".join(notes) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
