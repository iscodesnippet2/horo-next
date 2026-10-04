"""Build the dashboard and TUI front ends into the package before the wheel.

    python overlay/build_frontends.py <upstream-checkout> [--notes FILE]

Both are TypeScript projects. A source install builds them on the user's
machine with npm the first time they are used; a wheel has no source to build
from, so `hermes dashboard` would exit and the dashboard's Chat tab and
`hermes --tui` would have nothing to run. Upstream already looks for prebuilt
copies in the two places used here — hermes_cli/web_dist/ and
hermes_cli/tui_dist/entry.js — which is where its own Nix and Docker builds put
them.

The result is that the air-gapped machine never runs npm for these: the
dashboard needs nothing but the [web] extra, and the TUI needs only a `node`
binary (the bundle is self-contained).

Security, in the same spirit as security_bump.py for Python:

* Packages with a published advisory are raised to the nearest fixed version
  in the same major, if that version is past upstream's npm cooldown
  (.npmrc min-release-age=14). Upstream's own pins and overrides are edited in
  place; anything else gets a root override.
* A front end that still carries an advisory afterwards is NOT bundled. The
  wheel ships without it — exactly as before this script existed — and the
  release notes say why. npm audit cannot tell whether vulnerable code reaches
  a bundle, so presence in the dependency tree is treated as presence in the
  wheel.

npm runs with --ignore-scripts: install scripts are where npm supply-chain
attacks execute, and neither build needs one.

Writes the bundled front ends to horo-build.json ("frontends") so the verify
step checks each one is present — and each dropped one absent.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# name in horo-build.json → (npm workspace, packaged directory)
FRONTENDS = {"dashboard": ("web", "web_dist"), "tui": ("ui-tui", "tui_dist")}
# Upstream's .npmrc: min-release-age=14. A fix newer than that is reported, not taken.
COOLDOWN_DAYS = 14
# Package manifests whose pins a bump may edit: the root and every workspace a
# front end builds from (web imports apps/shared).
MANIFESTS = ["package.json", "web/package.json", "ui-tui/package.json", "apps/shared/package.json"]


def run(cmd: list[str], cwd: Path) -> None:
    print(f"[frontends] $ {' '.join(cmd)}  (in {cwd.name}/)", flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


# ── semver, just enough for npm advisory ranges ─────────────────────────────
def vtuple(v: str) -> tuple[int, ...] | None:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", v.strip())
    return tuple(map(int, m.groups())) if m else None


def satisfies(version: str, rng: str) -> bool:
    """npm range as printed by npm audit: `||` of space-separated comparators,
    or `a - b`. Unknown syntax counts as affected — fail closed."""
    v = vtuple(version)
    if v is None:
        return True
    for alt in rng.split("||"):
        alt = alt.strip()
        if alt in ("", "*"):
            return True
        hyphen = re.fullmatch(r"(\S+)\s+-\s+(\S+)", alt)
        comps = [f">={hyphen.group(1)}", f"<={hyphen.group(2)}"] if hyphen else alt.split()
        ok = True
        for c in comps:
            m = re.fullmatch(r"(>=|<=|>|<|=)?(\S+)", c)
            b = vtuple(m.group(2)) if m else None
            if b is None:
                return True
            op = m.group(1) or "="
            ok &= {"<": v < b, "<=": v <= b, ">": v > b, ">=": v >= b, "=": v == b}[op]
        if ok:
            return True
    return False


# ── audit and bump ──────────────────────────────────────────────────────────
def audit(root: Path, workspace: str) -> dict:
    """{package: {"installed": [...], "ranges": [...], "advisories": [...]}} for
    the runtime dependencies of one workspace."""
    r = subprocess.run(["npm", "audit", "--json", "--omit=dev", f"--workspace={workspace}"],
                       cwd=root, capture_output=True, text=True)
    try:
        vulns = json.loads(r.stdout)["vulnerabilities"]
    except (ValueError, KeyError):
        sys.exit(f"[frontends] npm audit for {workspace} produced no report "
                 f"(exit {r.returncode}): {(r.stderr or r.stdout).strip()[:300]}")
    out = {}
    for name, v in vulns.items():
        advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
        if not advisories:
            continue  # only flagged because it depends on a flagged package
        installed = set()
        for node in v.get("nodes", []):
            pj = root / node / "package.json"
            if pj.is_file():
                installed.add(json.loads(pj.read_text(encoding="utf-8"))["version"])
        out[name] = {"installed": sorted(installed), "ranges": [a["range"] for a in advisories],
                     "advisories": [f"{a.get('severity')} {a.get('url', '').rsplit('/', 1)[-1]} "
                                    f"{a.get('title', '')}" for a in advisories]}
    return out


def nearest_fix(name: str, installed: str, ranges: list[str]) -> tuple[str | None, str]:
    """Smallest release above `installed`, same major, outside every advisory
    range, older than the cooldown. Returns (version, reason-if-none)."""
    r = subprocess.run(["npm", "view", name, "time", "--json"], capture_output=True, text=True)
    try:
        times = json.loads(r.stdout)
    except ValueError:
        return None, f"cannot list {name} releases"
    cur = vtuple(installed)
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=COOLDOWN_DAYS)
    waiting = None
    for ver, when in sorted(((k, t) for k, t in times.items() if vtuple(k)), key=lambda kv: vtuple(kv[0])):
        vt = vtuple(ver)
        if cur is None or vt <= cur or vt[0] != cur[0]:
            continue
        if any(satisfies(ver, rg) for rg in ranges):
            continue
        published = dt.datetime.fromisoformat(when.replace("Z", "+00:00"))
        if published > cutoff:
            waiting = waiting or (ver, published + dt.timedelta(days=COOLDOWN_DAYS))
            continue
        return ver, ""
    if waiting:
        return None, f"fix {waiting[0]} is in the {COOLDOWN_DAYS}-day cooldown until {waiting[1]:%Y-%m-%d}"
    return None, f"no fixed release in major {cur[0] if cur else '?'}"


def pin(root: Path, name: str, version: str) -> str:
    """Raise `name` to `version`: upstream's own override or exact pin if it has
    one (an override that disagrees with a direct pin is an npm error), else a
    root override."""
    rootpj = root / "package.json"
    data = json.loads(rootpj.read_text(encoding="utf-8"))
    if name in data.get("overrides", {}):
        data["overrides"][name] = version
        rootpj.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return "upstream override"
    edited = []
    for rel in MANIFESTS:
        pj = root / rel
        if not pj.is_file():
            continue
        d = json.loads(pj.read_text(encoding="utf-8"))
        hit = [s for s in ("dependencies", "devDependencies", "optionalDependencies")
               if name in d.get(s, {})]
        for section in hit:
            d[section][name] = version
        if hit:
            pj.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
            edited.append(rel)
    if edited:
        return "pin in " + ", ".join(edited)
    data.setdefault("overrides", {})[name] = version
    rootpj.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return "new root override"


def install(root: Path, locked: bool) -> None:
    workspaces = [f"--workspace={w}" for w, _ in FRONTENDS.values()]
    verb = "ci" if locked else "install"
    run(["npm", verb, "--ignore-scripts", "--no-audit", "--no-fund",
         "--include-workspace-root=false", *workspaces], root)


def bump(root: Path) -> list[str]:
    notes = []
    findings: dict[str, dict] = {}
    for ws, _ in FRONTENDS.values():
        for name, f in audit(root, ws).items():
            findings.setdefault(name, f)
    changed = False
    for name, f in sorted(findings.items()):
        # Several copies may be installed; the fix must clear the highest.
        installed = max(f["installed"], key=lambda v: vtuple(v) or (0,)) if f["installed"] else "0.0.0"
        fix, why = nearest_fix(name, installed, f["ranges"])
        if fix:
            how = pin(root, name, fix)
            notes.append(f"- {name} {installed} → {fix} ({how}): {'; '.join(f['advisories'])}")
            changed = True
        else:
            notes.append(f"- {name} {installed}: not raised — {why}")
    if changed:
        install(root, locked=False)  # re-resolves package-lock.json with the new pins
    return notes


def build(root: Path, name: str) -> Path:
    pkg = root / "hermes_cli"
    if name == "dashboard":
        out = pkg / "web_dist"
        shutil.rmtree(out, ignore_errors=True)
        # vite writes to hermes_cli/web_dist (web/vite.config.ts outDir).
        run(["node", "../node_modules/typescript/bin/tsc", "-b"], root / "web")
        run(["node", "../node_modules/vite/bin/vite.js", "build"], root / "web")
        if not (out / "index.html").is_file():
            sys.exit(f"[frontends] dashboard build produced no {out}/index.html")
        return out
    # TUI: esbuild writes one self-contained ui-tui/dist/entry.js.
    run(["node", "ui-tui/scripts/build.mjs"], root)
    entry = root / "ui-tui" / "dist" / "entry.js"
    if not entry.is_file():
        sys.exit(f"[frontends] TUI build produced no {entry}")
    out = pkg / "tui_dist"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir()
    shutil.copy2(entry, out / "entry.js")
    # The bundle is an ES module; node decides that from the nearest
    # package.json. Upstream's Nix build ships ui-tui/package.json beside it
    # for the same reason. Only the field node reads is kept.
    (out / "package.json").write_text('{"type": "module"}\n', encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("checkout", type=Path)
    ap.add_argument("--notes", type=Path)
    args = ap.parse_args()
    root = args.checkout.resolve()

    if not shutil.which("npm") or not shutil.which("node"):
        sys.exit("[frontends] node and npm are required")

    install(root, locked=True)
    notes = ["", "## Front ends", "",
             "The dashboard and TUI are prebuilt into the wheel; the target machine "
             "does not run npm for them. A front end whose dependencies still carry "
             "an advisory after raising them is left out.", ""]
    bumped = bump(root)
    if bumped:
        notes += ["Raised npm packages:", *bumped, ""]

    bundled = []
    for name, (ws, dirname) in FRONTENDS.items():
        shutil.rmtree(root / "hermes_cli" / dirname, ignore_errors=True)
        remaining = audit(root, ws)
        if remaining:
            print(f"[frontends] SKIP {name}: advisories remain in {ws}")
            notes.append(f"- **{name}: not included.** Advisories remain in its dependencies:")
            notes += [f"  - {p} {', '.join(f['installed'])}: {'; '.join(f['advisories'])}"
                      for p, f in sorted(remaining.items())]
            continue
        out = build(root, name)
        size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file()) / 1e6
        print(f"[frontends] ok   {name} → hermes_cli/{dirname} ({size:.1f} MB)")
        notes.append(f"- {name}: included (npm audit of its runtime dependencies: no advisories)")
        bundled.append(name)

    meta_path = root / "horo-build.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    meta["frontends"] = bundled
    meta_path.write_text(json.dumps(meta) + "\n", encoding="utf-8")

    print("\n".join(notes))
    if args.notes:
        with args.notes.open("a", encoding="utf-8") as f:
            f.write("\n".join(notes) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
