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
import os
import re
import shlex
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
# npm 11: npm 10's resolver crashes ("reading 'edgesOut'") re-locking this
# monorepo after a pin moves (vitest 4.1.10 → 4.1.11). Upstream's engines allow
# npm <11.10 || >=11.17. Override like HORO_UV, e.g. HORO_NPM="npx -y npm@11.21.0".
NPM = shlex.split(os.environ.get("HORO_NPM", "npm"))


def manifests(root: Path) -> list[str]:
    """The root and every workspace package.json. A pin has to move in all of
    them together: one lock serves the whole monorepo, and two workspaces
    pinning different versions of a package with exact-version peers (vitest)
    cannot be resolved."""
    globs = json.loads((root / "package.json").read_text(encoding="utf-8")).get("workspaces", [])
    out = ["package.json"]
    for g in globs:
        for d in sorted(root.glob(g)):
            if (d / "package.json").is_file():
                out.append(str((d / "package.json").relative_to(root)))
    return out


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
def locked_versions(root: Path, name: str) -> set[str]:
    pkgs = json.loads((root / "package-lock.json").read_text(encoding="utf-8")).get("packages", {})
    return {v["version"] for k, v in pkgs.items()
            if k.endswith("node_modules/" + name) and isinstance(v, dict) and "version" in v}


def forget(root: Path, names: set[str]) -> None:
    """Drop these packages from the lock so the next resolve picks them afresh.
    npm keeps a locked version that an edited override no longer allows and
    reports the tree "up to date"."""
    lock = root / "package-lock.json"
    data = json.loads(lock.read_text(encoding="utf-8"))
    pkgs = data.get("packages", {})
    for k in [k for k in pkgs if any(k.endswith("node_modules/" + n) for n in names)]:
        del pkgs[k]
    lock.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def audit(root: Path, workspace: str, dev: bool = False) -> dict:
    """{package: {"installed": [...], "ranges": [...], "advisories": [...]}} for
    one workspace: runtime dependencies, or with `dev` the build and test
    tools too."""
    cmd = [*NPM, "audit", "--json", f"--workspace={workspace}"] + ([] if dev else ["--omit=dev"])
    r = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
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
        # From the lock, not audit's "nodes": those list one copy, and a
        # package installed in two majors (undici 6 for the TUI, 7 for jsdom)
        # would have the other one missed.
        installed = locked_versions(root, name)
        out[name] = {"installed": sorted(installed), "ranges": [a["range"] for a in advisories],
                     "advisories": [f"{a.get('severity')} {a.get('url', '').rsplit('/', 1)[-1]} "
                                    f"{a.get('title', '')}" for a in advisories]}
    return out


def nearest_fix(name: str, installed: str, ranges: list[str]) -> tuple[str | None, str]:
    """Smallest release above `installed`, same major, outside every advisory
    range, older than the cooldown. Returns (version, reason-if-none)."""
    r = subprocess.run([*NPM, "view", name, "time", "--json"], capture_output=True, text=True)
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


def major_of(spec: str) -> int | None:
    m = re.search(r"(\d+)", spec)
    return int(m.group(1)) if m else None


def pin(root: Path, name: str, major: int, version: str, allow_new: bool) -> str | None:
    """Raise the `major` line of `name` to `version`, where upstream already
    controls it: root overrides (`name` or `name@^major`, as upstream writes
    them for packages installed in two majors) and exact pins in the front
    ends' manifests. Other majors of the same package are left alone — the
    TUI uses undici 6 while jsdom pulls undici 7.

    Only when upstream controls nothing for it, and `allow_new`, is a root
    override `name@^major` added. Returns how it was raised, or None."""
    edited = []
    rootpj = root / "package.json"
    data = json.loads(rootpj.read_text(encoding="utf-8"))
    ov = data.get("overrides", {})
    for key, val in list(ov.items()):
        if not isinstance(val, str):
            continue
        if key == name and major_of(val) == major:
            ov[key] = version
            edited.append(f"override {key}")
        elif key.startswith(name + "@") and major_of(key[len(name) + 1:]) == major:
            ov[key] = version
            edited.append(f"override {key}")
    if edited:
        rootpj.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    for rel in manifests(root):
        pj = root / rel
        if not pj.is_file():
            continue
        d = json.loads(pj.read_text(encoding="utf-8"))
        hit = [s for s in ("dependencies", "devDependencies", "optionalDependencies")
               if isinstance(d.get(s, {}).get(name), str) and major_of(d[s][name]) == major]
        for section in hit:
            d[section][name] = version
        if hit:
            pj.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
            edited.append(f"pin in {rel}")
    if edited:
        return ", ".join(edited)
    if not allow_new:
        return None
    data = json.loads(rootpj.read_text(encoding="utf-8"))
    data.setdefault("overrides", {})[f"{name}@^{major}"] = version
    rootpj.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return f"new override {name}@^{major}"


def install(root: Path, locked: bool) -> None:
    workspaces = [f"--workspace={w}" for w, _ in FRONTENDS.values()]
    if not locked:
        # Re-resolve the lock for the whole monorepo first, then install from
        # it: a workspace-filtered `npm install` resolves only part of the tree.
        run([*NPM, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], root)
    run([*NPM, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
         "--include-workspace-root=false", *workspaces], root)


def bump(root: Path) -> list[str]:
    """Raise everything installed, build and test tools included. Those never
    reach the wheel, but they run in the build — and the goal is no known
    advisory anywhere in the pipeline. Whether a front end is bundled is still
    decided by its runtime dependencies alone (see main).

    Two rounds. The first only moves pins and overrides upstream already has;
    raising a parent often fixes its children (vitest brings @vitest/mocker),
    and an override that fights a parent's exact pin breaks npm's resolver.
    The second adds overrides for whatever is still flagged."""
    notes, unfixed = [], {}
    for allow_new in (False, True):
        findings: dict[str, dict] = {}
        for ws, _ in FRONTENDS.values():
            for name, f in audit(root, ws, dev=True).items():
                findings.setdefault(name, f)
        changed = set()
        unfixed = {}
        for name, f in sorted(findings.items()):
            # One package may be installed in several majors; each is its own line.
            by_major: dict[int, str] = {}
            for v in f["installed"]:
                vt = vtuple(v)
                if vt and any(satisfies(v, rg) for rg in f["ranges"]):
                    if vt[0] not in by_major or vt > vtuple(by_major[vt[0]]):
                        by_major[vt[0]] = v
            for major, installed in sorted(by_major.items()):
                fix, why = nearest_fix(name, installed, f["ranges"])
                how = pin(root, name, major, fix, allow_new) if fix else None
                if how:
                    notes.append(f"- {name} {installed} → {fix} ({how}): {'; '.join(f['advisories'])}")
                    changed.add(name)
                elif not fix:
                    unfixed[f"{name} {installed}"] = why
        if changed:
            forget(root, changed)
            install(root, locked=False)  # re-resolves package-lock.json with the new pins
    notes += [f"- {k}: not raised — {why}" for k, why in sorted(unfixed.items())]
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

    if not shutil.which(NPM[0]) or not shutil.which("node"):
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

    # Build and test tools left unfixed: reported — they are not in the wheel.
    tools = {}
    for ws, _ in FRONTENDS.values():
        runtime = audit(root, ws)
        tools.update({p: f for p, f in audit(root, ws, dev=True).items() if p not in runtime})
    notes.append("- build and test tools (not in the wheel): " + (
        "no advisories" if not tools else "advisories remain in " + ", ".join(
            f"{p} {', '.join(f['installed'])}" for p, f in sorted(tools.items()))))

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
