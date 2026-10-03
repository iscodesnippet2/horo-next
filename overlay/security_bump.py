"""Raise direct dependencies that have a published vulnerability fix.

    python overlay/security_bump.py <upstream-checkout> [--notes FILE]

Upstream pins dependencies exactly (==X.Y.Z, a supply-chain policy adopted
after the Mini Shai-Hulud worm) and bumps them by hand. Between bumps a pinned
version can collect advisories — v0.21.5 shipped PyJWT==2.13.0 with a CRITICAL
one. On a normal machine that is a security gap; behind an enterprise mirror
that filters by CVE it is an install failure, because pip cannot override an
exact pin written into the package's own metadata.

Scope is DIRECT dependencies only, and that is deliberate:

* `==X` with an advisory → `==fix`. These are the hard blockers.
* `>=X` with an advisory at X → `>=fix`. pip would usually pick a newer
  version anyway; raising the floor makes the guarantee explicit.
* Transitive dependencies are left alone. A wheel does not pin them, so pip
  already resolves to whatever newest version is available — on a normal
  machine that is the patched one, and behind a mirror it is whatever the
  mirror allows. Adding floors for them would create install failures on
  mirrors that have not synced the fix yet, which is the opposite of the goal.

Pins stay exact. Only the version moves, and only to the lowest version that
fixes every advisory, so the change is as small as the fix allows.

Exits non-zero, holding the release, when an advisory has no fix or the
raised version conflicts with another requirement (detected by re-locking).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ROOT = Path(sys.argv[1]).resolve()
NOTES = Path(sys.argv[sys.argv.index("--notes") + 1]) if "--notes" in sys.argv else None
PP = ROOT / "pyproject.toml"


def osv(name: str, version: str) -> list[dict]:
    body = json.dumps({"package": {"name": name, "ecosystem": "PyPI"}, "version": version}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r).get("vulns", [])


_RELEASES: dict[str, list[Version]] = {}


def pypi_releases(name: str) -> list[Version]:
    """Final, non-yanked releases on PyPI, ascending."""
    if name not in _RELEASES:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=60) as r:
            data = json.load(r)
        out = []
        for ver, files in data.get("releases", {}).items():
            try:
                v = Version(ver)
            except InvalidVersion:
                continue
            if v.is_prerelease or v.is_devrelease or not files or all(f.get("yanked") for f in files):
                continue
            out.append(v)
        _RELEASES[name] = sorted(out)
    return _RELEASES[name]


def nearest_fix(vuln: dict, name: str, current: Version) -> Version | None:
    """Smallest version above `current` that this advisory does not affect.

    Advisories record the boundary two ways. `fixed: X` names the fix directly.
    `last_affected: X` only says X is the last bad version — PyJWT's
    CVE-2026-103001 is recorded that way — so the fix is the first real
    release after X, which only PyPI can tell us.
    """
    fixes = []
    for affected in vuln.get("affected", []):
        if canonicalize_name(affected.get("package", {}).get("name", "")) != name:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    try:
                        v = Version(event["fixed"])
                    except InvalidVersion:
                        continue
                    if v > current:
                        fixes.append(v)
                elif "last_affected" in event:
                    try:
                        last = Version(event["last_affected"])
                    except InvalidVersion:
                        continue
                    if last >= current:
                        after = [v for v in pypi_releases(name) if v > last]
                        if after:
                            fixes.append(after[0])
    return min(fixes) if fixes else None


meta = tomllib.loads(PP.read_text(encoding="utf-8"))["project"]
specs = list(meta.get("dependencies", []))
for group in meta.get("optional-dependencies", {}).values():
    specs.extend(group)

changes, held = [], []
seen = set()
for raw in specs:
    req = Requirement(raw)
    name = canonicalize_name(req.name)
    for spec in req.specifier:
        if spec.operator not in ("==", ">=") or (raw, str(spec)) in seen:
            continue
        seen.add((raw, str(spec)))
        try:
            current = Version(spec.version)
        except InvalidVersion:
            continue
        vulns = [v for v in osv(name, str(current)) if not v.get("withdrawn")]
        if not vulns:
            continue
        fixes = [(v["id"], nearest_fix(v, name, current)) for v in vulns]
        unfixed = [vid for vid, fx in fixes if fx is None]
        if unfixed:
            held.append(f"{req.name}{spec}: no fixed version for {', '.join(unfixed)}")
            continue
        target = max(fx for _, fx in fixes)
        if not req.specifier.contains(str(target)) and spec.operator == ">=":
            # e.g. >=2.7,<3 but the fix is 3.0 — crossing the cap is a real
            # upgrade decision, not a security bump.
            held.append(f"{req.name}{req.specifier}: fix {target} is outside the allowed range")
            continue
        new_spec = f"{spec.operator}{target}"
        changes.append((raw, raw.replace(str(spec), new_spec, 1),
                        req.name, str(spec), new_spec, [vid for vid, _ in fixes]))

text = PP.read_text(encoding="utf-8")
applied = []
for change in changes:
    old, new = change[0], change[1]
    # The same requirement string often appears in several extras; every copy
    # must move together or the extras would disagree about the version.
    n = text.count(f'"{old}"')
    if n == 0:
        held.append(f"{old}: requirement not found verbatim in pyproject.toml")
        continue
    text = text.replace(f'"{old}"', f'"{new}"')
    applied.append(change)
changes = applied
PP.write_text(text, encoding="utf-8")

for _, _, name, before, after, ids in changes:
    print(f"[security] {name}: {before} -> {after}  ({len(ids)} advisories: {', '.join(ids[:4])}{' …' if len(ids) > 4 else ''})")
for h in held:
    print(f"[security] HOLD {h}")

# Re-lock: the raised versions must still resolve against everything else.
if changes and not held:
    # The uv on PATH (setup-uv in CI). Override with HORO_UV, e.g.
    # HORO_UV="uvx --from uv@0.12.22 uv", where the local uv predates
    # upstream's lockfile format.
    import os
    import shlex
    uv = shlex.split(os.environ.get("HORO_UV", "uv"))
    r = subprocess.run([*uv, "lock"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        held.append("uv lock failed after raising versions:\n" + r.stderr[-1500:])
        print(f"[security] HOLD {held[-1]}")
    else:
        print("[security] uv.lock re-resolved")

# ── Transitive dependencies: the lock only ────────────────────────────────
# The wheel leaves transitives unpinned, so `pip install horo-next` already
# resolves them to the newest available — patched, online. But the offline
# dependency list each release publishes is exported from uv.lock, and the lock
# still holds upstream's versions: v0.21.5's lock carries anyio 4.12.1 with a
# CRITICAL advisory. An air-gapped site building its wheelhouse from that list
# would fetch the vulnerable version, which a CVE-filtering mirror blocks.
#
# So vulnerable transitives are upgraded IN THE LOCK, never as floors in the
# wheel. Online installs are unchanged; the offline list becomes patched.
# What cannot move (another requirement caps it) is reported, not held: the
# wheel itself is fine, and the cause is a constraint we do not own.
import os
import shlex

uv = shlex.split(os.environ.get("HORO_UV", "uv"))
lingering: list[str] = []
transitive_upgraded: list[str] = []


def locked_set() -> dict[str, str]:
    r = subprocess.run([*uv, "export", "--frozen", "--no-dev", "--all-extras", "--no-emit-project",
                        "--no-hashes", "--format", "requirements-txt"],
                       cwd=ROOT, capture_output=True, text=True)
    out = {}
    for line in r.stdout.splitlines():
        if "==" in line and not line.startswith((" ", "#")):
            n, v = line.split(";")[0].strip().split("==", 1)
            out[canonicalize_name(n.split("[")[0])] = v.strip()
    return out


def vulnerable(pkgs: dict[str, str]) -> dict[str, list[str]]:
    found = {}
    items = list(pkgs.items())
    for i in range(0, len(items), 500):
        chunk = items[i:i + 500]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
                                       for n, v in chunk]}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            for (n, _), res in zip(chunk, json.load(r)["results"]):
                ids = [x["id"] for x in res.get("vulns", [])]
                if ids:
                    found[n] = ids
    return found


def why_not_upgraded(name: str, version: str) -> str:
    """Say why a fixed version exists but the lock did not take it.

    Upstream's [tool.uv] exclude-newer is a cooldown — uv ignores releases
    younger than the window, so a freshly published (possibly compromised)
    version is not adopted until it has aged. A security fix inside that
    window is held back by design, not by a conflict. Upstream grants such
    fixes temporary per-package exceptions by hand; this does not do so
    automatically, because bypassing the cooldown on every advisory would
    remove half of the defence the exact pins are part of.
    """
    import datetime as dt
    fix = None
    for v in osv(name, version):
        if not v.get("withdrawn"):
            f = nearest_fix(v, name, Version(version))
            if f and (fix is None or f > fix):
                fix = f
    if fix is None:
        return "no fixed version published"
    major = "a major-version change, " if fix.major != Version(version).major else ""
    window = re.search(r'^exclude-newer\s*=\s*"(\d+)\s*days?"',
                       PP.read_text(encoding="utf-8"), re.M)
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{fix}/json", timeout=60) as r:
            uploaded = min(dt.datetime.fromisoformat(u["upload_time_iso_8601"].replace("Z", "+00:00"))
                           for u in json.load(r)["urls"])
    except Exception:
        uploaded = None
    if window and uploaded:
        clears = uploaded + dt.timedelta(days=int(window.group(1)))
        if clears > dt.datetime.now(dt.timezone.utc):
            return (f"fix {fix} ({major}published {uploaded:%Y-%m-%d}) is inside upstream's "
                    f"{window.group(1)}-day exclude-newer cooldown; it clears {clears:%Y-%m-%d} "
                    f"and the next build after that picks it up")
    return f"fix {fix} ({major}released) is excluded by another requirement's version cap"


import re  # noqa: E402

if not held:
    direct = {canonicalize_name(Requirement(s).name) for s in specs}
    before = locked_set()
    targets = sorted(n for n in vulnerable(before) if n not in direct)
    if targets:
        args = [a for n in targets for a in ("--upgrade-package", n)]
        r = subprocess.run([*uv, "lock", *args], cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            held.append("uv lock failed upgrading vulnerable transitives:\n" + r.stderr[-1500:])
        else:
            after = locked_set()
            still = vulnerable({n: after[n] for n in targets if n in after})
            for n in targets:
                if n not in after:
                    continue
                if n in still:
                    reason = why_not_upgraded(n, after[n])
                    lingering.append(f"`{n}` {after[n]} — {reason}")
                    print(f"[security] WARN transitive {n}=={after[n]} still has advisories: {reason}")
                else:
                    transitive_upgraded.append(f"`{n}` {before[n]} → {after[n]}")
                    print(f"[security] transitive {n}: {before[n]} -> {after[n]} (lock only)")

if NOTES:
    lines = ["## Security updates over upstream", ""]
    if changes:
        lines += [f"- `{n}` {b} → {a} ({', '.join(ids)})" for _, _, n, b, a, ids in changes]
    else:
        lines.append("No direct dependency needed raising.")
    if transitive_upgraded:
        lines += ["", "Transitive dependencies upgraded in the offline dependency list "
                      "(the wheel does not pin these):", ""]
        lines += [f"- {t}" for t in transitive_upgraded]
    if lingering:
        lines += ["", "Still carrying advisories (reason given for each):", ""]
        lines += [f"- {t}" for t in lingering]
    NOTES.write_text("\n".join(lines) + "\n", encoding="utf-8")

if held:
    sys.exit(f"[security] {len(held)} item(s) need a human — release held")
print(f"[security] {len(changes)} direct dependencies raised")
