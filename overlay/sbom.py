"""Software bill of materials and third-party notices for a horo-next release.

    python overlay/sbom.py generate <checkout> <version> <upstream-tag> \\
        --core requirements-X.txt --all requirements-X-all-extras.txt \\
        --extras-map extras-map-X.json --out horo-next.cdx.json
    python overlay/sbom.py embed <wheel> <sbom> --release-copy <out.json>

Security review systems (Sonatype, Dependency-Track, Black Duck) identify a
package's contents by component coordinates. For the Python dependencies that
works from the wheel metadata alone. It does not for the dashboard and TUI:
they are minified JavaScript with no package.json, so a scanner either sees
nothing or reports unidentified code. This SBOM names every npm package that
is actually inside each bundle, with version, license and the integrity hash
npm verified — read from the bundles' own sourcemaps (dashboard) and module
markers (TUI), not from the dependency tree, which lists far more than ships.

`generate` (before the wheel is built) writes the CycloneDX 1.5 SBOM and
THIRD_PARTY_LICENSES — the license texts of those bundled npm packages, which
minification strips from the code — and adds the latter to the wheel's
license files. `embed` (after) puts the SBOM in the wheel at
.dist-info/sboms/ (PEP 770) and writes a copy for the release page that also
carries the finished wheel's own hash.

Python dependencies are not bundled — pip installs each as its own package,
with its own license files — so they are listed with their license but no
notice text.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import sys
import urllib.request
import uuid
import zipfile
from pathlib import Path

REPO = "https://github.com/iscodesnippet2/horo-next"
UPSTREAM = "https://github.com/NousResearch/hermes-agent"
LICENSE_FILES = re.compile(r"^(licen[cs]e|copying|notice)(\.|-|$)", re.I)
NOTICES = "THIRD_PARTY_LICENSES"


def die(msg: str) -> None:
    sys.exit(f"[sbom] {msg}")


# ── what is inside the bundles ──────────────────────────────────────────────
def package_dir(path: str) -> str | None:
    """'…/node_modules/@scope/pkg/lib/x.js' → '…/node_modules/@scope/pkg'
    (the innermost node_modules — nested copies are separate packages)."""
    i = path.rfind("node_modules/")
    if i < 0:
        return None
    rest = path[i + len("node_modules/"):].split("/")
    n = 2 if rest[0].startswith("@") else 1
    if len(rest) <= n:
        return None
    return path[:i] + "node_modules/" + "/".join(rest[:n])


def dashboard_modules(root: Path) -> set[str]:
    maps = root / ".horo-sourcemaps" / "web"
    files = list(maps.rglob("*.map"))
    if not files:
        die(f"no dashboard sourcemaps under {maps} — run build_frontends.py first")
    out = set()
    dist = root / "hermes_cli" / "web_dist"
    for m in files:
        # Sources are relative to where the map sat beside its chunk.
        here = dist / m.parent.relative_to(maps)
        for src in json.loads(m.read_text(encoding="utf-8")).get("sources", []):
            p = os.path.relpath(os.path.normpath(here / src.split("?")[0]), root)
            d = package_dir(p.replace(os.sep, "/"))
            if d:
                out.add(d)
    return out


def tui_modules(root: Path) -> set[str]:
    # esbuild (unminified) heads each inlined module with "// <path>".
    entry = root / "ui-tui" / "dist" / "entry.js"
    if not entry.is_file():
        die(f"{entry} missing — run build_frontends.py first")
    out = set()
    for line in entry.read_text(encoding="utf-8").splitlines():
        if line.startswith("// ") and "node_modules/" in line:
            # Paths are relative to the repo root, where build.mjs runs esbuild.
            d = package_dir(line[3:].strip())
            if d:
                out.add(d)
    return out


def npm_purl(name: str, version: str) -> str:
    # purl spec: the scope's "@" is percent-encoded, its "/" is a separator.
    return f"pkg:npm/%40{name[1:]}@{version}" if name.startswith("@") else f"pkg:npm/{name}@{version}"


def npm_components(root: Path, bundled: dict[str, set[str]]) -> tuple[list[dict], list[tuple[str, str, Path | None, str]]]:
    lock = json.loads((root / "package-lock.json").read_text(encoding="utf-8"))["packages"]
    where: dict[str, set[str]] = {}
    for frontend, dirs in bundled.items():
        for d in dirs:
            where.setdefault(d, set()).add(frontend)
    comps, notices, missing = {}, [], []
    for d, fronts in sorted(where.items()):
        entry = lock.get(d)
        if entry is None:
            missing.append(d)
            continue
        if entry.get("link"):
            continue  # a workspace of this monorepo (@hermes/shared): upstream's own code
        name = entry.get("name") or d.rsplit("node_modules/", 1)[1]
        version = entry["version"]
        purl = npm_purl(name, version)
        lic = entry.get("license")
        c = comps.setdefault(purl, {
            "type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl,
            "scope": "required",
            "licenses": [{"expression": lic}] if lic else [],
            "properties": [],
        })
        integ = entry.get("integrity", "")
        if integ.startswith("sha512-") and "hashes" not in c:
            c["hashes"] = [{"alg": "SHA-512", "content": base64.b64decode(integ[7:]).hex()}]
        if entry.get("resolved"):
            c["externalReferences"] = [{"type": "distribution", "url": entry["resolved"]}]
        for f in sorted(fronts):
            prop = {"name": "horo:bundled-in", "value": f}
            if prop not in c["properties"]:
                c["properties"].append(prop)
        pkgdir = root / d
        lic_files = sorted(p for p in pkgdir.iterdir() if p.is_file() and LICENSE_FILES.match(p.name)) \
            if pkgdir.is_dir() else []
        notices.append((f"{name}@{version}", lic or "UNKNOWN", lic_files[0] if lic_files else None,
                        ", ".join(sorted(fronts))))
    if missing:
        die(f"bundled modules with no package-lock entry: {missing[:5]}")
    return list(comps.values()), notices


# ── Python dependencies ─────────────────────────────────────────────────────
REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;]+)\s*(?:;\s*(.+))?$")


def read_reqs(path: Path) -> dict[str, tuple[str, str | None]]:
    out = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = REQ.match(raw.split(" #")[0])
        if m:
            out[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = (m.group(2), m.group(3))
    return out


def pypi_license(name: str, version: str) -> list[dict]:
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as r:
            info = json.load(r)["info"]
    except OSError:
        return []
    if info.get("license_expression"):
        return [{"expression": info["license_expression"]}]
    lic = (info.get("license") or "").strip()
    if lic and len(lic) <= 80 and "\n" not in lic:
        return [{"license": {"name": lic}}]
    names = [c.split(" :: ")[-1] for c in info.get("classifiers", []) if c.startswith("License :: ")]
    return [{"license": {"name": n}} for n in names]


def python_components(core: Path, everything: Path, extras_map: dict) -> list[dict]:
    core_set, all_reqs = read_reqs(core), read_reqs(everything)
    with cf.ThreadPoolExecutor(16) as pool:
        lic = dict(zip(all_reqs, pool.map(lambda kv: pypi_license(kv[0], kv[1][0]), all_reqs.items())))
    comps = []
    for name, (version, marker) in sorted(all_reqs.items()):
        purl = f"pkg:pypi/{name}@{version}"
        props = [{"name": "horo:installed-by", "value": "core" if name in core_set else "extras"}]
        feats = [f for f in extras_map.get(name, []) if f != "core"]
        if feats:
            props.append({"name": "horo:extras", "value": ",".join(feats)})
        if marker:
            props.append({"name": "horo:environment-marker", "value": marker})
        comps.append({"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl,
                      "scope": "required" if name in core_set else "optional",
                      "licenses": lic.get(name, []), "properties": props})
    return comps


# ── generate / embed ────────────────────────────────────────────────────────
def generate(a) -> int:
    root = a.checkout.resolve()
    meta = json.loads((root / "horo-build.json").read_text(encoding="utf-8"))
    frontends = meta.get("frontends", [])
    bundled = {}
    if "dashboard" in frontends:
        bundled["dashboard"] = dashboard_modules(root)
    if "tui" in frontends:
        bundled["tui"] = tui_modules(root)
    npm, notices = npm_components(root, bundled)
    py = python_components(a.core, a.all, json.loads(a.extras_map.read_text(encoding="utf-8")))

    unlicensed = [c["purl"] for c in npm if not c["licenses"]]
    if unlicensed:
        die(f"bundled npm packages without a declared license: {unlicensed}")

    this = f"pkg:pypi/horo-next@{a.version}"
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "horo-next overlay/sbom.py",
                                      "externalReferences": [{"type": "vcs", "url": REPO}]}]},
            "component": {
                "type": "application", "bom-ref": this, "name": "horo-next", "version": a.version,
                "purl": this,
                "description": "Unofficial PyPI distribution of Hermes Agent by Nous Research",
                "licenses": [{"expression": "MIT"}],
                "externalReferences": [{"type": "vcs", "url": REPO},
                                       {"type": "distribution", "url": f"https://pypi.org/project/horo-next/{a.version}/"},
                                       {"type": "website", "url": UPSTREAM}],
                # Repackaging, stated in the vocabulary scanners understand:
                # the ancestor is upstream's tagged release; the change is packaging.
                "pedigree": {
                    "ancestors": [{"type": "application", "bom-ref": f"upstream-{a.upstream_tag}",
                                   "name": "hermes-agent", "version": a.upstream_tag,
                                   "purl": f"pkg:github/nousresearch/hermes-agent@{a.upstream_tag}",
                                   "licenses": [{"expression": "MIT"}],
                                   "externalReferences": [{"type": "vcs",
                                                           "url": f"{UPSTREAM}/tree/{a.upstream_tag}"}]}],
                    "notes": "Built from the upstream tag with packaging-only changes (build guard, "
                             "distribution name, bundled assets, prebuilt dashboard and TUI, "
                             "dependency security raises). See " + REPO + "/tree/horo/overlay",
                },
                "properties": [{"name": "horo:upstream-tag", "value": a.upstream_tag},
                               {"name": "horo:bundled-frontends", "value": ",".join(frontends) or "none"}],
            },
        },
        "components": py + npm,
        "dependencies": [{"ref": this, "dependsOn": sorted(
            [c["bom-ref"] for c in py if c["scope"] == "required"] + [c["bom-ref"] for c in npm])}],
    }
    a.out.write_text(json.dumps(bom, indent=1) + "\n", encoding="utf-8")

    # Third-party notices for what is compiled into the bundles.
    buf = [f"Third-party software bundled in horo-next {a.version}",
           "", "The dashboard (hermes_cli/web_dist) and terminal UI (hermes_cli/tui_dist) are",
           "compiled JavaScript that contains the npm packages below. Their license texts",
           "follow, as each package ships them. Python dependencies are installed as",
           "separate packages and carry their own license files.", ""]
    for ident, lic, path, fronts in sorted(notices):
        buf += ["=" * 78, f"{ident}  —  {lic}  —  bundled in: {fronts}", "=" * 78]
        if path:
            buf.append(path.read_text(encoding="utf-8", errors="replace").strip())
        else:
            buf.append(f"(The package declares the license {lic} and ships no license file.)")
        buf.append("")
    (root / NOTICES).write_text("\n".join(buf) + "\n", encoding="utf-8")
    pp = root / "pyproject.toml"
    text = pp.read_text(encoding="utf-8")
    anchor = 'license-files = ["LICENSE"]'
    if text.count(anchor) != 1:
        die(f"pyproject.toml: anchor {anchor!r} not found — cannot ship the notices")
    pp.write_text(text.replace(anchor, f'license-files = ["LICENSE", "{NOTICES}"]'), encoding="utf-8")

    without_file = sum(1 for n in notices if n[2] is None)
    print(f"[sbom] {len(py)} Python components ({sum(c['scope'] == 'required' for c in py)} core), "
          f"{len(npm)} bundled npm components "
          + ", ".join(f"{f}: {len(d)}" for f, d in bundled.items()))
    print(f"[sbom] {NOTICES}: {len(notices)} entries, {without_file} without a license file in the package")
    print(f"[sbom] wrote {a.out}")
    return 0


def embed(a) -> int:
    wheel, sbom = a.wheel.resolve(), a.sbom.resolve()
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        distinfo = next(n.split("/")[0] for n in names if n.endswith(".dist-info/RECORD"))
        record_name = f"{distinfo}/RECORD"
        entries = {n: z.read(n) for n in names}
        infos = {n: z.getinfo(n) for n in names}
    target = f"{distinfo}/sboms/{sbom.name}"
    data = sbom.read_bytes()
    entries[target] = data
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    rows = [r for r in csv.reader(io.StringIO(entries[record_name].decode())) if r and r[0] != target]
    rows.insert(len(rows) - 1, [target, f"sha256={digest}", str(len(data))])  # RECORD stays last
    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows(rows)
    entries[record_name] = out.getvalue().encode()
    tmp = wheel.with_suffix(".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for n in [n for n in names if n != record_name] + [target, record_name]:
            if n == target or n == record_name:
                z.writestr(zipfile.ZipInfo(n, date_time=infos[record_name].date_time), entries[n],
                           compress_type=zipfile.ZIP_DEFLATED)
            else:
                z.writestr(infos[n], entries[n])
    shutil.move(tmp, wheel)

    # The release copy also records the finished wheel, which the embedded
    # copy cannot (it is inside it).
    bom = json.loads(data)
    bom["metadata"]["component"]["hashes"] = [
        {"alg": "SHA-256", "content": hashlib.sha256(wheel.read_bytes()).hexdigest()}]
    a.release_copy.write_text(json.dumps(bom, indent=1) + "\n", encoding="utf-8")
    print(f"[sbom] embedded {target}; release copy {a.release_copy}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("checkout", type=Path)
    g.add_argument("version")
    g.add_argument("upstream_tag")
    g.add_argument("--core", type=Path, required=True)
    g.add_argument("--all", type=Path, required=True)
    g.add_argument("--extras-map", type=Path, required=True)
    g.add_argument("--out", type=Path, required=True)
    e = sub.add_parser("embed")
    e.add_argument("wheel", type=Path)
    e.add_argument("sbom", type=Path)
    e.add_argument("--release-copy", type=Path, required=True)
    a = ap.parse_args()
    return generate(a) if a.cmd == "generate" else embed(a)


if __name__ == "__main__":
    sys.exit(main())
