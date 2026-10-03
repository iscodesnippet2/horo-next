#!/usr/bin/env python3
"""Check which horo-next dependencies the enterprise mirror will serve.

Run on the air-gapped machine. Needs only Python and pip — no internet, no uv,
nothing installed. It asks pip to download each package on its own and records
which ones the mirror refuses, so one run produces the complete list instead of
pip stopping at the first failure.

    python3 probe.py requirements-0.21.5.txt
    python3 probe.py requirements-0.21.5-all-extras.txt --map extras-map-0.21.5.json
    python3 probe.py requirements-0.21.5.txt --index-url https://mirror.example/simple

pip is called exactly as it would be for a real install, so it uses this
machine's pip configuration (pip.conf, PIP_INDEX_URL, certificates, proxy,
netrc). Environment markers are evaluated by pip on this machine — packages
that do not apply to this OS or Python are reported as skipped, not missing.

Each package is tried as a wheel first. If no wheel is available it is tried
again as a source distribution, which would need a compiler to install.

Writes airgap-probe-report.json next to the requirements file. Bring that file
back to analyse the results. Credentials in index URLs are removed from it.

Exit status: 0 when every applicable package is available as a wheel,
1 otherwise, 2 when the mirror cannot be reached at all.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

UNREACHABLE = re.compile(
    r"Failed to establish a new connection|Max retries exceeded|Name or service not known|"
    r"nodename nor servname|Connection refused|Network is unreachable|timed out|"
    r"Temporary failure in name resolution", re.I)
TLS = re.compile(r"SSLError|CERTIFICATE_VERIFY_FAILED|certificate verify failed", re.I)
BLOCKED = re.compile(r"\b403\b|Forbidden", re.I)
NOT_FOUND = re.compile(r"\b404\b|Not Found", re.I)
NO_MATCH = re.compile(r"No matching distribution found|Could not find a version that satisfies", re.I)
FROM_VERSIONS = re.compile(r"from versions: ([^)]*)\)")
SKIPPED = re.compile(r"Ignoring [^:]+: markers .* don't match", re.I)


def redact(url: str) -> str:
    """Drop user:password from a URL — the report leaves this machine."""
    try:
        p = urlsplit(url)
    except ValueError:
        return "<unparseable>"
    if p.username or p.password:
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
        return urlunsplit((p.scheme, "***@" + host, p.path, p.query, p.fragment))
    return url


def pip_config() -> list[str]:
    r = subprocess.run([sys.executable, "-m", "pip", "config", "list"],
                       capture_output=True, text=True)
    out = []
    for line in r.stdout.splitlines():
        key, _, value = line.partition("=")
        value = value.strip().strip("'\"")
        if "url" in key.lower():
            value = " ".join(redact(v) for v in value.split())
        out.append(f"{key}={value}")
    for var in ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST", "PIP_CERT"):
        if os.environ.get(var):
            v = os.environ[var]
            out.append(f"env {var}={redact(v) if 'URL' in var else v}")
    return out


def read_requirements(path: Path) -> list[str]:
    reqs = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        reqs.append(line)
    return reqs


def name_of(req: str) -> str:
    m = re.match(r"\s*([A-Za-z0-9_.\-]+)", req)
    return re.sub(r"[-_.]+", "-", m.group(1)).lower() if m else req


def download(req: str, dest: str, extra: list[str], binary_only: bool, timeout: int):
    cmd = [sys.executable, "-m", "pip", "download", "--no-deps", "--disable-pip-version-check",
           "--no-input", "--progress-bar", "off", "-d", dest]
    if binary_only:
        cmd += ["--only-binary", ":all:"]
    cmd += [*extra, req]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return 124, "timed out"


def classify(req: str, dest: str, extra: list[str], timeout: int) -> dict:
    result = {"requirement": req, "package": name_of(req)}
    code, out = download(req, dest, extra, binary_only=True, timeout=timeout)
    if code == 0:
        result["status"] = "skipped" if SKIPPED.search(out) else "ok"
        return result

    def reason(text: str) -> tuple[str, str]:
        if UNREACHABLE.search(text):
            return "unreachable", "mirror could not be reached"
        if TLS.search(text):
            return "tls", "TLS error — check pip's cert / trusted-host settings"
        if BLOCKED.search(text):
            return "blocked", "refused by the mirror (HTTP 403, usually a security policy)"
        if NOT_FOUND.search(text):
            return "missing", "not on the mirror (HTTP 404)"
        if NO_MATCH.search(text):
            return "missing", "no matching file on the mirror"
        return "error", text.strip().splitlines()[-1][:300] if text.strip() else "unknown error"

    status, detail = reason(out)
    versions = FROM_VERSIONS.search(out)
    if versions:
        listed = [v.strip() for v in versions.group(1).split(",") if v.strip() and v.strip() != "none"]
        result["mirror_versions"] = listed[-8:]

    if status == "missing":
        code2, out2 = download(req, dest, extra, binary_only=False, timeout=timeout)
        if code2 == 0:
            result.update(status="sdist-only",
                          detail="only a source distribution — installing needs a compiler")
            return result
        if not (NO_MATCH.search(out2) or NOT_FOUND.search(out2) or BLOCKED.search(out2)):
            # The mirror HAS the file; it just cannot be prepared on this
            # Python. Reporting it as missing would send someone to ask the
            # mirror team for a package that is already there.
            lines = out2.splitlines()
            # Prefer the actual exception (e.g. "ModuleNotFoundError: No module
            # named 'imp'") over pip's generic "subprocess-exited-with-error".
            exc = [ln.strip() for ln in lines if re.match(r"\s*\w+(Error|Exception): ", ln)]
            cause = exc[-1] if exc else next(
                (ln.strip() for ln in lines if "error:" in ln.lower()),
                lines[-1].strip() if lines else "unknown")
            result.update(status="sdist-unbuildable",
                          detail=f"only a source distribution, and it fails to build here: {cause[:200]}")
            return result
    result.update(status=status, detail=detail)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("requirements", type=Path, help="requirements-<version>.txt from a horo-next release")
    ap.add_argument("--map", type=Path, help="extras-map-<version>.json: which features need each package")
    ap.add_argument("--index-url", help="mirror URL (default: this machine's pip configuration)")
    ap.add_argument("--dest", type=Path, help="keep downloaded files here (a ready-made wheelhouse)")
    ap.add_argument("--workers", type=int, default=4, help="parallel downloads (default 4)")
    ap.add_argument("--timeout", type=int, default=300, help="seconds per package (default 300)")
    ap.add_argument("--report", type=Path, help="report path (default: next to the requirements file)")
    ap.add_argument("--no-self", action="store_true",
                    help="do not probe horo-next itself — for checking the dependencies "
                         "before a version has been published")
    args = ap.parse_args()

    reqs = read_requirements(args.requirements)
    if not reqs:
        print(f"No requirements found in {args.requirements}")
        return 1

    # horo-next itself must come from the mirror too.
    version = re.search(r"requirements-(\d+\.\d+\.\d+(?:\.post\d+)?)", args.requirements.name)
    if version and not args.no_self:
        reqs.insert(0, f"horo-next=={version.group(1)}")

    feature = {}
    if args.map:
        feature = json.loads(args.map.read_text(encoding="utf-8"))
        feature["horo-next"] = ["core"]

    extra = ["--index-url", args.index_url] if args.index_url else []
    dest = str(args.dest) if args.dest else tempfile.mkdtemp(prefix="horo-probe-")
    Path(dest).mkdir(parents=True, exist_ok=True)

    print(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}")
    print(f"Probing {len(reqs)} packages with {args.workers} workers...")

    # Fail fast if the mirror is unreachable: a few hundred identical timeouts
    # say nothing the first one did not.
    report = args.report or args.requirements.with_name("airgap-probe-report.json")

    def write_report(results: list[dict], summary: dict) -> None:
        report.write_text(json.dumps({
            "generated": dt.datetime.now().isoformat(timespec="seconds"),
            "host": socket.gethostname(),
            "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
            "pip": subprocess.run([sys.executable, "-m", "pip", "--version"],
                                  capture_output=True, text=True).stdout.split(" from ")[0],
            "pip_config": pip_config() + ([f"cli --index-url={redact(args.index_url)}"]
                                          if args.index_url else []),
            "requirements_file": args.requirements.name,
            "summary": summary,
            "results": sorted(results, key=lambda x: x["package"]),
        }, indent=1) + "\n", encoding="utf-8")

    first = classify(reqs[0], dest, extra, args.timeout)
    if first["status"] in ("unreachable", "tls"):
        print(f"\nCannot reach the package index: {first['detail']}")
        print("Check pip's index-url / cert / trusted-host settings, or pass --index-url.")
        # Still written: the pip configuration it records is what diagnoses this.
        write_report([first], {first["status"]: 1})
        print(f"Report written to {report}")
        return 2

    results = [first]
    done = 1
    with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(classify, r, dest, extra, args.timeout) for r in reqs[1:]]
        for fut in cf.as_completed(futures):
            results.append(fut.result())
            done += 1
            if done % 20 == 0 or done == len(reqs):
                print(f"  {done}/{len(reqs)}")

    if not args.dest:
        shutil.rmtree(dest, ignore_errors=True)

    for r in results:
        r["needed_by"] = feature.get(r["package"], [])

    problems = [r for r in results if r["status"] not in ("ok", "skipped")]
    by_status: dict[str, int] = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1

    print("\n=== Result ===")
    for status in ("ok", "skipped", "sdist-only", "sdist-unbuildable", "blocked", "missing", "error"):
        if by_status.get(status):
            print(f"  {status:10} {by_status[status]}")

    if problems:
        print("\n=== Not available as a wheel ===")
        for r in sorted(problems, key=lambda x: ("core" not in x["needed_by"], x["package"])):
            need = ", ".join(r["needed_by"]) if r["needed_by"] else "?"
            line = f"  {r['requirement']:40} {r['status']:10} needed by: {need}"
            print(line)
            print(f"      {r.get('detail', '')}")
            if r.get("mirror_versions"):
                print(f"      mirror has: {', '.join(r['mirror_versions'])}")

    if feature:
        print()
        if any("core" in r["needed_by"] for r in problems):
            print("horo-next CANNOT be installed: a core dependency is unavailable.")
        else:
            print("horo-next core installs. Unavailable features (extras):")
            lost = sorted({e for r in problems for e in r["needed_by"]})
            print("  " + (", ".join(lost) if lost else "none"))

    write_report(results, by_status)
    print(f"\nReport written to {report}")
    if args.dest:
        print(f"Downloaded files kept in {dest} — usable as a wheelhouse:")
        print(f"  pip install --no-index --find-links {dest} horo-next")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
