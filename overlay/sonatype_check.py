"""Check a release's SBOM against Sonatype's vulnerability data.

    SONATYPE_GUIDE_TOKEN=... python overlay/sonatype_check.py <sbom.cdx.json> \\
        [--fail] [--notes FILE] [--json FILE]

audit.py checks OSV. An enterprise mirror running Sonatype Repository Firewall
judges by Sonatype's own data, which overlaps with OSV but is not the same —
this asks Sonatype directly, through Sonatype Guide's OSS Index-compatible
component-report API (formerly OSS Index).

Checked: every component in the SBOM that reaches the target — Python
dependencies whose environment marker matches Linux / CPython 3.12 (core and
extras), and every npm package compiled into the bundles. Components are sent
as purls only; nothing else leaves the build.

Needs a Sonatype Guide personal access token (guide.sonatype.com → Settings →
Personal Access Tokens) in SONATYPE_GUIDE_TOKEN; in CI, the repository secret
of the same name. Without one the check cannot run, and says so: it does not
pass by default.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from packaging.markers import Marker

ENDPOINT = os.environ.get("SONATYPE_GUIDE_URL", "https://api.guide.sonatype.com/api/v3/component-report")
BATCH = 128  # OSS Index's per-request limit
TARGET = {"python_version": "3.12", "python_full_version": "3.12.0", "sys_platform": "linux",
          "platform_system": "Linux", "platform_machine": "x86_64", "os_name": "posix",
          "implementation_name": "cpython", "platform_python_implementation": "CPython", "extra": ""}


def reaches_target(c: dict) -> bool:
    if not c.get("purl", "").startswith("pkg:pypi/"):
        return True  # bundled npm: in the wheel on every platform
    marker = next((p["value"] for p in c.get("properties", []) if p["name"] == "horo:environment-marker"), None)
    return marker is None or Marker(marker).evaluate(TARGET)


def query(purls: list[str], token: str) -> list[dict]:
    auth = base64.b64encode(f"horo-next:{token}".encode()).decode()  # user name is ignored for a PAT
    req = urllib.request.Request(ENDPOINT, data=json.dumps({"coordinates": purls}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                sys.exit("[sonatype] 401 Unauthorized: SONATYPE_GUIDE_TOKEN was rejected")
            if e.code == 429 and attempt < 3:
                time.sleep(10 * (attempt + 1))
                continue
            sys.exit(f"[sonatype] HTTP {e.code} from {ENDPOINT}: {e.read()[:300]!r}")
    sys.exit("[sonatype] rate limited; gave up after retries")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sbom", type=Path)
    ap.add_argument("--fail", action="store_true", help="exit non-zero on any finding")
    ap.add_argument("--notes", type=Path)
    ap.add_argument("--json", type=Path, help="append to this audit report (audit.py's format)")
    a = ap.parse_args()

    token = os.environ.get("SONATYPE_GUIDE_TOKEN", "").strip()
    if not token:
        sys.exit("[sonatype] SONATYPE_GUIDE_TOKEN is not set — the Sonatype check did not run. "
                 "Add a Sonatype Guide personal access token as a repository secret of that name.")

    bom = json.loads(a.sbom.read_text(encoding="utf-8"))
    comps = [c for c in bom.get("components", []) if reaches_target(c)]
    purls = sorted({c["purl"] for c in comps})
    results = []
    for i in range(0, len(purls), BATCH):
        results += query(purls[i:i + BATCH], token)

    findings = []
    for r in results:
        for v in r.get("vulnerabilities", []):
            findings.append({"purl": r.get("coordinates"), "id": v.get("id"), "cve": v.get("cve") or v.get("id"),
                             "title": v.get("title", ""), "cvss": v.get("cvssScore"),
                             "reference": v.get("reference")})
    returned = {r.get("coordinates") for r in results}
    py = sum(p.startswith("pkg:pypi/") for p in purls)
    lines = [f"Sonatype (OSS Index API): {len(purls)} components on Linux / Python 3.12 "
             f"({py} Python, {len(purls) - py} bundled npm), {len({f['purl'] for f in findings})} with known advisories"]
    if len(returned) < len(purls):
        lines.append(f"  - note: Sonatype returned {len(returned)} of {len(purls)} components")
    for f in sorted(findings, key=lambda x: (x["purl"], x["cve"])):
        lines.append(f"  - {f['purl']}: {f['cve']} (CVSS {f['cvss']}) {f['title'][:90]}")
    print("\n".join(lines))
    if a.notes:
        with a.notes.open("a", encoding="utf-8") as fh:
            fh.write("\n" + "\n".join(lines) + "\n")
    if a.json:
        data = json.loads(a.json.read_text(encoding="utf-8")) if a.json.is_file() else {"audits": []}
        data["audits"].append({
            "label": "Sonatype, SBOM components",
            "source": a.sbom.name,
            "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "database": "Sonatype (OSS Index-compatible API, Sonatype Guide)",
            "target": {"os": "Linux", "python": "3.12", "implementation": "CPython"},
            "packages": [{"purl": p} for p in purls],
            "advisories": findings,
            "result": "fail" if findings else "pass",
        })
        a.json.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    if findings and a.fail:
        sys.exit("[sonatype] known advisories in Sonatype's data — release held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
