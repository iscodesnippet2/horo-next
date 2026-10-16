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
import datetime as dt
import json
import sys
from pathlib import Path

from packaging.markers import Marker

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sonatype  # noqa: E402

TARGET = {"python_version": "3.12", "python_full_version": "3.12.0", "sys_platform": "linux",
          "platform_system": "Linux", "platform_machine": "x86_64", "os_name": "posix",
          "implementation_name": "cpython", "platform_python_implementation": "CPython", "extra": ""}


def reaches_target(c: dict) -> bool:
    if not c.get("purl", "").startswith("pkg:pypi/"):
        return True  # bundled npm: in the wheel on every platform
    marker = next((p["value"] for p in c.get("properties", []) if p["name"] == "horo:environment-marker"), None)
    return marker is None or Marker(marker).evaluate(TARGET)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sbom", type=Path)
    ap.add_argument("--fail", action="store_true", help="exit non-zero on any finding")
    ap.add_argument("--notes", type=Path)
    ap.add_argument("--json", type=Path, help="append to this audit report (audit.py's format)")
    a = ap.parse_args()

    if not sonatype.available():
        sys.exit("[sonatype] SONATYPE_GUIDE_TOKEN is not set — the Sonatype check did not run. "
                 "Add a Sonatype Guide personal access token as a repository secret of that name.")

    bom = json.loads(a.sbom.read_text(encoding="utf-8"))
    comps = [c for c in bom.get("components", []) if reaches_target(c)]
    purls = sorted({c["purl"] for c in comps})
    results = sonatype.report(purls)

    findings = []
    for purl, vulns in results.items():
        for v in vulns:
            findings.append({"purl": purl, "id": v.get("id"), "cve": v.get("cve") or v.get("id"),
                             "title": v.get("title", ""), "cvss": v.get("cvssScore"),
                             "reference": v.get("reference")})
    py = sum(p.startswith("pkg:pypi/") for p in purls)
    lines = [f"Sonatype (OSS Index API): {len(purls)} components on Linux / Python 3.12 "
             f"({py} Python, {len(purls) - py} bundled npm), {len({f['purl'] for f in findings})} with known advisories"]
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
