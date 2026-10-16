"""Audit a resolved dependency list for the air-gapped target against OSV.

    python overlay/audit.py <requirements.txt> <label> [--fail] [--notes FILE] [--json FILE]

`--json` appends this audit to a machine-readable report (one object per
audited list): when, against which database, for which target, every package
checked and every advisory found. Security review systems ingest that; the
release notes are for people.

The air-gapped machines run Linux with CPython 3.12. Only packages whose
environment markers match that target are checked, because that is what pip
there would install — a Windows-only or 3.14-only requirement is irrelevant to
it, and counting one would either raise false alarms or hide a real gap
behind noise.

`--fail` exits non-zero on any advisory. The release workflow uses it for core
dependencies: an enterprise mirror that filters by CVE blocks the whole install
if one core package is refused, so a known advisory there is a release
blocker, not a footnote. Extras are reported without failing — a blocked extra
costs one feature, and most extras (Google, Slack, Telegram integrations) are
unreachable from an air-gapped network anyway.

OSV is not the only advisory database. Commercial scanners used by enterprise
mirrors overlap with it but are not identical, so a clean result here narrows
the risk; the probe run inside the enterprise network is what settles it.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
import urllib.request
from pathlib import Path

from packaging.markers import Marker

TARGET = {"python_version": "3.12", "python_full_version": "3.12.0", "sys_platform": "linux",
          "platform_system": "Linux", "platform_machine": "x86_64", "os_name": "posix",
          "implementation_name": "cpython", "platform_python_implementation": "CPython", "extra": ""}

path, label = Path(sys.argv[1]), sys.argv[2]
fail_on_any = "--fail" in sys.argv
notes = Path(sys.argv[sys.argv.index("--notes") + 1]) if "--notes" in sys.argv else None
report = Path(sys.argv[sys.argv.index("--json") + 1]) if "--json" in sys.argv else None

pkgs: dict[str, str] = {}
for raw in path.read_text(encoding="utf-8").splitlines():
    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([^\s;]+)\s*(?:;\s*(.+))?$", raw)
    if not m:
        continue
    if m.group(4) and not Marker(m.group(4)).evaluate(TARGET):
        continue
    pkgs[m.group(1).lower().replace("_", "-")] = m.group(3)


def post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


hits: dict[tuple[str, str], list[str]] = {}
items = list(pkgs.items())
for i in range(0, len(items), 500):
    chunk = items[i:i + 500]
    res = post("https://api.osv.dev/v1/querybatch",
               {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]})
    for (n, v), r in zip(chunk, res["results"]):
        ids = [x["id"] for x in r.get("vulns", []) if not x.get("withdrawn")]
        if ids:
            hits[(n, v)] = ids


def describe(vid: str) -> tuple[str, str]:
    with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=60) as r:
        d = json.load(r)
    sev = (d.get("database_specific") or {}).get("severity") or "UNRATED"
    cve = next((a for a in d.get("aliases", []) if a.startswith("CVE-")), vid)
    return sev, cve


lines = [f"{label}: {len(pkgs)} packages on Linux / Python 3.12, {len(hits)} with known advisories"]
findings = []
for (n, v), ids in sorted(hits.items()):
    seen, parts = set(), []
    for vid in ids:
        sev, cve = describe(vid)
        if cve in seen:
            continue
        seen.add(cve)
        parts.append(f"{cve} {sev}")
        findings.append({"package": n, "version": v, "id": vid, "cve": cve, "severity": sev})
    lines.append(f"  - {n}=={v}: {', '.join(parts)}")

if report:
    data = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else {"audits": []}
    data["audits"].append({
        "label": label,
        "source": path.name,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "database": "OSV (https://osv.dev), ecosystem PyPI",
        "target": {"os": "Linux", "python": "3.12", "implementation": "CPython"},
        "packages": [{"name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"} for n, v in sorted(pkgs.items())],
        "advisories": findings,
        "result": "fail" if hits else "pass",
    })
    report.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")

print("\n".join(lines))
if notes:
    with notes.open("a", encoding="utf-8") as f:
        f.write("\n" + "\n".join(lines) + "\n")

if hits and fail_on_any:
    sys.exit(f"[audit] {label}: known advisories on the air-gapped target — release held")
