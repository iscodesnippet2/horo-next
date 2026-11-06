"""Sonatype's vulnerability data, through Sonatype Guide's OSS Index-compatible API.

Shared by sonatype_check.py (the release gate) and by security_bump.py and
build_frontends.py, which use it to find versions to raise to: OSV and npm
audit miss advisories Sonatype has (ctranslate2's records carry only commit
ranges; undici's October advisories reached Sonatype before GitHub's global
database), and an enterprise mirror running Sonatype judges by Sonatype's.

Needs SONATYPE_GUIDE_TOKEN (a Guide personal access token). Without one,
`available()` is False: the upgrade steps fall back to OSV / npm audit alone,
and the release gate refuses to pass.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = os.environ.get("SONATYPE_GUIDE_URL", "https://api.guide.sonatype.com/api/v3/component-report")
BATCH = 128  # OSS Index's per-request limit
# Each component asked about costs credits (0.1 on the free tier). One release
# asks about many twice: both bump rounds, then the gate over the SBOM. Answers
# are kept for the run — in memory, and in this file when set, so the workflow's
# steps share them. Only answers are kept; a component not returned is asked again.
CACHE = os.environ.get("HORO_SONATYPE_CACHE", "")
_answers: dict[str, list[dict]] = {}


def token() -> str:
    return os.environ.get("SONATYPE_GUIDE_TOKEN", "").strip()


def available() -> bool:
    return bool(token())


def _post(purls: list[str]) -> list[dict]:
    auth = base64.b64encode(f"horo-next:{token()}".encode()).decode()  # user name is ignored for a PAT
    req = urllib.request.Request(ENDPOINT, data=json.dumps({"coordinates": purls}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                sys.exit("[sonatype] 401 Unauthorized: SONATYPE_GUIDE_TOKEN was rejected")
            if e.code == 402:
                sys.exit(f"[sonatype] out of Sonatype Guide credits — no result, nothing passes: {e.read()[:300]!r}")
            if e.code == 429 and attempt < 3:
                time.sleep(10 * (attempt + 1))
                continue
            sys.exit(f"[sonatype] HTTP {e.code} from {ENDPOINT}: {e.read()[:300]!r}")
    sys.exit("[sonatype] rate limited; gave up after retries")


def _key(purl: str) -> str:
    """Compare purls as Sonatype may echo them: `%40` or `@`, any case, and
    PyPI names with `_`/`.` for `-`."""
    p = urllib.parse.unquote(purl).lower()
    if p.startswith("pkg:pypi/"):
        name, _, ver = p[len("pkg:pypi/"):].partition("@")
        p = "pkg:pypi/" + re.sub(r"[-_.]+", "-", name) + "@" + ver
    return p


NOT_RETURNED = {"id": "NOT-RETURNED", "title": "Sonatype returned no result for this component",
                "cvssScore": None}


def report(purls: list[str]) -> dict[str, list[dict]]:
    """{purl: [vulnerability, ...]} for every purl asked about; an empty list is
    clean. A purl Sonatype did not answer for is NOT treated as clean: it
    carries NOT_RETURNED, so callers fail closed."""
    purls = sorted(set(purls))
    if CACHE and not _answers and os.path.isfile(CACHE):
        with open(CACHE, encoding="utf-8") as f:
            _answers.update(json.load(f))
    out = {p: _answers[_key(p)] for p in purls if _key(p) in _answers}
    todo = [p for p in purls if p not in out]
    asked = {_key(p): p for p in todo}
    for i in range(0, len(todo), BATCH):
        for r in _post(todo[i:i + BATCH]):
            p = asked.get(_key(r.get("coordinates", "")))
            if p:
                out[p] = _answers[_key(p)] = r.get("vulnerabilities", [])
    if todo and CACHE:
        with open(CACHE, "w", encoding="utf-8") as f:
            json.dump(_answers, f)
    for p in purls:
        out.setdefault(p, [NOT_RETURNED])
    return out


def pypi_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name}@{version}"


def npm_purl(name: str, version: str) -> str:
    # purl spec: the scope's "@" is percent-encoded, its "/" is a separator.
    return f"pkg:npm/%40{name[1:]}@{version}" if name.startswith("@") else f"pkg:npm/{name}@{version}"


def first_clean(purl_of, candidates: list[str]) -> str | None:
    """The first candidate version (in the order given) Sonatype reports clean."""
    if not candidates:
        return None
    res = report([purl_of(v) for v in candidates])
    return next((v for v in candidates if not res.get(purl_of(v))), None)
