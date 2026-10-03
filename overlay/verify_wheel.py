"""Install a built horo-next wheel into a clean venv and check it actually works.

    python overlay/verify_wheel.py <wheel> <python-version> <expected-version>

Every check here guards a failure that a successful build and upload would not
reveal. The wheel can be accepted by PyPI and install without error while:
skills are absent, dependencies are missing on some Pythons, the version reads
"unknown", `hermes update` damages the install, or a source checkout in the home
directory is reported as this install. Each of those was found by installing
into a clean venv — none by building.

Runs outside the source tree with a throwaway HERMES_HOME, so nothing resolves
to the checkout and nothing touches a real ~/.hermes.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

WHEEL, PYV, EXPECTED = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3]

failures: list[str] = []


def check(cond: bool, label: str, detail: str = "") -> None:
    print(f"  {'ok  ' if cond else 'FAIL'} {label}{(' — ' + detail) if detail else ''}")
    if not cond:
        failures.append(label)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    venv, home, cwd = tmp / "venv", tmp / "home", tmp / "elsewhere"
    home.mkdir(); cwd.mkdir()
    env = {**os.environ, "HERMES_HOME": str(home), "VIRTUAL_ENV": str(venv), "NO_COLOR": "1"}
    env.pop("PYTHONPATH", None)

    def run(*cmd, **kw):
        return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=600, **kw)

    print(f"[verify] Python {PYV}")
    r = run("uv", "venv", "--python", PYV, str(venv))
    if r.returncode:
        sys.exit(f"[verify] cannot create a {PYV} venv:\n{r.stderr[-800:]}")
    r = run("uv", "pip", "install", str(WHEEL))
    check(r.returncode == 0, "wheel installs", r.stderr[-400:] if r.returncode else "")
    if r.returncode:
        sys.exit(1)

    py, hermes = venv / "bin" / "python", venv / "bin" / "hermes"

    probe = r'''
import json, re, importlib.metadata as md
from pathlib import Path
out = {}
dist = md.distribution("horo-next")
out["name"], out["version"] = dist.metadata["Name"], dist.version
reqs = dist.requires or []
out["url_reqs"] = [r for r in reqs if re.search(r"@\s*(git\+|https?://)", r)]
out["upstream_reqs"] = [r for r in reqs if re.match(r"hermes[-_]agent\b", r, re.I)]
out["license"] = any("licenses/LICENSE" in str(f) for f in (dist.files or []))
try:
    md.distribution("hermes-agent"); out["upstream_installed"] = True
except md.PackageNotFoundError:
    out["upstream_installed"] = False
import hermes_cli, hermes_constants as hc
out["module_version"] = hermes_cli.__version__
base = Path(hc.__file__).parent
for key, fn in (("skills", hc.get_bundled_skills_dir), ("optional", hc.get_optional_skills_dir)):
    d = fn(base / ("skills" if key == "skills" else "optional-skills"))
    out[key] = [str(d), d.is_dir(), sum(1 for _ in d.rglob("SKILL.md")) if d.is_dir() else 0]
import agent.i18n as i18n
locdir = next((getattr(i18n, n)() for n in dir(i18n)
               if "locale" in n.lower() and "dir" in n.lower() and callable(getattr(i18n, n))), None)
out["locales"] = len(list(Path(locdir).glob("*"))) if locdir and Path(locdir).is_dir() else 0
from tools.skills_sync import sync_skills
out["synced"] = len((sync_skills(quiet=True) or {}).get("copied", []))
from hermes_cli import banner
fake = Path(__import__("os").environ["HERMES_HOME"]) / "hermes-agent" / ".git"
fake.mkdir(parents=True)
out["adopted_home_checkout"] = str(banner._resolve_repo_dir())
print("JSON" + json.dumps(out))
'''
    r = run(str(py), "-c", probe)
    data = {}
    for line in r.stdout.splitlines():
        if line.startswith("JSON"):
            data = json.loads(line[4:])
    check(bool(data), "package imports and resolves its assets", r.stderr[-600:] if not data else "")
    if data:
        check(data["name"] == "horo-next", "distribution name", data["name"])
        check(data["version"] == EXPECTED, "distribution version", data["version"])
        check(data["module_version"] == EXPECTED, "hermes_cli.__version__", data["module_version"])
        check(not data["url_reqs"], "no URL requirements", str(data["url_reqs"]))
        check(not data["upstream_reqs"], "no requirement on the upstream distribution", str(data["upstream_reqs"]))
        check(not data["upstream_installed"], "upstream hermes-agent was not pulled in")
        check(data["license"], "MIT license shipped in dist-info")
        check(data["skills"][1] and data["skills"][2] > 0 and "_bundled" in data["skills"][0],
              "bundled skills resolve from the wheel", f"{data['skills'][2]} SKILL.md")
        check(data["optional"][1] and data["optional"][2] > 0, "optional skills resolve",
              f"{data['optional'][2]} SKILL.md")
        check(data["locales"] > 0, "locales resolve", f"{data['locales']} files")
        check(data["synced"] > 0, "bundled skills sync into HERMES_HOME", f"{data['synced']} copied")
        check(data["adopted_home_checkout"] == "None",
              "a git checkout in HERMES_HOME is not adopted as this install",
              data["adopted_home_checkout"])

    r = run(str(hermes), "--version")
    check(r.returncode == 0 and EXPECTED in r.stdout, "`hermes --version`", r.stdout.strip().splitlines()[0] if r.stdout else r.stderr[-200:])

    # Upstream's update takes a HERMES_HOME backup before anything else; that is
    # the side effect being guarded. Log files are excluded because every full
    # CLI start opens agent.log/errors.log, whichever subcommand runs — they say
    # nothing about what update did. Anything else new is a failure.
    def state(root: Path) -> set[str]:
        return {str(p.relative_to(root)) for p in root.rglob("*")
                if p.suffix != ".log" and "logs" not in p.relative_to(root).parts}

    before = state(home)
    r = run(str(hermes), "update")
    after = state(home)
    check(r.returncode == 0 and "pip install -U horo-next" in r.stdout,
          "`hermes update` points to pip", r.stdout.strip().splitlines()[-1] if r.stdout else "")
    check(after == before, "`hermes update` takes no backup and changes no state",
          f"new: {sorted(after - before)[:5]}")

    r = run(str(hermes), "skills", "list")
    builtin = next((ln for ln in r.stdout.splitlines() if "builtin" in ln and "enabled" in ln), "")
    check("0 builtin" not in builtin and builtin != "", "`hermes skills list` shows builtin skills", builtin.strip())

if failures:
    sys.exit(f"[verify] Python {PYV}: {len(failures)} check(s) failed")
print(f"[verify] Python {PYV}: all checks passed")
