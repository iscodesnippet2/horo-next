"""Turn an upstream Hermes Agent release checkout into the horo-next package.

    python overlay/horo_overlay.py <upstream-checkout> <expected-version>

horo-next is an unofficial PyPI distribution of Hermes Agent. Upstream stopped
publishing to PyPI and its setup.py refuses to build wheels outside Nix. This
overlay changes packaging only — never product behaviour — so that each
upstream release can be rebuilt as a wheel that installs and works.

Two kinds of step, deliberately treated differently:

* Removal steps (URL dependencies, Python-version gates) are checked by
  POSTCONDITION. Upstream's shape varies between releases — a release may
  simply not contain what main does — so counting anchors would fail on
  correct input. What must hold is the result: no URL requirement survives,
  every core dependency is active on every supported Python.

* Code edits use EXACT anchors and fail if the anchor moved. These change
  behaviour in a specific place; silently skipping one would ship a wheel that
  builds, uploads, and misbehaves — the failure this script exists to prevent.
"""
from __future__ import annotations

import re
import shutil
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(sys.argv[1]).resolve()
EXPECTED_VERSION = sys.argv[2]

DIST_NAME = "horo-next"
# Lowest Python horo-next supports, whatever upstream later declares.
# The upper bound follows each upstream release: we do not vouch for a Python
# upstream has not tested a release against.
MIN_PYTHON = (3, 11)
# The air-gapped machines run CPython 3.12. A release that cannot install
# there is not a release, so it stops here rather than at someone's terminal.
# Upstream main already declares 3.14-only dependencies; if that reaches a
# tagged release, this is the line that catches it.
REQUIRED_PYTHONS = ("3.12",)

# Asset directories at the repo root, outside any Python package — absent from
# a wheel built with upstream's config.
ASSETS = ["skills", "optional-skills", "optional-mcps", "locales"]

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"[overlay] FAIL {msg}")


def ok(msg: str) -> None:
    print(f"[overlay] ok   {msg}")


def edit(path: str, old: str, new: str, count: int = 1) -> None:
    p = ROOT / path
    if not p.exists():
        return fail(f"{path}: file missing")
    text = p.read_text(encoding="utf-8")
    found = text.count(old)
    if found != count:
        return fail(f"{path}: expected {count} anchor(s), found {found}: {old.splitlines()[0][:70]!r}")
    p.write_text(text.replace(old, new), encoding="utf-8")
    ok(path)


def sub_once(path: str, pattern: str, repl: str, label: str) -> None:
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, text, count=1, flags=re.M)
    if n != 1:
        return fail(f"{path}: {label} anchor not found")
    p.write_text(new, encoding="utf-8")
    ok(f"{path}: {label}")


PP = ROOT / "pyproject.toml"

# ── 1. Build guard ───────────────────────────────────────────────────────
# Upstream refuses wheel/sdist builds outside Nix. Patched rather than bypassed
# with HERMES_NIX_BUILD=1, which would claim a Nix build that is not happening.
edit("setup.py",
     '_IN_NIX_BUILD = os.environ.get("HERMES_NIX_BUILD") == "1"',
     '_IN_NIX_BUILD = True  # horo-next: PyPI is a supported target here')

# ── 2. Distribution name and PyPI page ───────────────────────────────────
# hermes-agent belongs to Nous Research on PyPI. The command stays `hermes`
# and the home stays ~/.hermes: this IS Hermes Agent, repackaged.
edit("pyproject.toml", 'name = "hermes-agent"', f'name = "{DIST_NAME}"')
# Upstream's aggregate extras refer to the project by its own name —
# `all` lists "hermes-agent[uvloop]" and friends. After the rename those point
# at the PyPI package hermes-agent (Nous's, frozen at 0.19.0): a different
# distribution providing the same top-level modules. `pip install horo-next[all]`
# would install both and let them overwrite each other. Found when re-locking
# after a security bump failed to resolve against hermes-agent<=0.16.0's pins.
text = PP.read_text(encoding="utf-8")
self_refs = text.count('"hermes-agent[')
PP.write_text(text.replace('"hermes-agent[', f'"{DIST_NAME}['), encoding="utf-8")
ok(f"pyproject.toml: {self_refs} self-referencing extras renamed")
# The one-line summary shows in search results and `pip search`-style listings,
# where the README does not. Upstream's tagline under the horo-next name reads
# as the official package — found on the first TestPyPI upload.
sub_once("pyproject.toml", r'^description = ".*"$',
         'description = "Unofficial PyPI distribution of Hermes Agent by Nous Research"',
         "description")
shutil.copy(HERE.parent / "pypi" / "README.md", ROOT / "README-PYPI.md")
edit("pyproject.toml", 'readme = "README.md"', 'readme = "README-PYPI.md"')

# ── 3. URL dependencies (postcondition) ──────────────────────────────────
# PyPI rejects any Requires-Dist carrying a URL, extras included. Those
# packages move to the operator's wheelhouse.
lines = PP.read_text(encoding="utf-8").splitlines(keepends=True)
url_dep = re.compile(r'^\s*"[^"]*@\s*(git\+|https?://|file:)')
kept = [ln for ln in lines if not url_dep.match(ln)]
if len(kept) != len(lines):
    PP.write_text("".join(kept), encoding="utf-8")
ok(f"pyproject.toml: removed {len(lines) - len(kept)} URL dependencies")

# ── 4. Python range (postcondition) ──────────────────────────────────────
# Upstream main (after v0.21.5) gates every core dependency on
# python_version >= '3.14' as a self-updater migration shim, while declaring
# >=3.11. On PyPI that is a trap: pip on 3.12 installs the package and almost
# none of its dependencies. horo-next keeps 3.11–3.13 working.
text = PP.read_text(encoding="utf-8")
text = text.replace(" and python_version >= '3.14'", "")
text = text.replace("python_version >= '3.14' and ", "")
text = re.sub(r"\s*;\s*python_version >= '3\.14'\s*\"", '"', text)
text = text.replace('environments = ["python_version >= \'3.14\'"]',
                    f'environments = ["python_version >= \'{MIN_PYTHON[0]}.{MIN_PYTHON[1]}\'"]')
PP.write_text(text, encoding="utf-8")

# ── 5. Bundle assets inside a package ────────────────────────────────────
bundle = ROOT / "hermes_cli" / "_bundled"
if bundle.exists():
    shutil.rmtree(bundle)
for name in ASSETS:
    src = ROOT / name
    if not src.is_dir():
        fail(f"asset dir missing upstream: {name}/")
        continue
    # LICENSE files travel with each skill: several are third-party MIT.
    shutil.copytree(src, bundle / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
ok(f"bundled {len(ASSETS)} asset dirs into hermes_cli/_bundled/")
# web_dist/ and tui_dist/ are the prebuilt dashboard and TUI, written by
# build_frontends.py before the wheel is built. Upstream already looks for them
# there; they are .gitignored build output, so its config never packaged them.
sub_once("pyproject.toml", r'^hermes_cli = \[',
         'hermes_cli = ["_bundled/**/*", "web_dist/**/*", "tui_dist/*", ', "package-data")

# _packaged_dir returned the caller's source-checkout default without checking
# it exists. From a wheel that default is site-packages/skills — missing — so
# skills resolved to an absent path instead of the bundled copy.
edit("hermes_constants.py",
     '''    override = os.getenv(env_var, "").strip()
    return Path(override) if override else default if default is not None else get_hermes_home() / subdir''',
     '''    override = os.getenv(env_var, "").strip()
    if override:
        return Path(override)
    if default is not None and default.exists():
        return default
    bundled = Path(__file__).resolve().parent / "hermes_cli" / "_bundled" / subdir
    if bundled.is_dir():
        return bundled
    return default if default is not None else get_hermes_home() / subdir''')

edit("agent/i18n.py",
     '    return Path(__file__).resolve().parent.parent / "locales"\n',
     '''    source = Path(__file__).resolve().parent.parent / "locales"
    if source.is_dir():
        return source
    # Installed from a wheel: locales ship inside hermes_cli/_bundled/.
    return Path(__file__).resolve().parent.parent / "hermes_cli" / "_bundled" / "locales"
''')

# ── 6. Do not adopt a source checkout found in the home directory ────────
# Installed from a wheel there is no .git beside the code, so upstream falls
# back to $HERMES_HOME/hermes-agent — the checkout a source install leaves
# behind. Anyone moving from a source install to pip has one. The banner would
# then report that checkout's commits as this install's.
edit("hermes_cli/banner.py",
     '''    repo_dir = Path(__file__).parent.parent.resolve()
    if not (repo_dir / ".git").exists():
        repo_dir = get_hermes_home() / "hermes-agent"
    return repo_dir if (repo_dir / ".git").exists() else None''',
     '''    repo_dir = Path(__file__).parent.parent.resolve()
    # horo-next: a package install has no checkout of its own; a git repo in
    # $HERMES_HOME belongs to some other install and must not be reported as ours.
    return repo_dir if (repo_dir / ".git").exists() else None''')

# ── 7. `hermes update` on a package install ──────────────────────────────
# Upstream's update assumes a git checkout. From a wheel it first takes a
# HERMES_HOME backup, then on macOS/Linux tells the user to run upstream's curl
# installer, and on Windows extracts a source ZIP into site-packages.
sub_once("hermes_cli/main.py",
         r'^(def cmd_update\(args\):\n    """[^\n]*"""\n)',
         r'''\1    # horo-next: a package install has no checkout to update.
    from pathlib import Path as _Path
    if not (_Path(__file__).resolve().parent.parent / ".git").exists():
        print("horo-next is installed as a Python package. Update it with:")
        print("  pip install -U horo-next")
        return
''', "cmd_update package-install guard")

# ── Postconditions ───────────────────────────────────────────────────────
try:
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.utils import canonicalize_name
except ImportError:
    sys.exit("[overlay] needs `packaging` installed")

meta = tomllib.loads(PP.read_text(encoding="utf-8"))
project = meta["project"]

if project.get("name") != DIST_NAME:
    fail(f"name is {project.get('name')!r}")
if "Unofficial" not in project.get("description", ""):
    fail(f"description does not say it is unofficial: {project.get('description')!r}")
if project.get("version") != EXPECTED_VERSION:
    fail(f"version {project.get('version')!r} != expected {EXPECTED_VERSION!r}")
init_version = re.search(r'^__version__\s*=\s*"([^"]+)"',
                         (ROOT / "hermes_cli" / "__init__.py").read_text(encoding="utf-8"), re.M)
if init_version and init_version.group(1) != EXPECTED_VERSION:
    fail(f"hermes_cli.__version__ {init_version.group(1)!r} != {EXPECTED_VERSION!r}")

all_reqs = list(project.get("dependencies", []))
for group in project.get("optional-dependencies", {}).values():
    all_reqs.extend(group)
url_left = [r for r in all_reqs if Requirement(r).url]
if url_left:
    fail(f"URL dependencies remain: {url_left}")
foreign = [r for r in all_reqs if canonicalize_name(Requirement(r).name) == "hermes-agent"]
if foreign:
    fail(f"requirements still name the upstream distribution: {foreign}")

spec = SpecifierSet(project.get("requires-python", ""))
lo = f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}"
if not spec.contains(lo):
    fail(f"requires-python {spec} excludes {lo}")
supported = [f"3.{m}" for m in range(MIN_PYTHON[1], 20) if spec.contains(f"3.{m}")]
core = [Requirement(r) for r in project.get("dependencies", [])]
for pyv in supported:
    env = {"python_version": pyv, "python_full_version": pyv + ".0", "sys_platform": "linux",
           "platform_system": "Linux", "platform_machine": "x86_64", "os_name": "posix",
           "implementation_name": "cpython", "platform_python_implementation": "CPython", "extra": ""}
    active = sum(1 for r in core if r.marker is None or r.marker.evaluate(env))
    print(f"[overlay] Linux/{pyv}: {active}/{len(core)} core dependencies active")
counts = {pyv: sum(1 for r in core if r.marker is None or r.marker.evaluate(
    {"python_version": pyv, "python_full_version": pyv + ".0", "sys_platform": "linux",
     "platform_system": "Linux", "platform_machine": "x86_64", "os_name": "posix",
     "implementation_name": "cpython", "platform_python_implementation": "CPython", "extra": ""}))
    for pyv in supported}
if len(set(counts.values())) > 1:
    fail(f"core dependency set differs across supported Pythons: {counts}")
for required in REQUIRED_PYTHONS:
    if required not in supported:
        fail(f"Python {required} is not supported by this release ({spec}) — "
             f"the air-gapped target cannot install it")
print(f"[overlay] supported Python: {', '.join(supported)}")

if failures:
    sys.exit(f"[overlay] {len(failures)} step(s) failed — not building")

# The verification matrix is read from here rather than written into the
# workflow: a hardcoded list would drift from what each release declares.
import json  # noqa: E402
(ROOT / "horo-build.json").write_text(
    json.dumps({"version": EXPECTED_VERSION, "pythons": supported}) + "\n", encoding="utf-8")
print("[overlay] done")
