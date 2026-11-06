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
# Security review systems (Sonatype and others) follow Project-URL to the
# source, and read the maintainer to tell this repackaging from the original.
edit("pyproject.toml", 'authors = [{ name = "Nous Research" }]',
     'authors = [{ name = "Nous Research" }]\n'
     'maintainers = [{ name = "horo-next contributors" }]\n'
     'classifiers = [\n'
     '  "Operating System :: POSIX :: Linux",\n'
     '  "Operating System :: MacOS",\n'
     '  "Programming Language :: Python :: 3",\n'
     '  "Topic :: Scientific/Engineering :: Artificial Intelligence",\n'
     ']')
if "[project.urls]" in PP.read_text(encoding="utf-8"):
    fail("pyproject.toml: upstream now declares [project.urls]; merge instead of appending")
else:
    with PP.open("a", encoding="utf-8") as f:
        f.write('\n[project.urls]\n'
                'Source = "https://github.com/iscodesnippet2/horo-next"\n'
                'Issues = "https://github.com/iscodesnippet2/horo-next/issues"\n'
                'Upstream = "https://github.com/NousResearch/hermes-agent"\n')
    ok("pyproject.toml: project URLs")

# ── 2b. Version and install stamp ────────────────────────────────────────
# Since v0.21.6 upstream declares version 0.0.0 and reads its identity from
# install-stamp.json, which each packager (Docker, Nix, desktop) writes. This
# is one more packager. Its distribution names the steward: a tree without a
# checkout is sealed, and `hermes update` refuses with that steward's message
# instead of updating it in place.
STAMP_DISTRIBUTION = DIST_NAME
if re.search(r'^version = "0\.0\.0"$', PP.read_text(encoding="utf-8"), re.M):
    sub_once("pyproject.toml", r'^version = "0\.0\.0"$', f'version = "{EXPECTED_VERSION}"', "version")
    import datetime as _dt
    import json as _json
    import subprocess as _sp
    _git = lambda *a: _sp.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True).stdout.strip()  # noqa: E731
    commit = _git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("install stamp: upstream commit unknown (not a git checkout?)")
    stamp = {
        # Fields as scripts/write_install_stamp.py writes them (schema 2).
        "schemaVersion": 2,
        "commit": commit,
        "commitDate": int(_git("log", "-1", "--format=%ct") or 0) or None,
        "branch": None,
        "builtAt": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "dirty": False,
        "source": "build",
        "distribution": STAMP_DISTRIBUTION,
        "updateMechanism": "external",
        "baseVersion": EXPECTED_VERSION,
        "displayVersion": EXPECTED_VERSION,
        "distance": 0,
        "payload": "bootstrap",
        "tag": None,
    }
    (ROOT / "hermes_cli" / "install-stamp.json").write_text(_json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    ok(f"install stamp: {EXPECTED_VERSION} at {commit[:12]}")
    # The stamp sits beside the code, which in a wheel is site-packages itself —
    # no place for a top-level data file. It ships inside hermes_cli instead.
    edit("pm/paths.py",
         '''        root = install_root()
    return root / "install-stamp.json"''',
         '''        root = install_root()
        packaged = Path(__file__).resolve().parent.parent / "hermes_cli" / "install-stamp.json"
        if not (root / "install-stamp.json").is_file() and packaged.is_file():
            return packaged  # horo-next: the stamp ships inside hermes_cli
    return root / "install-stamp.json"''')
    edit("hermes_cli/steward.py",
         "STEWARD_UPDATE_MESSAGES = {\n",
         "STEWARD_UPDATE_MESSAGES = {\n"
         f'    "{STAMP_DISTRIBUTION}": (\n'
         '        "✗ This Hermes is the horo-next Python package.\\n"\n'
         '        "\\n"\n'
         '        "Update it with pip:\\n"\n'
         '        "  pip install -U horo-next"\n'
         "    ),\n")

# ── 3. URL dependencies (postcondition) ──────────────────────────────────
# PyPI rejects any Requires-Dist carrying a URL, extras included. Those
# packages move to the operator's wheelhouse.
lines = PP.read_text(encoding="utf-8").splitlines(keepends=True)
url_dep = re.compile(r'^\s*"[^"]*@\s*(git\+|https?://|file:)')
kept = [ln for ln in lines if not url_dep.match(ln)]
if len(kept) != len(lines):
    PP.write_text("".join(kept), encoding="utf-8")
ok(f"pyproject.toml: removed {len(lines) - len(kept)} URL dependencies")

# ── 3b. Extras: an allowlist for the air-gapped target (postcondition) ───
# horo-next serves machines that reach a local OpenAI-compatible endpoint, a
# local Mattermost and an enterprise package mirror, nothing else. Extras for
# cloud services and public messaging platforms cannot work there, yet every
# one of their dependencies had to stay free of advisories and was listed in
# the SBOM: they caused most version raises and held releases. Each extra kept
# here is one that works offline. [mattermost] is new: the adapter needs only
# aiohttp, which upstream ships only inside other extras.
KEEP_EXTRAS = {"acp", "cron", "mcp", "pty", "uvloop", "web"}
text = PP.read_text(encoding="utf-8")
upstream_extras = tomllib.loads(text)["project"]["optional-dependencies"]
missing = KEEP_EXTRAS - set(upstream_extras)
if missing:
    fail(f"pyproject.toml: extras to keep are gone upstream: {sorted(missing)}")
aiohttp_pin = next((r for reqs in upstream_extras.values() for r in reqs if r.startswith("aiohttp==")), None)
if aiohttp_pin is None:
    fail("pyproject.toml: no aiohttp pin to reuse for [mattermost]")
for extra in sorted(set(upstream_extras) - KEEP_EXTRAS - {"all"}):
    # One-line `name = [...]` or a multi-line block closed by a lone `]`.
    text, n = re.subn(rf"^{re.escape(extra)} = \[(?:[^\n]*\]|.*?^\])[^\n]*\n", "", text, count=1, flags=re.M | re.S)
    if n != 1:
        fail(f"pyproject.toml: extra [{extra}] not found to drop")
everything = sorted(KEEP_EXTRAS | {"mattermost"})
all_block = "all = [\n" + "".join(f'  "{DIST_NAME}[{x}]",\n' for x in everything) + "]\n"
text, n = re.subn(r"^all = \[.*?^\]\n", lambda _: all_block, text, count=1, flags=re.M | re.S)
if n != 1:
    fail("pyproject.toml: [all] not found to rewrite")
header = "[project.optional-dependencies]\n"
if text.count(header) != 1:
    fail("pyproject.toml: optional-dependencies table not found")
text = text.replace(header, f'{header}mattermost = ["{aiohttp_pin}"]\n')
PP.write_text(text, encoding="utf-8")
ok(f"pyproject.toml: extras reduced to {', '.join(everything)}")

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

# ── 4b. browser-harness, vendored ────────────────────────────────────────
# browser_exec, upstream's only browser tool since v0.23.0, runs on
# browser-harness, a core dependency that pins pillow==12.3.0. Upstream
# needs Pillow 13 for its advisories and gets there with a uv override;
# pip has none, so the published metadata would not resolve. The harness
# ships inside the wheel instead, from the release upstream pins (hash-
# checked), and its other requirements become ours. Its Pillow use (open,
# convert, draw) is what upstream already runs on 13.
#
# Its telemetry, opt-out and sent to PostHog, is switched off: Hermes already
# sets ANONYMIZED_TELEMETRY=false when it starts the harness, and the target
# has no route out.
BH_VERSION = "0.1.13"
BH_WHEEL = ("https://files.pythonhosted.org/packages/4a/bd/f166cf9a465eff436048d25851ab28b0d798af02b56998127a4165227fc4/"
            f"browser_harness-{BH_VERSION}-py3-none-any.whl")
BH_SHA256 = "2491459e4bfc0ee8aea22dc6c4680fc0f791b7ba553446323c50d2883449d769"
vendored: list[dict] = []  # → horo-build.json, read by sbom.py
text = PP.read_text(encoding="utf-8")
bh_line = re.search(r'^\s*"browser-harness==([^";]+)",[^\n]*\n', text, re.M)
if not bh_line:
    ok("pyproject.toml: no browser-harness dependency (before v0.23): nothing to vendor")
elif bh_line.group(1) != BH_VERSION:
    fail(f"pyproject.toml: upstream pins browser-harness {bh_line.group(1)}, vendoring is for {BH_VERSION}")
else:
    import hashlib
    import io
    import urllib.request
    import zipfile
    from email.parser import HeaderParser
    with urllib.request.urlopen(BH_WHEEL, timeout=60) as r:
        blob = r.read()
    if hashlib.sha256(blob).hexdigest() != BH_SHA256:
        fail("browser-harness wheel: SHA-256 mismatch")
    else:
        whl = zipfile.ZipFile(io.BytesIO(blob))
        dest = ROOT / "browser_harness"
        if dest.exists():
            fail("browser_harness/ already exists upstream")
        for name in whl.namelist():
            if name.startswith("browser_harness/"):
                (ROOT / name).parent.mkdir(parents=True, exist_ok=True)
                (ROOT / name).write_bytes(whl.read(name))
        info = f"browser_harness-{BH_VERSION}.dist-info"
        (ROOT / "LICENSES").mkdir(exist_ok=True)
        (ROOT / "LICENSES" / "browser-harness.txt").write_bytes(whl.read(f"{info}/licenses/LICENSE"))
        reqs = [r for r in HeaderParser().parsestr(whl.read(f"{info}/METADATA").decode()).get_all("Requires-Dist", [])
                if "extra ==" not in r]
        core_names = {re.split(r"[=<>!~ ;\[]", r, maxsplit=1)[0].lower().replace("_", "-")
                      for r in tomllib.loads(text)["project"]["dependencies"]}
        added = [r for r in reqs if re.split(r"[=<>!~ ;\[]", r, maxsplit=1)[0].lower() not in core_names]
        text = text.replace(bh_line.group(0), "".join(f'  "{r}",  # horo-next: browser-harness {BH_VERSION}, vendored\n'
                                                      for r in added))
        text = text.replace('license-files = ["LICENSE"]', 'license-files = ["LICENSE", "LICENSES/browser-harness.txt"]')
        PP.write_text(text, encoding="utf-8")
        ok(f"browser-harness {BH_VERSION} vendored; its requirements added: {', '.join(added) or 'none'}")
        vendored.append({"name": "browser-harness", "version": BH_VERSION, "license": "MIT",
                         "url": BH_WHEEL, "sha256": BH_SHA256, "path": "browser_harness",
                         "requires": reqs,
                         "patches": ["pillow==12.3.0 requirement replaced by the core Pillow pin",
                                     "telemetry.is_enabled() returns False",
                                     "admin._latest_release_tag() returns None (no PyPI version check)"]})
        edit("browser_harness/telemetry.py",
             "def is_enabled() -> bool:\n    if _env_disabled():",
             "def is_enabled() -> bool:\n    return False  # horo-next: never sent from a horo-next install\n    if _env_disabled():")
        # Its daily PyPI version check: this copy is updated with horo-next.
        edit("browser_harness/admin.py",
             '    """Return latest PyPI version, or None. Cached for 24h to avoid hammering PyPI."""\n',
             '    """Return latest PyPI version, or None. Cached for 24h to avoid hammering PyPI."""\n'
             "    return None  # horo-next: vendored; it updates with horo-next, not from PyPI\n")
        sub_once("pyproject.toml", r'^\[tool\.setuptools\.packages\.find\]\ninclude = \[\n',
                 '[tool.setuptools.packages.find]\ninclude = [\n  "browser_harness",\n', "vendored package")
        sub_once("pyproject.toml", r'^\[tool\.setuptools\.package-data\]\n',
                 '[tool.setuptools.package-data]\nbrowser_harness = ["SKILL.md", "video-template.html"]\n',
                 "vendored package data")

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
         'hermes_cli = ["_bundled/**/*", "web_dist/**/*", "tui_dist/*", "install-stamp.json", ', "package-data")

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
extras = project.get("optional-dependencies", {})
if set(extras) != KEEP_EXTRAS | {"mattermost", "all"}:
    fail(f"extras are not the allowlist: {sorted(extras)}")
if "Source" not in project.get("urls", {}):
    fail("no Source URL in project metadata")
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
# pip has no overrides: what upstream forces with [tool.uv] must already hold
# in the published requirements, or `pip install horo-next` cannot resolve.
if any(canonicalize_name(Requirement(r).name) == "browser-harness" for r in all_reqs):
    fail("browser-harness is still a requirement (its pillow==12.3.0 pin cannot resolve under pip)")

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
    json.dumps({"version": EXPECTED_VERSION, "pythons": supported, "vendored": vendored}) + "\n", encoding="utf-8")
print("[overlay] done")
