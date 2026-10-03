"""Map every locked package to what needs it: core, or which extras.

    python overlay/extras_map.py <upstream-checkout> <out.json>

The air-gapped probe reports which packages the enterprise mirror refuses.
That list only becomes useful once each package is tied to a consequence:
a refused core package means horo-next does not install at all, a refused
package needed only by the `google` extra means Google integrations are
unavailable and nothing else changes. This file carries that mapping into
the probe, so the answer is read on the air-gapped machine itself.

Markers are ignored — the mapping is deliberately conservative. A package
listed under an extra is one that extra MAY need on some platform.
"""
from __future__ import annotations

import json
import sys
import tomllib
from collections import deque
from pathlib import Path

lock = tomllib.loads((Path(sys.argv[1]) / "uv.lock").read_text(encoding="utf-8"))
pkgs = {p["name"]: p for p in lock["package"]}
root = next(p for p in lock["package"] if "editable" in p.get("source", {}))
root_name = root["name"]


def closure(edges: list[dict]) -> set[str]:
    seen: set[str] = set()
    queue = deque(edges)
    while queue:
        edge = queue.popleft()
        name = edge["name"]
        target = pkgs.get(name)
        if target is None:
            continue
        # An edge naming the project itself is a self-referencing extra
        # (e.g. horo-next[uvloop] inside [all]); follow the extras it names.
        if name == root_name:
            for extra in edge.get("extra", []):
                queue.extend(root.get("optional-dependencies", {}).get(extra, []))
            continue
        if name not in seen:
            seen.add(name)
            queue.extend(target.get("dependencies", []))
        for extra in edge.get("extra", []):
            queue.extend(target.get("optional-dependencies", {}).get(extra, []))
    return seen


core = closure(root.get("dependencies", []))
mapping: dict[str, list[str]] = {name: ["core"] for name in core}
for extra, edges in sorted(root.get("optional-dependencies", {}).items()):
    for name in closure(edges) - core:
        mapping.setdefault(name, []).append(extra)

Path(sys.argv[2]).write_text(json.dumps(mapping, indent=1, sort_keys=True) + "\n", encoding="utf-8")
print(f"[extras-map] {len(core)} core packages, {len(mapping) - len(core)} extras-only packages")
