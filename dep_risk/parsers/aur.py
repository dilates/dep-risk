from __future__ import annotations

import re
from pathlib import Path

from dep_risk.scorers.base import Dependency

_PKG_RE = re.compile(r"^([A-Za-z0-9_\-\.+@]+)(?:[=:]([^\s#]+))?")


def parse_aur_packages(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _PKG_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        version = m.group(2) or ""
        deps.append(
            Dependency(
                name=name,
                version=version,
                version_spec=line,
                is_dev=False,
                ecosystem="aur",
            )
        )
    return deps
