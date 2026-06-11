from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from dep_risk.scorers.base import Dependency


def parse_package_json(path: Path) -> list[Dependency]:
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    deps: list[Dependency] = []

    def add_deps(section: dict[str, str], is_dev: bool) -> None:
        for name, spec in section.items():
            deps.append(
                Dependency(
                    name=name,
                    version=_strip_range(spec),
                    version_spec=spec,
                    is_dev=is_dev,
                    ecosystem="npm",
                )
            )

    add_deps(data.get("dependencies", {}), is_dev=False)
    add_deps(data.get("devDependencies", {}), is_dev=True)
    add_deps(data.get("peerDependencies", {}), is_dev=False)
    return deps


def parse_package_lock(path: Path) -> list[Dependency]:
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    deps: list[Dependency] = []
    lock_version = data.get("lockfileVersion", 1)

    if lock_version >= 2 and "packages" in data:
        for pkg_path, info in data["packages"].items():
            if pkg_path == "":
                continue
            name = info.get("name") or _name_from_path(pkg_path)
            if not name:
                continue
            version = info.get("version", "")
            is_dev = info.get("dev", False)
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    version_spec=version,
                    is_dev=is_dev,
                    ecosystem="npm",
                )
            )
    else:
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            is_dev = info.get("dev", False)
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    version_spec=version,
                    is_dev=is_dev,
                    ecosystem="npm",
                )
            )
            for child_name, child_info in info.get("dependencies", {}).items():
                deps.append(
                    Dependency(
                        name=child_name,
                        version=child_info.get("version", ""),
                        version_spec=child_info.get("version", ""),
                        is_dev=is_dev,
                        depth=1,
                        ecosystem="npm",
                    )
                )

    return _deduplicate(deps)


def parse_node_modules(path: Path) -> list[Dependency]:
    node_modules = path / "node_modules"
    if not node_modules.exists():
        return []

    deps: list[Dependency] = []
    for pkg_json in node_modules.rglob("package.json"):
        parts = pkg_json.parts
        nm_idx = None
        for i, p in enumerate(parts):
            if p == "node_modules":
                nm_idx = i
        if nm_idx is None:
            continue
        depth = sum(1 for p in parts[nm_idx + 1:] if p == "node_modules")
        try:
            with open(pkg_json) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        name = data.get("name", "")
        version = data.get("version", "")
        if not name or not version:
            continue
        deps.append(
            Dependency(
                name=name,
                version=version,
                version_spec=version,
                is_dev=False,
                depth=depth,
                ecosystem="npm",
            )
        )

    return _deduplicate(deps)


def _strip_range(spec: str) -> str:
    return spec.lstrip("^~>=<! ")


def _name_from_path(pkg_path: str) -> Optional[str]:
    parts = pkg_path.split("/")
    while "node_modules" in parts:
        idx = len(parts) - 1 - parts[::-1].index("node_modules")
        parts = parts[idx + 1:]
    if not parts:
        return None
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else None


def _deduplicate(deps: list[Dependency]) -> list[Dependency]:
    seen: dict[str, Dependency] = {}
    for dep in deps:
        key = f"{dep.name}@{dep.version}"
        if key not in seen:
            seen[key] = dep
    return list(seen.values())
