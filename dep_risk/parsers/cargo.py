from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from dep_risk.scorers.base import Dependency

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


def parse_cargo_toml(path: Path) -> list[Dependency]:
    if tomllib is None:
        return []
    deps: list[Dependency] = []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, Exception):
        return []

    workspace_deps = data.get("workspace", {}).get("dependencies", {})
    _collect_cargo_deps(workspace_deps, is_dev=False, deps=deps)

    _collect_cargo_deps(data.get("dependencies", {}), is_dev=False, deps=deps)
    _collect_cargo_deps(data.get("dev-dependencies", {}), is_dev=True, deps=deps)
    _collect_cargo_deps(data.get("build-dependencies", {}), is_dev=False, deps=deps)

    for target_cfg in data.get("target", {}).values():
        _collect_cargo_deps(target_cfg.get("dependencies", {}), is_dev=False, deps=deps)
        _collect_cargo_deps(target_cfg.get("dev-dependencies", {}), is_dev=True, deps=deps)

    return deps


def parse_cargo_lock(path: Path) -> list[Dependency]:
    if tomllib is None:
        return _parse_cargo_lock_manual(path)
    deps: list[Dependency] = []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, Exception):
        return _parse_cargo_lock_manual(path)

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        checksum = pkg.get("checksum")
        source = pkg.get("source", "")
        is_git = source.startswith("git+")
        is_path = not source and not checksum

        dep = Dependency(
            name=name,
            version=version,
            version_spec=version,
            is_dev=False,
            ecosystem="cargo",
            checksum=checksum,
            is_path_dep=is_path,
            is_git_dep=is_git,
            git_url=source if is_git else None,
        )
        deps.append(dep)
    return deps


def _parse_cargo_lock_manual(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    current: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current:
                dep = _pkg_dict_to_dep(current)
                if dep:
                    deps.append(dep)
            current = {}
        elif "=" in line and not line.startswith("#"):
            key, _, val = line.partition("=")
            current[key.strip()] = val.strip().strip('"')
    if current:
        dep = _pkg_dict_to_dep(current)
        if dep:
            deps.append(dep)
    return deps


def _pkg_dict_to_dep(pkg: dict[str, str]) -> Optional[Dependency]:
    name = pkg.get("name", "")
    version = pkg.get("version", "")
    if not name:
        return None
    checksum = pkg.get("checksum")
    source = pkg.get("source", "")
    is_git = source.startswith("git+")
    is_path = not source and not checksum
    return Dependency(
        name=name,
        version=version,
        version_spec=version,
        is_dev=False,
        ecosystem="cargo",
        checksum=checksum,
        is_path_dep=is_path,
        is_git_dep=is_git,
        git_url=source if is_git else None,
    )


def _collect_cargo_deps(
    section: dict[str, object], is_dev: bool, deps: list[Dependency]
) -> None:
    for name, spec in section.items():
        if isinstance(spec, str):
            deps.append(
                Dependency(
                    name=name,
                    version=spec,
                    version_spec=spec,
                    is_dev=is_dev,
                    ecosystem="cargo",
                )
            )
        elif isinstance(spec, dict):
            if "path" in spec:
                deps.append(
                    Dependency(
                        name=name,
                        version=spec.get("version", ""),
                        version_spec=str(spec.get("version", "")),
                        is_dev=is_dev,
                        is_path_dep=True,
                        ecosystem="cargo",
                    )
                )
                continue
            if "git" in spec:
                deps.append(
                    Dependency(
                        name=name,
                        version="git",
                        version_spec=f"git+{spec['git']}",
                        is_dev=is_dev,
                        is_git_dep=True,
                        git_url=spec["git"],
                        ecosystem="cargo",
                    )
                )
                continue
            version = str(spec.get("version", ""))
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    version_spec=version,
                    is_dev=is_dev,
                    ecosystem="cargo",
                )
            )
