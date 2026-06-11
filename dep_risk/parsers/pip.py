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

_VCS_SCHEMES = ("git+", "hg+", "svn+", "bzr+")
_VERSION_RE = re.compile(r"([A-Za-z0-9_\-\.]+)\s*([=!<>~^]+.*)?")
_EXTRAS_RE = re.compile(r"^([A-Za-z0-9_\-\.]+)\[([^\]]+)\]")


def parse_requirements_txt(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        dep = _parse_req_line(line)
        if dep:
            deps.append(dep)
    return deps


def parse_pipfile(path: Path) -> list[Dependency]:
    if tomllib is None:
        return []
    deps: list[Dependency] = []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, Exception):
        return []

    for section, is_dev in [("packages", False), ("dev-packages", True)]:
        for name, spec in data.get(section, {}).items():
            if name == "python_version":
                continue
            if isinstance(spec, dict):
                version_spec = spec.get("version", "*")
                git_url = spec.get("git")
                if git_url:
                    deps.append(
                        Dependency(
                            name=name,
                            version="git",
                            version_spec=f"git+{git_url}",
                            is_dev=is_dev,
                            is_git_dep=True,
                            git_url=git_url,
                            ecosystem="pip",
                        )
                    )
                    continue
            else:
                version_spec = str(spec)
            version = _extract_version(version_spec)
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    version_spec=version_spec,
                    is_dev=is_dev,
                    ecosystem="pip",
                )
            )
    return deps


def parse_pyproject_toml(path: Path) -> list[Dependency]:
    if tomllib is None:
        return []
    deps: list[Dependency] = []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, Exception):
        return []

    project = data.get("project", {})
    requires = project.get("dependencies", [])
    for spec in requires:
        dep = _parse_req_line(spec)
        if dep:
            deps.append(dep)

    optional_deps = project.get("optional-dependencies", {})
    for group, specs in optional_deps.items():
        for spec in specs:
            dep = _parse_req_line(spec)
            if dep:
                dep.is_dev = group in ("dev", "test", "tests", "testing", "lint", "docs")
                deps.append(dep)

    poetry = data.get("tool", {}).get("poetry", {})
    for section, is_dev in [("dependencies", False), ("dev-dependencies", True), ("group", None)]:
        if section == "group":
            for group_name, group_data in poetry.get("group", {}).items():
                is_dev_group = group_name in ("dev", "test", "lint", "docs")
                for name, spec in group_data.get("dependencies", {}).items():
                    dep = _make_dep_from_poetry(name, spec, is_dev_group)
                    if dep:
                        deps.append(dep)
        else:
            for name, spec in poetry.get(section, {}).items():
                if name == "python":
                    continue
                dep = _make_dep_from_poetry(name, spec, is_dev)
                if dep:
                    deps.append(dep)

    return deps


def _parse_req_line(line: str) -> Optional[Dependency]:
    line = line.split("#")[0].strip()
    if not line:
        return None

    for scheme in _VCS_SCHEMES:
        if line.startswith(scheme):
            name = _extract_vcs_name(line)
            return Dependency(
                name=name or line,
                version="git",
                version_spec=line,
                is_dev=False,
                is_git_dep=True,
                git_url=line,
                ecosystem="pip",
            )

    extras_match = _EXTRAS_RE.match(line)
    if extras_match:
        name = extras_match.group(1)
        extras = [e.strip() for e in extras_match.group(2).split(",")]
        rest = line[extras_match.end():]
        version_spec = rest.strip().lstrip(",").strip()
        version = _extract_version(version_spec)
        return Dependency(
            name=name,
            version=version,
            version_spec=line,
            is_dev=False,
            extras=extras,
            ecosystem="pip",
        )

    m = _VERSION_RE.match(line)
    if not m:
        return None
    name = m.group(1).strip()
    version_spec = (m.group(2) or "").strip()
    version = _extract_version(version_spec)
    return Dependency(
        name=name,
        version=version,
        version_spec=version_spec or "*",
        is_dev=False,
        ecosystem="pip",
    )


def _extract_version(spec: str) -> str:
    if not spec or spec == "*":
        return ""
    m = re.search(r"==\s*([^\s,;]+)", spec)
    if m:
        return m.group(1)
    m = re.search(r"([0-9][^\s,;]*)", spec)
    if m:
        return m.group(1)
    return spec.lstrip("=><~!^ ").split(",")[0].strip()


def _extract_vcs_name(url: str) -> Optional[str]:
    m = re.search(r"#egg=([A-Za-z0-9_\-\.]+)", url)
    if m:
        return m.group(1)
    parts = url.rstrip("/").split("/")
    if parts:
        name = parts[-1]
        name = re.sub(r"\.git$", "", name)
        name = re.sub(r"@.*$", "", name)
        return name
    return None


def _make_dep_from_poetry(
    name: str, spec: object, is_dev: bool
) -> Optional[Dependency]:
    if isinstance(spec, str):
        version = _extract_version(spec)
        return Dependency(
            name=name,
            version=version,
            version_spec=spec,
            is_dev=is_dev,
            ecosystem="pip",
        )
    if isinstance(spec, dict):
        if "git" in spec:
            return Dependency(
                name=name,
                version="git",
                version_spec=f"git+{spec['git']}",
                is_dev=is_dev,
                is_git_dep=True,
                git_url=spec["git"],
                ecosystem="pip",
            )
        version_spec = spec.get("version", "*")
        version = _extract_version(str(version_spec))
        return Dependency(
            name=name,
            version=version,
            version_spec=str(version_spec),
            is_dev=is_dev,
            ecosystem="pip",
        )
    return None
