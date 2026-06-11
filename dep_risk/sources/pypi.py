from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from dep_risk.cache import Cache, TTL_REGISTRY
from dep_risk.sources._base import fetch_json


@dataclass
class PypiVersionData:
    version: str
    upload_time: str = ""
    has_sig: bool = False
    yanked: bool = False
    yanked_reason: str = ""
    requires_python: str = ""
    packagetype: str = ""


@dataclass
class PypiPackageData:
    name: str
    latest_version: str
    author: str = ""
    author_email: str = ""
    maintainer: str = ""
    maintainer_email: str = ""
    home_page: str = ""
    project_urls: dict[str, str] = field(default_factory=dict)
    requires_dist: list[str] = field(default_factory=list)
    summary: str = ""
    license: str = ""
    keywords: str = ""
    classifiers: list[str] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)
    version_data: dict[str, PypiVersionData] = field(default_factory=dict)
    repository_url: str = ""


class PypiRegistry:
    BASE = "https://pypi.org/pypi"

    def __init__(self, cache: Optional[Cache] = None) -> None:
        self._cache = cache

    async def fetch_package(
        self, name: str, client: httpx.AsyncClient
    ) -> Optional[PypiPackageData]:
        cache_key = f"pip:{name}:latest"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return _parse_pypi_package(cached)

        url = f"{self.BASE}/{name}/json"
        data = await fetch_json(client, url)
        if data is None:
            return None

        if self._cache:
            self._cache.set(cache_key, data, TTL_REGISTRY)

        return _parse_pypi_package(data)

    async def fetch_package_version(
        self, name: str, version: str, client: httpx.AsyncClient
    ) -> Optional[PypiVersionData]:
        cache_key = f"pip:{name}:{version}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return _make_version_data(version, cached)

        url = f"{self.BASE}/{name}/{version}/json"
        data = await fetch_json(client, url)
        if data is None:
            return None

        if self._cache:
            self._cache.set(cache_key, data, TTL_REGISTRY)

        return _make_version_data(version, data)


def _parse_pypi_package(data: dict[str, Any]) -> PypiPackageData:
    info = data.get("info", {})
    releases = data.get("releases", {})
    urls = data.get("urls", [])

    project_urls = info.get("project_urls") or {}
    repo_url = _find_repo_url(project_urls, info.get("home_page", ""))

    version_data: dict[str, PypiVersionData] = {}
    for ver, files in releases.items():
        if not files:
            continue
        first_file = files[0] if isinstance(files, list) and files else {}
        if not isinstance(first_file, dict):
            continue
        version_data[ver] = PypiVersionData(
            version=ver,
            upload_time=first_file.get("upload_time", ""),
            has_sig=first_file.get("has_sig", False),
            yanked=first_file.get("yanked", False),
            yanked_reason=first_file.get("yanked_reason", "") or "",
            requires_python=info.get("requires_python", "") or "",
            packagetype=first_file.get("packagetype", ""),
        )

    return PypiPackageData(
        name=info.get("name", ""),
        latest_version=info.get("version", ""),
        author=info.get("author", "") or "",
        author_email=info.get("author_email", "") or "",
        maintainer=info.get("maintainer", "") or "",
        maintainer_email=info.get("maintainer_email", "") or "",
        home_page=info.get("home_page", "") or "",
        project_urls=project_urls,
        requires_dist=info.get("requires_dist", []) or [],
        summary=info.get("summary", "") or "",
        license=info.get("license", "") or "",
        keywords=info.get("keywords", "") or "",
        classifiers=info.get("classifiers", []) or [],
        versions=list(releases.keys()),
        version_data=version_data,
        repository_url=repo_url,
    )


def _make_version_data(version: str, data: dict[str, Any]) -> PypiVersionData:
    info = data.get("info", {})
    urls = data.get("urls", [])
    first = urls[0] if urls else {}
    return PypiVersionData(
        version=version,
        upload_time=first.get("upload_time", "") if isinstance(first, dict) else "",
        has_sig=first.get("has_sig", False) if isinstance(first, dict) else False,
        yanked=info.get("yanked", False),
        yanked_reason=info.get("yanked_reason", "") or "",
        requires_python=info.get("requires_python", "") or "",
    )


def _find_repo_url(project_urls: dict[str, str], home_page: str) -> str:
    for key, url in project_urls.items():
        key_lower = key.lower()
        if any(k in key_lower for k in ("source", "code", "repository", "github", "gitlab")):
            return url
    if "github.com" in home_page or "gitlab.com" in home_page:
        return home_page
    return ""
