from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from dep_risk.cache import Cache, TTL_REGISTRY
from dep_risk.sources._base import fetch_json


@dataclass
class NpmMaintainer:
    name: str
    email: str = ""


@dataclass
class NpmVersionData:
    version: str
    scripts: dict[str, str] = field(default_factory=dict)
    dependencies: dict[str, str] = field(default_factory=dict)
    dist_tarball: str = ""
    maintainers: list[NpmMaintainer] = field(default_factory=list)
    publish_time: str = ""


@dataclass
class NpmPackageData:
    name: str
    latest_version: str
    versions: list[str] = field(default_factory=list)
    maintainers: list[NpmMaintainer] = field(default_factory=list)
    time_modified: str = ""
    time_created: str = ""
    repository_url: str = ""
    version_times: dict[str, str] = field(default_factory=dict)
    version_data: dict[str, NpmVersionData] = field(default_factory=dict)
    description: str = ""
    homepage: str = ""
    keywords: list[str] = field(default_factory=list)


class NpmRegistry:
    BASE = "https://registry.npmjs.org"

    def __init__(self, cache: Optional[Cache] = None) -> None:
        self._cache = cache

    async def fetch_package(
        self, name: str, client: httpx.AsyncClient
    ) -> Optional[NpmPackageData]:
        cache_key = f"npm:{name}:latest"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return _parse_npm_package(cached)

        encoded = name.replace("/", "%2F")
        url = f"{self.BASE}/{encoded}"
        data = await fetch_json(client, url)
        if data is None:
            return None

        if self._cache:
            self._cache.set(cache_key, data, TTL_REGISTRY)

        return _parse_npm_package(data)

    async def fetch_package_version(
        self, name: str, version: str, client: httpx.AsyncClient
    ) -> Optional[NpmVersionData]:
        cache_key = f"npm:{name}:{version}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return _parse_npm_version(version, cached)

        encoded = name.replace("/", "%2F")
        url = f"{self.BASE}/{encoded}/{version}"
        data = await fetch_json(client, url)
        if data is None:
            return None

        if self._cache:
            self._cache.set(cache_key, data, TTL_REGISTRY)

        return _parse_npm_version(version, data)


def _parse_npm_package(data: dict[str, Any]) -> NpmPackageData:
    dist_tags = data.get("dist-tags", {})
    latest = dist_tags.get("latest", "")
    time_data = data.get("time", {})

    maintainers = [
        NpmMaintainer(name=m.get("name", ""), email=m.get("email", ""))
        for m in data.get("maintainers", [])
        if isinstance(m, dict)
    ]

    repo = data.get("repository", {})
    if isinstance(repo, str):
        repo_url = repo
    elif isinstance(repo, dict):
        repo_url = repo.get("url", "")
    else:
        repo_url = ""

    version_data: dict[str, NpmVersionData] = {}
    for ver, ver_info in data.get("versions", {}).items():
        if isinstance(ver_info, dict):
            version_data[ver] = _parse_npm_version(ver, ver_info)

    return NpmPackageData(
        name=data.get("name", ""),
        latest_version=latest,
        versions=list(data.get("versions", {}).keys()),
        maintainers=maintainers,
        time_modified=time_data.get("modified", ""),
        time_created=time_data.get("created", ""),
        repository_url=repo_url,
        version_times={k: v for k, v in time_data.items() if k not in ("modified", "created")},
        version_data=version_data,
        description=data.get("description", ""),
        homepage=data.get("homepage", ""),
        keywords=data.get("keywords", []) or [],
    )


def _parse_npm_version(version: str, data: dict[str, Any]) -> NpmVersionData:
    maintainers = [
        NpmMaintainer(name=m.get("name", ""), email=m.get("email", ""))
        for m in data.get("maintainers", [])
        if isinstance(m, dict)
    ]
    dist = data.get("dist", {})
    return NpmVersionData(
        version=version,
        scripts=data.get("scripts", {}),
        dependencies=data.get("dependencies", {}),
        dist_tarball=dist.get("tarball", ""),
        maintainers=maintainers,
    )
