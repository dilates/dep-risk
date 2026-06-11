from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from dep_risk.cache import Cache, TTL_REGISTRY
from dep_risk.sources._base import fetch_json

USER_AGENT = "dep-risk/1.0 (https://github.com/dilates/dep-risk)"


@dataclass
class CrateOwner:
    login: str
    name: str = ""
    avatar: str = ""
    kind: str = ""


@dataclass
class CrateVersion:
    version: str
    created_at: str = ""
    yanked: bool = False
    checksum: str = ""
    downloads: int = 0


@dataclass
class CrateData:
    name: str
    newest_version: str
    max_version: str = ""
    description: str = ""
    repository: str = ""
    homepage: str = ""
    documentation: str = ""
    downloads: int = 0
    recent_downloads: int = 0
    owners: list[CrateOwner] = field(default_factory=list)
    versions: list[CrateVersion] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""


class CratesRegistry:
    BASE = "https://crates.io/api/v1"

    def __init__(self, cache: Optional[Cache] = None) -> None:
        self._cache = cache
        self._headers = {"User-Agent": USER_AGENT}

    async def fetch_package(
        self, name: str, client: httpx.AsyncClient
    ) -> Optional[CrateData]:
        cache_key = f"cargo:{name}:latest"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return _parse_crate(cached)

        url = f"{self.BASE}/crates/{name}"
        data = await fetch_json(client, url, headers=self._headers)
        if data is None:
            return None

        owners_url = f"{self.BASE}/crates/{name}/owner_users"
        owners_data = await fetch_json(client, owners_url, headers=self._headers)
        if owners_data:
            data["_owners"] = owners_data.get("users", [])

        versions_url = f"{self.BASE}/crates/{name}/versions"
        versions_data = await fetch_json(client, versions_url, headers=self._headers)
        if versions_data:
            data["_versions_detail"] = versions_data.get("versions", [])

        if self._cache:
            self._cache.set(cache_key, data, TTL_REGISTRY)

        return _parse_crate(data)

    async def fetch_package_versions(
        self, name: str, client: httpx.AsyncClient
    ) -> list[CrateVersion]:
        result = await self.fetch_package(name, client)
        if result is None:
            return []
        return result.versions


def _parse_crate(data: dict[str, Any]) -> CrateData:
    crate = data.get("crate", {})
    versions_raw = data.get("versions", []) or data.get("_versions_detail", [])
    owners_raw = data.get("_owners", [])

    owners = [
        CrateOwner(
            login=o.get("login", ""),
            name=o.get("name", "") or "",
            avatar=o.get("avatar", "") or "",
            kind=o.get("kind", ""),
        )
        for o in owners_raw
        if isinstance(o, dict)
    ]

    versions = [
        CrateVersion(
            version=v.get("num", ""),
            created_at=v.get("created_at", ""),
            yanked=v.get("yanked", False),
            checksum=v.get("checksum", "") or "",
            downloads=v.get("downloads", 0),
        )
        for v in versions_raw
        if isinstance(v, dict)
    ]

    keywords = [k.get("keyword", k) if isinstance(k, dict) else str(k) for k in data.get("keywords", [])]
    categories = [c.get("category", c) if isinstance(c, dict) else str(c) for c in data.get("categories", [])]

    return CrateData(
        name=crate.get("name", ""),
        newest_version=crate.get("newest_version", ""),
        max_version=crate.get("max_version", ""),
        description=crate.get("description", "") or "",
        repository=crate.get("repository", "") or "",
        homepage=crate.get("homepage", "") or "",
        documentation=crate.get("documentation", "") or "",
        downloads=crate.get("downloads", 0),
        recent_downloads=crate.get("recent_downloads", 0),
        owners=owners,
        versions=versions,
        keywords=keywords,
        categories=categories,
        created_at=crate.get("created_at", ""),
        updated_at=crate.get("updated_at", ""),
    )
