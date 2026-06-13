from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from dep_risk.cache import Cache, TTL_REGISTRY
from dep_risk.sources._base import fetch_json, TIMEOUT


@dataclass
class AurPackageData:
    name: str
    version: str
    description: str = ""
    url: str = ""
    num_votes: int = 0
    popularity: float = 0.0
    out_of_date: Optional[int] = None
    maintainer: Optional[str] = None
    submitter: str = ""
    first_submitted: int = 0
    last_modified: int = 0
    url_path: str = ""
    depends: list[str] = field(default_factory=list)
    make_depends: list[str] = field(default_factory=list)
    license: list[str] = field(default_factory=list)
    repository_url: str = ""
    pkgbuild: str = ""


class AurRegistry:
    RPC_BASE = "https://aur.archlinux.org/rpc/v5/info"
    PKGBUILD_BASE = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h="

    def __init__(self, cache: Optional[Cache] = None) -> None:
        self._cache = cache

    async def fetch_package(
        self, name: str, client: httpx.AsyncClient
    ) -> Optional[AurPackageData]:
        cache_key = f"aur:{name}:info"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                pkg = _parse_aur_response(cached)
                if pkg:
                    pkgbuild = await self._fetch_pkgbuild(name, client)
                    pkg.pkgbuild = pkgbuild
                return pkg

        url = f"{self.RPC_BASE}?arg[]={name}"
        data = await fetch_json(client, url)
        if data is None or not data.get("results"):
            return None

        if self._cache:
            self._cache.set(cache_key, data, TTL_REGISTRY)

        pkg = _parse_aur_response(data)
        if pkg:
            pkg.pkgbuild = await self._fetch_pkgbuild(name, client)
        return pkg

    async def _fetch_pkgbuild(self, name: str, client: httpx.AsyncClient) -> str:
        cache_key = f"aur:{name}:pkgbuild"
        if self._cache:
            cached = self._cache.get(cache_key)
            if isinstance(cached, str):
                return cached

        url = f"{self.PKGBUILD_BASE}{name}"
        try:
            resp = await client.get(url, timeout=TIMEOUT)
            if resp.status_code == 200:
                text = resp.text
                if self._cache:
                    self._cache.set(cache_key, text, TTL_REGISTRY)
                return text
        except Exception:
            pass
        return ""


def _parse_aur_response(data: dict[str, Any]) -> Optional[AurPackageData]:
    results = data.get("results", [])
    if not results:
        return None
    r = results[0]

    upstream_url = r.get("URL", "") or ""
    repo_url = upstream_url if any(
        host in upstream_url for host in ("github.com", "gitlab.com", "codeberg.org", "git.")
    ) else ""

    return AurPackageData(
        name=r.get("Name", ""),
        version=r.get("Version", ""),
        description=r.get("Description", "") or "",
        url=upstream_url,
        num_votes=r.get("NumVotes", 0) or 0,
        popularity=float(r.get("Popularity", 0.0) or 0.0),
        out_of_date=r.get("OutOfDate"),
        maintainer=r.get("Maintainer"),
        submitter=r.get("Submitter", "") or "",
        first_submitted=r.get("FirstSubmitted", 0) or 0,
        last_modified=r.get("LastModified", 0) or 0,
        url_path=r.get("URLPath", "") or "",
        depends=r.get("Depends", []) or [],
        make_depends=r.get("MakeDepends", []) or [],
        license=r.get("License", []) or [],
        repository_url=repo_url,
    )
