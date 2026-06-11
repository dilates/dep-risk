from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from dep_risk.cache import Cache, TTL_GITHUB
from dep_risk.sources._base import fetch_json

_GITHUB_URL_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git|/|$)"
)


@dataclass
class Contributor:
    login: str
    contributions: int = 0


@dataclass
class Release:
    tag_name: str
    published_at: str = ""
    prerelease: bool = False
    draft: bool = False


@dataclass
class GitHubRepoData:
    owner: str
    repo: str
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    archived: bool = False
    pushed_at: str = ""
    created_at: str = ""
    license: str = ""
    topics: list[str] = field(default_factory=list)
    description: str = ""
    default_branch: str = "main"
    size: int = 0
    contributors: list[Contributor] = field(default_factory=list)
    recent_commit_count: int = 0
    releases: list[Release] = field(default_factory=list)
    subscribers_count: int = 0
    language: str = ""


class GitHubSource:
    BASE = "https://api.github.com"

    def __init__(self, token: str = "", cache: Optional[Cache] = None) -> None:
        self._token = token
        self._cache = cache

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    async def fetch_repo(
        self, owner: str, repo: str, client: httpx.AsyncClient
    ) -> Optional[GitHubRepoData]:
        repo = repo.removesuffix(".git")
        cache_key = f"github:{owner}/{repo}:repo"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return _parse_repo(cached)

        url = f"{self.BASE}/repos/{owner}/{repo}"
        data = await fetch_json(client, url, headers=self._headers())
        if data is None:
            return None

        if self._cache:
            self._cache.set(cache_key, data, TTL_GITHUB)

        result = _parse_repo(data)

        contrib_data = await self._fetch_contributors(owner, repo, client)
        result.contributors = contrib_data

        releases = await self._fetch_releases(owner, repo, client)
        result.releases = releases

        return result

    async def _fetch_contributors(
        self, owner: str, repo: str, client: httpx.AsyncClient
    ) -> list[Contributor]:
        cache_key = f"github:{owner}/{repo}:contributors"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return [Contributor(**c) for c in cached]

        url = f"{self.BASE}/repos/{owner}/{repo}/contributors?per_page=20&anon=false"
        data = await fetch_json(client, url, headers=self._headers())
        if not isinstance(data, list):
            return []

        contribs = [
            Contributor(
                login=c.get("login", ""),
                contributions=c.get("contributions", 0),
            )
            for c in data
            if isinstance(c, dict)
        ]

        if self._cache:
            self._cache.set(
                cache_key, [{"login": c.login, "contributions": c.contributions} for c in contribs], TTL_GITHUB
            )

        return contribs

    async def _fetch_releases(
        self, owner: str, repo: str, client: httpx.AsyncClient
    ) -> list[Release]:
        cache_key = f"github:{owner}/{repo}:releases"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return [Release(**r) for r in cached]

        url = f"{self.BASE}/repos/{owner}/{repo}/releases?per_page=10"
        data = await fetch_json(client, url, headers=self._headers())
        if not isinstance(data, list):
            return []

        releases = [
            Release(
                tag_name=r.get("tag_name", ""),
                published_at=r.get("published_at", ""),
                prerelease=r.get("prerelease", False),
                draft=r.get("draft", False),
            )
            for r in data
            if isinstance(r, dict)
        ]

        if self._cache:
            self._cache.set(
                cache_key,
                [{"tag_name": r.tag_name, "published_at": r.published_at, "prerelease": r.prerelease, "draft": r.draft} for r in releases],
                TTL_GITHUB,
            )

        return releases

    async def fetch_commits_recent(
        self, owner: str, repo: str, client: httpx.AsyncClient, days: int = 90
    ) -> int:
        from datetime import datetime, timezone, timedelta
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cache_key = f"github:{owner}/{repo}:commits:{days}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return int(cached)

        url = f"{self.BASE}/repos/{owner}/{repo}/commits?per_page=100&since={since}"
        data = await fetch_json(client, url, headers=self._headers())
        count = len(data) if isinstance(data, list) else 0

        if self._cache:
            self._cache.set(cache_key, count, TTL_GITHUB)

        return count


def parse_github_url(url: str) -> Optional[tuple[str, str]]:
    if not url:
        return None
    m = _GITHUB_URL_RE.search(url)
    if m:
        return m.group(1), m.group(2)
    return None


def _parse_repo(data: dict[str, Any]) -> GitHubRepoData:
    license_data = data.get("license") or {}
    license_name = license_data.get("spdx_id", "") or license_data.get("name", "") if isinstance(license_data, dict) else ""

    return GitHubRepoData(
        owner=data.get("owner", {}).get("login", "") if isinstance(data.get("owner"), dict) else "",
        repo=data.get("name", ""),
        stars=data.get("stargazers_count", 0),
        forks=data.get("forks_count", 0),
        open_issues=data.get("open_issues_count", 0),
        archived=data.get("archived", False),
        pushed_at=data.get("pushed_at", "") or "",
        created_at=data.get("created_at", "") or "",
        license=license_name,
        topics=data.get("topics", []) or [],
        description=data.get("description", "") or "",
        default_branch=data.get("default_branch", "main"),
        size=data.get("size", 0),
        subscribers_count=data.get("subscribers_count", 0),
        language=data.get("language", "") or "",
    )
