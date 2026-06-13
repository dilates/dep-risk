from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import httpx

from dep_risk.cache import Cache, get_default_cache
from dep_risk.config import Config
from dep_risk.parsers.aur import parse_aur_packages
from dep_risk.parsers.cargo import parse_cargo_lock, parse_cargo_toml
from dep_risk.parsers.npm import parse_node_modules, parse_package_json, parse_package_lock
from dep_risk.parsers.pip import parse_pipfile, parse_pyproject_toml, parse_requirements_txt
from dep_risk.scorers import (
    ActivityScorer,
    EntropyScorer,
    GitHubScorer,
    InstallScriptScorer,
    MaintainerScorer,
    TyposquatScorer,
    VersionScorer,
)
from dep_risk.scorers.base import Dependency, PackageResult
from dep_risk.sources.aur import AurRegistry
from dep_risk.sources.crates import CratesRegistry
from dep_risk.sources.github import GitHubSource, parse_github_url
from dep_risk.sources.npm_registry import NpmRegistry
from dep_risk.sources.pypi import PypiRegistry

log = logging.getLogger(__name__)

SCORERS = [
    MaintainerScorer(),
    ActivityScorer(),
    InstallScriptScorer(),
    TyposquatScorer(),
    VersionScorer(),
    GitHubScorer(),
    EntropyScorer(),
]


def detect_ecosystems(directory: Path) -> list[str]:
    ecosystems: list[str] = []
    if (directory / "package.json").exists():
        ecosystems.append("npm")
    if any(
        directory.glob(p)
        for p in ("requirements*.txt", "Pipfile", "setup.py", "setup.cfg")
    ) or _has_python_pyproject(directory):
        ecosystems.append("pip")
    if (directory / "Cargo.toml").exists():
        ecosystems.append("cargo")
    if (directory / "packages.aur").exists():
        ecosystems.append("aur")
    return ecosystems


def _has_python_pyproject(directory: Path) -> bool:
    pp = directory / "pyproject.toml"
    if not pp.exists():
        return False
    try:
        text = pp.read_text()
        return "[project]" in text or "[tool.poetry]" in text
    except OSError:
        return False


def collect_dependencies(
    directory: Path,
    ecosystems: list[str],
    include_dev: bool,
    exclude: list[str],
) -> list[Dependency]:
    all_deps: list[Dependency] = []

    if "npm" in ecosystems:
        lock = directory / "package-lock.json"
        if lock.exists():
            all_deps.extend(parse_package_lock(lock))
        elif (directory / "package.json").exists():
            all_deps.extend(parse_package_json(directory / "package.json"))
        else:
            all_deps.extend(parse_node_modules(directory))

    if "pip" in ecosystems:
        for req_file in sorted(directory.glob("requirements*.txt")):
            all_deps.extend(parse_requirements_txt(req_file))
        pipfile = directory / "Pipfile"
        if pipfile.exists():
            all_deps.extend(parse_pipfile(pipfile))
        pp = directory / "pyproject.toml"
        if pp.exists() and _has_python_pyproject(directory):
            all_deps.extend(parse_pyproject_toml(pp))

    if "cargo" in ecosystems:
        lock = directory / "Cargo.lock"
        toml = directory / "Cargo.toml"
        if lock.exists():
            all_deps.extend(parse_cargo_lock(lock))
        elif toml.exists():
            all_deps.extend(parse_cargo_toml(toml))

    if "aur" in ecosystems:
        aur_file = directory / "packages.aur"
        if aur_file.exists():
            all_deps.extend(parse_aur_packages(aur_file))

    filtered: list[Dependency] = []
    seen: set[str] = set()
    for dep in all_deps:
        if dep.name in exclude:
            continue
        if dep.is_path_dep:
            continue
        if dep.is_dev and not include_dev:
            continue
        key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
        if key not in seen:
            seen.add(key)
            filtered.append(dep)

    return filtered


class Scanner:
    def __init__(self, config: Config, cache: Optional[Cache] = None) -> None:
        self._config = config
        self._cache = cache if not config.no_cache else None

        self._npm = NpmRegistry(cache=self._cache)
        self._pypi = PypiRegistry(cache=self._cache)
        self._crates = CratesRegistry(cache=self._cache)
        self._aur = AurRegistry(cache=self._cache)
        self._github = GitHubSource(token=config.github_token, cache=self._cache)

    async def scan(
        self,
        directory: Path,
        ecosystems: list[str],
        progress_callback=None,
    ) -> list[PackageResult]:
        deps = collect_dependencies(
            directory,
            ecosystems,
            self._config.include_dev,
            self._config.exclude,
        )

        semaphore = asyncio.Semaphore(self._config.workers)
        results: list[PackageResult] = []

        limits = httpx.Limits(max_connections=self._config.workers, max_keepalive_connections=self._config.workers)
        async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
            tasks = [
                self._process_package(dep, client, semaphore)
                for dep in deps
            ]
            for i, coro in enumerate(asyncio.as_completed(tasks)):
                result = await coro
                results.append(result)
                if progress_callback:
                    progress_callback(i + 1, len(deps), result.name)

        results.sort(key=lambda r: r.total_score, reverse=True)
        return results

    async def _process_package(
        self,
        dep: Dependency,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
    ) -> PackageResult:
        async with semaphore:
            registry_data = None
            github_data = None
            fetch_errors: list[str] = []
            registry_url = ""
            github_url: Optional[str] = None

            try:
                registry_data, registry_url = await self._fetch_registry(dep, client)
            except Exception as exc:
                fetch_errors.append(f"Registry fetch error: {exc}")

            repo_url = _extract_repo_url(registry_data, dep.ecosystem)
            if repo_url:
                github_url = _normalize_github_url(repo_url)
                parsed = parse_github_url(repo_url)
                if parsed:
                    try:
                        github_data = await self._github.fetch_repo(parsed[0], parsed[1], client)
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 403:
                            fetch_errors.append("GitHub rate limit reached — GitHub scorer skipped")
                        else:
                            fetch_errors.append(f"GitHub fetch error: {exc}")
                    except Exception as exc:
                        fetch_errors.append(f"GitHub fetch error: {exc}")

            if dep.is_git_dep:
                fetch_errors.append("Pinned to VCS, not a registry package — elevated risk")

            result = PackageResult(
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                registry_url=registry_url,
                github_url=github_url,
                fetch_errors=fetch_errors,
            )

            for scorer in SCORERS:
                try:
                    risk_score = await scorer.score(dep, registry_data, github_data)
                    result.scores[scorer.name] = risk_score
                    if risk_score.score > 0 and risk_score.finding:
                        result.flags.append(risk_score.finding)
                except Exception as exc:
                    fetch_errors.append(f"Scorer '{scorer.name}' error: {exc}")
                    log.debug("Scorer %s failed for %s: %s", scorer.name, dep.name, exc)

            if dep.is_git_dep:
                result.flags.insert(0, "Pinned to VCS URL — not a registry package")

            result.compute_total(self._config.weights)
            return result

    async def _fetch_registry(
        self, dep: Dependency, client: httpx.AsyncClient
    ) -> tuple[object, str]:
        if dep.ecosystem == "npm":
            data = await self._npm.fetch_package(dep.name, client)
            url = f"https://registry.npmjs.org/{dep.name}"
            return data, url
        if dep.ecosystem == "pip":
            data = await self._pypi.fetch_package(dep.name, client)
            url = f"https://pypi.org/project/{dep.name}/"
            return data, url
        if dep.ecosystem == "cargo":
            data = await self._crates.fetch_package(dep.name, client)
            url = f"https://crates.io/crates/{dep.name}"
            return data, url
        if dep.ecosystem == "aur":
            data = await self._aur.fetch_package(dep.name, client)
            url = f"https://aur.archlinux.org/packages/{dep.name}"
            return data, url
        return None, ""


def _extract_repo_url(registry_data: object, ecosystem: str) -> str:
    if registry_data is None:
        return ""
    if ecosystem == "npm":
        return getattr(registry_data, "repository_url", "") or ""
    if ecosystem == "pip":
        return getattr(registry_data, "repository_url", "") or getattr(registry_data, "home_page", "") or ""
    if ecosystem == "cargo":
        return getattr(registry_data, "repository", "") or ""
    if ecosystem == "aur":
        return getattr(registry_data, "repository_url", "") or getattr(registry_data, "url", "") or ""
    return ""


def _normalize_github_url(url: str) -> Optional[str]:
    from dep_risk.sources.github import parse_github_url
    parsed = parse_github_url(url)
    if parsed:
        return f"https://github.com/{parsed[0]}/{parsed[1]}"
    return url if url.startswith("http") else None
