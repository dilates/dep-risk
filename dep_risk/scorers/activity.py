from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from dep_risk.scorers.base import Dependency, RiskScore


def _parse_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class ActivityScorer:
    name = "activity"
    weight = 0.15

    async def score(
        self,
        dep: Dependency,
        registry_data: Any,
        github_data: Any,
    ) -> RiskScore:
        score = 0.0
        findings: list[str] = []
        details: list[str] = []
        evidence: dict[str, Any] = {}

        if dep.ecosystem == "aur":
            return await self._score_aur(dep, registry_data, github_data)

        pushed_at: Optional[str] = None
        archived = False
        has_source = False

        if github_data is not None:
            from dep_risk.sources.github import GitHubRepoData
            if isinstance(github_data, GitHubRepoData):
                pushed_at = github_data.pushed_at
                archived = github_data.archived
                has_source = True
                evidence["pushed_at"] = pushed_at
                evidence["archived"] = archived
                evidence["recent_commits"] = github_data.recent_commit_count
                evidence["open_issues"] = github_data.open_issues

                if archived:
                    score += 35
                    findings.append("Repository is archived")
                    details.append("The GitHub repository is marked as archived.")

                if pushed_at:
                    days_since = _days_ago(pushed_at)
                    if days_since is not None:
                        if days_since > 5 * 365:
                            score += 50
                            findings.append(f"Long-abandoned — last commit {int(days_since / 365)} years ago")
                            details.append(f"No GitHub activity in {int(days_since)} days — likely unpatched vulnerabilities.")
                        elif days_since > 2 * 365:
                            score += 30
                            findings.append(f"Abandoned project — last commit {int(days_since / 365)} years ago")
                            details.append(f"No GitHub activity in {int(days_since)} days.")

                if github_data.recent_commit_count == 0 and github_data.open_issues > 10:
                    score += 20
                    findings.append("Unmaintained but actively targeted — no commits, many open issues")
                    details.append(f"Zero commits in 90 days but {github_data.open_issues} open issues.")
        else:
            has_source = _check_registry_source(registry_data)

        if not has_source and github_data is None:
            score += 25
            findings.append("No source repository link found")
            details.append("No GitHub or source URL found in registry metadata.")

        release_time = _latest_release_time(registry_data, dep.ecosystem)
        if release_time and github_data and pushed_at:
            release_dt = _parse_dt(release_time)
            push_dt = _parse_dt(pushed_at)
            if release_dt and push_dt:
                gap = abs((release_dt - push_dt).total_seconds()) / 86400
                if gap > 7:
                    score += 40
                    findings.append("Version released without corresponding GitHub commits")
                    details.append(f"Registry release and last GitHub push differ by {gap:.0f} days.")
                    evidence["release_push_gap_days"] = gap

        score = min(100.0, score)
        finding = findings[0] if findings else "No activity concerns detected"
        detail = "\n".join(details) if details else "Project appears actively maintained."

        return RiskScore(
            scorer=self.name,
            score=score,
            weight=self.weight,
            finding=finding,
            detail=detail,
            evidence=evidence,
        )


    async def _score_aur(
        self,
        dep: Dependency,
        registry_data: Any,
        github_data: Any,
    ) -> RiskScore:
        from dep_risk.sources.aur import AurPackageData
        score = 0.0
        findings: list[str] = []
        details: list[str] = []
        evidence: dict[str, Any] = {}

        if isinstance(registry_data, AurPackageData):
            now_ts = datetime.now(timezone.utc).timestamp()
            evidence["last_modified"] = registry_data.last_modified
            evidence["out_of_date"] = registry_data.out_of_date
            evidence["num_votes"] = registry_data.num_votes

            if registry_data.out_of_date:
                days_flagged = (now_ts - registry_data.out_of_date) / 86400
                score += 30
                findings.append(f"Flagged out-of-date {int(days_flagged)} days ago")
                details.append(f"AUR package has been flagged as out-of-date for {int(days_flagged)} days.")

            if registry_data.last_modified:
                days_stale = (now_ts - registry_data.last_modified) / 86400
                if days_stale > 5 * 365:
                    score += 50
                    findings.append(f"Long-abandoned — not updated in {int(days_stale / 365)} years")
                    details.append(f"PKGBUILD last modified {int(days_stale)} days ago.")
                elif days_stale > 2 * 365:
                    score += 30
                    findings.append(f"Stale PKGBUILD — not updated in {int(days_stale / 365)} years")
                    details.append(f"PKGBUILD last modified {int(days_stale)} days ago.")

            if registry_data.num_votes < 10:
                score += 25
                findings.append(f"Very low community scrutiny — only {registry_data.num_votes} votes")
                details.append("Fewer than 10 AUR votes means very few users have reviewed this PKGBUILD.")
            elif registry_data.num_votes < 50:
                score += 10
                findings.append(f"Low AUR votes ({registry_data.num_votes}) — limited community review")

        if github_data is not None:
            from dep_risk.sources.github import GitHubRepoData
            if isinstance(github_data, GitHubRepoData):
                if github_data.archived:
                    score += 35
                    findings.append("Upstream repository is archived")
                    details.append("The upstream GitHub repository is archived.")
                    evidence["archived"] = True

        score = min(100.0, score)
        finding = findings[0] if findings else "No activity concerns detected"
        detail = "\n".join(details) if details else "AUR package appears actively maintained."
        return RiskScore(
            scorer=self.name,
            score=score,
            weight=self.weight,
            finding=finding,
            detail=detail,
            evidence=evidence,
        )


def _days_ago(s: str) -> Optional[float]:
    dt = _parse_dt(s)
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


def _check_registry_source(registry_data: Any) -> bool:
    if registry_data is None:
        return False
    repo = getattr(registry_data, "repository_url", "") or getattr(registry_data, "repository", "") or getattr(registry_data, "home_page", "")
    return bool(repo)


def _latest_release_time(registry_data: Any, ecosystem: str) -> Optional[str]:
    if registry_data is None:
        return None
    if ecosystem == "npm":
        return getattr(registry_data, "time_modified", None)
    if ecosystem == "pip":
        vd = getattr(registry_data, "version_data", {})
        latest = getattr(registry_data, "latest_version", "")
        v = vd.get(latest)
        if v:
            return getattr(v, "upload_time", None)
    if ecosystem == "cargo":
        versions = getattr(registry_data, "versions", [])
        if versions:
            return getattr(versions[0], "created_at", None)
    return None
