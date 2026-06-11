from __future__ import annotations

from typing import Any

from dep_risk.scorers.base import Dependency, RiskScore


class GitHubScorer:
    name = "github"
    weight = 0.10

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

        if github_data is None:
            score += 20
            findings.append("No GitHub repository found")
            details.append("No source repository could be found for this package.")
            evidence["no_repo"] = True
            return RiskScore(
                scorer=self.name,
                score=score,
                weight=self.weight,
                finding=findings[0],
                detail="\n".join(details),
                evidence=evidence,
            )

        from dep_risk.sources.github import GitHubRepoData
        if not isinstance(github_data, GitHubRepoData):
            return RiskScore(
                scorer=self.name,
                score=0.0,
                weight=self.weight,
                finding="GitHub data unavailable",
                detail="Could not parse GitHub repository data.",
                evidence={},
            )

        repo = github_data
        evidence["stars"] = repo.stars
        evidence["forks"] = repo.forks
        evidence["open_issues"] = repo.open_issues
        evidence["archived"] = repo.archived
        evidence["license"] = repo.license
        evidence["topics"] = repo.topics

        if repo.archived:
            score += 35
            findings.append("Repository is archived on GitHub")
            details.append("The GitHub repository is archived — no longer maintained.")

        if repo.stars < 10:
            score += 30
            findings.append(f"Very low visibility — only {repo.stars} stars")
            details.append(f"Low star count ({repo.stars}) suggests minimal community oversight.")
        elif repo.stars < 50:
            score += 10
            findings.append(f"Low visibility — {repo.stars} stars")

        if repo.forks > 0 and repo.stars > 0 and repo.forks > repo.stars * 3:
            score += 20
            findings.append(f"Unusual fork/star ratio ({repo.forks} forks vs {repo.stars} stars)")
            details.append("Fork count far exceeds stars — unusual engagement pattern.")
            evidence["fork_star_ratio"] = repo.forks / repo.stars

        if repo.open_issues > 200:
            score += 25
            findings.append(f"Large backlog of {repo.open_issues} open issues")
            details.append(f"High number of unaddressed issues ({repo.open_issues}).")

        if not repo.license:
            score += 20
            findings.append("No license found")
            details.append("Repository has no license — unclear usage rights.")

        warn_topics = {"deprecated", "unmaintained", "archived", "obsolete", "abandoned"}
        bad_topics = warn_topics.intersection(set(t.lower() for t in repo.topics))
        if bad_topics:
            score += 40
            findings.append(f"Repository tagged as: {', '.join(bad_topics)}")
            details.append(f"Topics indicate the package may be abandoned: {bad_topics}")
            evidence["warning_topics"] = list(bad_topics)

        score = min(100.0, score)
        finding = findings[0] if findings else "No GitHub concerns detected"
        detail = "\n".join(details) if details else "Repository appears healthy."

        return RiskScore(
            scorer=self.name,
            score=score,
            weight=self.weight,
            finding=finding,
            detail=detail,
            evidence=evidence,
        )
