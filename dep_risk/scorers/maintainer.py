from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from dep_risk.scorers.base import Dependency, RiskScore


class MaintainerScorer:
    name = "maintainer"
    weight = 0.25

    async def score(
        self,
        dep: Dependency,
        registry_data: Any,
        github_data: Any,
    ) -> RiskScore:
        score = 0.0
        findings: list[str] = []
        detail_lines: list[str] = []
        evidence: dict[str, Any] = {}

        if dep.ecosystem == "npm":
            score, findings, detail_lines, evidence = _score_npm(registry_data)
        elif dep.ecosystem == "pip":
            score, findings, detail_lines, evidence = _score_pip(registry_data)
        elif dep.ecosystem == "cargo":
            score, findings, detail_lines, evidence = _score_cargo(registry_data)

        score = min(100.0, score)
        finding = findings[0] if findings else "No maintainer concerns detected"
        detail = "\n".join(detail_lines) if detail_lines else "Maintainer activity appears normal."

        return RiskScore(
            scorer=self.name,
            score=score,
            weight=self.weight,
            finding=finding,
            detail=detail,
            evidence=evidence,
        )


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


def _days_ago(s: str) -> Optional[float]:
    dt = _parse_dt(s)
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


def _score_npm(data: Any) -> tuple[float, list[str], list[str], dict[str, Any]]:
    from dep_risk.sources.npm_registry import NpmPackageData
    score = 0.0
    findings: list[str] = []
    details: list[str] = []
    evidence: dict[str, Any] = {}

    if not isinstance(data, NpmPackageData):
        return score, findings, details, evidence

    maintainers = data.maintainers
    evidence["maintainer_count"] = len(maintainers)
    evidence["maintainers"] = [m.name for m in maintainers]

    if len(maintainers) == 1:
        score += 20
        findings.append("Single maintainer with no backup")
        details.append(f"Only one maintainer: {maintainers[0].name}")

    now = datetime.now(timezone.utc)
    six_months_ago = now - timedelta(days=180)
    thirty_days_ago = now - timedelta(days=30)
    seven_days_ago = now - timedelta(days=7)

    versions = data.versions
    recent_versions = []
    for ver, ts in data.version_times.items():
        dt = _parse_dt(ts)
        if dt and dt > six_months_ago:
            recent_versions.append((ver, dt))

    recent_versions.sort(key=lambda x: x[1])

    if len(recent_versions) >= 2:
        oldest_ver_data = data.version_data.get(recent_versions[0][0])
        newest_ver_data = data.version_data.get(recent_versions[-1][0])
        if oldest_ver_data and newest_ver_data:
            old_names = {m.name for m in oldest_ver_data.maintainers}
            new_names = {m.name for m in newest_ver_data.maintainers}
            if old_names and len(old_names) > 3 and len(new_names) == 1:
                score += 35
                findings.append(f"Maintainer exodus — dropped from {len(old_names)} to 1 maintainer")
                details.append(f"Maintainers dropped: {old_names - new_names}")
                evidence["maintainer_exodus"] = True

    latest_ver = data.version_data.get(data.latest_version)
    if latest_ver:
        latest_ver_time = data.version_times.get(data.latest_version, "")
        latest_dt = _parse_dt(latest_ver_time)

        prev_versions = [v for v in data.versions if v != data.latest_version]
        prev_maintainers: set[str] = set()
        for pv in prev_versions[-3:]:
            pv_data = data.version_data.get(pv)
            if pv_data:
                prev_maintainers.update(m.name for m in pv_data.maintainers)

        if latest_ver.maintainers:
            for m in latest_ver.maintainers:
                if prev_maintainers and m.name not in prev_maintainers:
                    days = _days_ago(latest_ver_time)
                    evidence[f"new_maintainer_{m.name}"] = latest_ver_time
                    if days is not None and days <= 7:
                        score += 60
                        findings.append(f"Very recent ownership change — {m.name} added {int(days)}d ago")
                        details.append(f"New maintainer '{m.name}' added only {int(days)} days ago — HIGH RISK")
                    elif days is not None and days <= 30:
                        score += 40
                        findings.append(f"New maintainer added within 30 days: {m.name}")
                        details.append(f"New maintainer '{m.name}' added {int(days)} days ago")

    if len(data.versions) >= 2:
        v1 = data.version_data.get(data.versions[-2]) if len(data.versions) >= 2 else None
        v2 = data.version_data.get(data.versions[-1]) if data.versions else None
        if v1 and v2:
            names_v1 = {m.name for m in v1.maintainers}
            names_v2 = {m.name for m in v2.maintainers}
            if names_v1 and names_v2 and names_v1 != names_v2 and not names_v1.intersection(names_v2):
                score += 50
                findings.append("Package ownership transferred — entire maintainer set changed")
                evidence["ownership_transfer"] = True
                details.append(f"Previous maintainers: {names_v1}\nCurrent maintainers: {names_v2}")

    return score, findings, details, evidence


def _score_pip(data: Any) -> tuple[float, list[str], list[str], dict[str, Any]]:
    from dep_risk.sources.pypi import PypiPackageData
    score = 0.0
    findings: list[str] = []
    details: list[str] = []
    evidence: dict[str, Any] = {}

    if not isinstance(data, PypiPackageData):
        return score, findings, details, evidence

    maintainers = []
    if data.maintainer:
        maintainers.append(data.maintainer)
    if data.author and data.author != data.maintainer:
        maintainers.append(data.author)

    evidence["maintainers"] = maintainers
    evidence["maintainer_count"] = len(maintainers)

    if len(maintainers) <= 1:
        score += 20
        findings.append("Single maintainer/author on PyPI")
        details.append(f"Only one listed maintainer: {maintainers[0] if maintainers else 'unknown'}")

    return score, findings, details, evidence


def _score_cargo(data: Any) -> tuple[float, list[str], list[str], dict[str, Any]]:
    from dep_risk.sources.crates import CrateData
    score = 0.0
    findings: list[str] = []
    details: list[str] = []
    evidence: dict[str, Any] = {}

    if not isinstance(data, CrateData):
        return score, findings, details, evidence

    owners = data.owners
    evidence["owner_count"] = len(owners)
    evidence["owners"] = [o.login for o in owners]

    if len(owners) == 1:
        score += 20
        findings.append("Single owner on crates.io")
        details.append(f"Only one owner: {owners[0].login}")
    elif len(owners) == 0:
        score += 30
        findings.append("No owners listed on crates.io")
        details.append("No owner information available")

    return score, findings, details, evidence
