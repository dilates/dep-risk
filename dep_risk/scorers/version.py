from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from dep_risk.scorers.base import Dependency, RiskScore

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


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


def _parse_semver(ver: str) -> Optional[tuple[int, int, int]]:
    m = _VERSION_RE.match(ver)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


class VersionScorer:
    name = "version"
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

        version_times = _get_version_times(registry_data, dep.ecosystem)
        yanked_versions = _get_yanked_versions(registry_data, dep.ecosystem)

        if not version_times:
            return RiskScore(
                scorer=self.name,
                score=0.0,
                weight=self.weight,
                finding="No version history available",
                detail="Could not retrieve version history.",
                evidence={},
            )

        sorted_versions = sorted(version_times.items(), key=lambda x: x[1] or "")

        for i in range(len(sorted_versions) - 1):
            ver1, ts1 = sorted_versions[i]
            ver2, ts2 = sorted_versions[i + 1]
            dt1 = _parse_dt(ts1) if ts1 else None
            dt2 = _parse_dt(ts2) if ts2 else None
            if dt1 and dt2:
                gap_hours = abs((dt2 - dt1).total_seconds()) / 3600
                sv1 = _parse_semver(ver1)
                sv2 = _parse_semver(ver2)
                if sv1 and sv2:
                    major_jump = sv2[0] - sv1[0]
                    if major_jump >= 1 and gap_hours <= 24:
                        score += 25
                        findings.append(f"Two major versions released within 24 hours ({ver1} → {ver2})")
                        details.append(f"Major version bump from {ver1} to {ver2} in {gap_hours:.0f}h")
                        evidence["rapid_major_bump"] = {"from": ver1, "to": ver2, "hours": gap_hours}

        for ver, ts in version_times.items():
            dt = _parse_dt(ts) if ts else None
            if dt:
                if dt.weekday() >= 5 and (2 <= dt.hour <= 5):
                    score += 15
                    findings.append(f"Version {ver} released on weekend at unusual hour ({dt.hour}:00 UTC)")
                    details.append(f"{ver} released {ts} — weekend late-night release pattern")
                    evidence[f"{ver}_unusual_time"] = ts
                    break

        sv_list = []
        for ver, _ in sorted_versions:
            sv = _parse_semver(ver)
            if sv:
                sv_list.append((ver, sv))

        for i in range(len(sv_list) - 1):
            v1_name, (maj1, min1, pat1) = sv_list[i]
            v2_name, (maj2, min2, pat2) = sv_list[i + 1]
            if maj1 == maj2 and min1 == min2:
                if pat2 - pat1 > 50:
                    score += 20
                    findings.append(f"Large patch version skip: {v1_name} → {v2_name}")
                    details.append(f"Patch version jumped from {pat1} to {pat2}")
                    evidence["version_skip"] = {"from": v1_name, "to": v2_name}
                    break
            elif maj1 == maj2 and min2 - min1 > 20:
                score += 20
                findings.append(f"Large minor version skip: {v1_name} → {v2_name}")
                details.append(f"Minor version jumped from {min1} to {min2}")
                evidence["version_skip"] = {"from": v1_name, "to": v2_name}
                break

        if yanked_versions:
            score += 30
            findings.append(f"Version(s) yanked/unpublished: {', '.join(yanked_versions[:3])}")
            details.append(f"Yanked versions: {yanked_versions}")
            evidence["yanked_versions"] = yanked_versions

        is_first = _is_first_publisher_release(registry_data, dep.ecosystem)
        if is_first:
            score += 20
            findings.append("First version published by this account")
            details.append("This appears to be the first-ever package published by this maintainer.")
            evidence["first_publisher_release"] = True

        score = min(100.0, score)
        finding = findings[0] if findings else "No version anomalies detected"
        detail = "\n".join(details) if details else "Version history appears normal."

        return RiskScore(
            scorer=self.name,
            score=score,
            weight=self.weight,
            finding=finding,
            detail=detail,
            evidence=evidence,
        )


def _get_version_times(registry_data: Any, ecosystem: str) -> dict[str, Optional[str]]:
    if registry_data is None:
        return {}
    if ecosystem == "npm":
        vt = getattr(registry_data, "version_times", {})
        return {k: v for k, v in vt.items()}
    if ecosystem == "pip":
        vd = getattr(registry_data, "version_data", {})
        return {ver: getattr(v, "upload_time", None) for ver, v in vd.items()}
    if ecosystem == "cargo":
        vd = getattr(registry_data, "versions", [])
        return {v.version: v.created_at for v in vd}
    return {}


def _get_yanked_versions(registry_data: Any, ecosystem: str) -> list[str]:
    if registry_data is None:
        return []
    yanked = []
    if ecosystem == "pip":
        for ver, vdata in getattr(registry_data, "version_data", {}).items():
            if getattr(vdata, "yanked", False):
                yanked.append(ver)
    if ecosystem == "cargo":
        for v in getattr(registry_data, "versions", []):
            if getattr(v, "yanked", False):
                yanked.append(v.version)
    return yanked


def _is_first_publisher_release(registry_data: Any, ecosystem: str) -> bool:
    if registry_data is None:
        return False
    if ecosystem == "npm":
        versions = getattr(registry_data, "versions", [])
        return len(versions) <= 1
    return False
