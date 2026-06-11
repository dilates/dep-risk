from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class RiskScore:
    scorer: str
    score: float
    weight: float
    finding: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Dependency:
    name: str
    version: str
    version_spec: str
    is_dev: bool = False
    depth: int = 0
    ecosystem: str = ""
    checksum: Optional[str] = None
    is_path_dep: bool = False
    is_git_dep: bool = False
    git_url: Optional[str] = None
    extras: list[str] = field(default_factory=list)


@dataclass
class PackageResult:
    name: str
    version: str
    ecosystem: str
    registry_url: str
    github_url: Optional[str]
    scores: dict[str, RiskScore] = field(default_factory=dict)
    total_score: float = 0.0
    risk_level: str = "low"
    flags: list[str] = field(default_factory=list)
    fetch_errors: list[str] = field(default_factory=list)

    def compute_total(self, weights: dict[str, float]) -> None:
        total = 0.0
        weight_sum = 0.0
        for scorer_name, score in self.scores.items():
            w = weights.get(scorer_name, score.weight)
            total += score.score * w
            weight_sum += w
        if weight_sum > 0:
            self.total_score = min(100.0, total / weight_sum * 100.0 if weight_sum < 1.0 else total)
        else:
            self.total_score = 0.0
        self.total_score = min(100.0, self.total_score)
        self.risk_level = score_to_level(self.total_score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "registry_url": self.registry_url,
            "github_url": self.github_url,
            "total_score": round(self.total_score, 2),
            "risk_level": self.risk_level,
            "flags": self.flags,
            "fetch_errors": self.fetch_errors,
            "scores": {
                k: {
                    "scorer": v.scorer,
                    "score": round(v.score, 2),
                    "weight": v.weight,
                    "finding": v.finding,
                    "detail": v.detail,
                    "evidence": v.evidence,
                }
                for k, v in self.scores.items()
            },
        }


def score_to_level(score: float) -> str:
    if score <= 20:
        return "low"
    if score <= 45:
        return "medium"
    if score <= 70:
        return "high"
    return "critical"


LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class Scorer(Protocol):
    name: str
    weight: float

    async def score(
        self,
        dep: Dependency,
        registry_data: Any,
        github_data: Any,
    ) -> RiskScore: ...
